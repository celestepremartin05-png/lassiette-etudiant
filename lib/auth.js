// Outils partagés pour les comptes de L'Assiette de l'étudiant.
// Supabase sert uniquement de base de données (tables public.users et public.sessions,
// RLS activé sans policy : seule la clé secrète, côté serveur, peut les lire).
// Les mots de passe sont hachés avec bcrypt, les e-mails partent par l'API Resend.

const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const SUPABASE_URL = (process.env.SUPABASE_URL || "https://qbyshrpigczvopxszoyz.supabase.co").replace(/\/+$/, "");
const SUPABASE_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const RESEND_KEY = process.env.RESEND_API_KEY || "";
const MAIL_FROM = process.env.MAIL_FROM || "L'Assiette de l'étudiant <noreply@assiette-etudiante.com>";
const APP_URL = (process.env.APP_URL || "https://www.assiette-etudiante.com").replace(/\/+$/, "");

const BCRYPT_COST = 10;
const SESSION_DAYS = 30;
const VERIFY_HOURS = 24;
const RESET_MINUTES = 60;
const RESEND_COOLDOWN_S = 60; // pas plus d'un e-mail par minute et par adresse
const MAX_FAILS = 5; // essais de connexion ratés avant blocage
const LOCK_MINUTES = 15;
const COOKIE = "ae_session";
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i;

// Hash factice : on compare quand même quand l'adresse n'existe pas,
// pour que la réponse prenne le même temps (on ne révèle pas qui est inscrit).
const DUMMY_HASH = bcrypt.hashSync("pas-un-vrai-mot-de-passe", BCRYPT_COST);

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

// ---------- utilitaires ----------
const now = () => new Date();
const addMs = (ms) => new Date(Date.now() + ms).toISOString();
const newToken = () => crypto.randomBytes(32).toString("base64url");
const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const normEmail = (e) => String(e || "").trim().toLowerCase();

function checkPassword(pw) {
  if (typeof pw !== "string" || pw.length < 8) throw new HttpError(400, "weak_password");
  // bcrypt ne prend en compte que les 72 premiers octets : on refuse au-delà.
  if (Buffer.byteLength(pw, "utf8") > 72) throw new HttpError(400, "password_too_long");
}

function checkEmail(email) {
  if (!email || email.length > 254 || !EMAIL_RE.test(email)) throw new HttpError(400, "invalid_email");
}

// ---------- Supabase (PostgREST) avec la clé secrète ----------
function dbHeaders(extra) {
  if (!SUPABASE_KEY) throw new HttpError(500, "server_not_configured");
  const h = { apikey: SUPABASE_KEY, "Content-Type": "application/json" };
  // Les anciennes clés « service_role » (JWT) doivent aussi aller dans Authorization.
  // Les nouvelles clés sb_secret_… passent uniquement par l'en-tête apikey.
  if (SUPABASE_KEY.startsWith("eyJ")) h.Authorization = "Bearer " + SUPABASE_KEY;
  return Object.assign(h, extra || {});
}

async function db(method, path, body, prefer) {
  const res = await fetch(SUPABASE_URL + "/rest/v1/" + path, {
    method,
    headers: dbHeaders(prefer ? { Prefer: prefer } : null),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!res.ok) {
    if (data && data.code === "23505") throw new HttpError(409, "already_registered");
    console.error("Supabase", method, path.split("?")[0], res.status, typeof data === "string" ? data : JSON.stringify(data));
    throw new HttpError(500, "database_error");
  }
  return data;
}

const enc = encodeURIComponent;

async function findUserBy(field, value) {
  const rows = await db("GET", `users?${field}=eq.${enc(value)}&select=*&limit=1`);
  return rows && rows[0] ? rows[0] : null;
}

async function updateUser(id, patch) {
  await db("PATCH", `users?id=eq.${enc(id)}`, patch, "return=minimal");
}

// ---------- sessions (cookie httpOnly) ----------
async function createSession(res, userId) {
  const token = newToken();
  // Ménage : on supprime les sessions expirées de cette personne.
  await db("DELETE", `sessions?user_id=eq.${enc(userId)}&expires_at=lt.${enc(now().toISOString())}`, undefined, "return=minimal");
  await db("POST", "sessions", {
    token_hash: sha256(token),
    user_id: userId,
    expires_at: addMs(SESSION_DAYS * 864e5),
  }, "return=minimal");
  setCookie(res, token, SESSION_DAYS * 86400);
}

function setCookie(res, value, maxAge) {
  res.setHeader("Set-Cookie",
    `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
}

function readCookie(req) {
  const raw = req.headers.cookie || "";
  const m = raw.match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  return m ? m[1] : null;
}

async function currentUser(req) {
  const token = readCookie(req);
  if (!token) return null;
  const rows = await db("GET",
    `sessions?token_hash=eq.${enc(sha256(token))}&select=expires_at,user_id,users(email,email_verified_at)&limit=1`);
  const s = rows && rows[0];
  if (!s || !s.users || new Date(s.expires_at) < now() || !s.users.email_verified_at) return null;
  return { id: s.user_id, email: s.users.email };
}

async function destroySession(req, res) {
  const token = readCookie(req);
  if (token) await db("DELETE", `sessions?token_hash=eq.${enc(sha256(token))}`, undefined, "return=minimal");
  setCookie(res, "", 0);
}

// ---------- e-mails (API Resend) ----------
function baseUrl(req) {
  // Les liens renvoient sur le domaine où la personne s'est inscrite
  // (site principal ou aperçu Vercel), jamais sur un domaine inconnu.
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || "").toLowerCase();
  if (/^(www\.)?assiette-etudiante\.com$/.test(host) || /^[a-z0-9-]+\.vercel\.app$/.test(host)) return "https://" + host;
  return APP_URL;
}

function mailHtml(title, text, button, link, foot) {
  return `<!doctype html><html lang="fr"><body style="margin:0;background:#fbf6ee;font-family:Arial,Helvetica,sans-serif;color:#2b2b2b">
<div style="max-width:480px;margin:0 auto;padding:32px 20px">
<p style="font-size:22px;font-weight:bold;margin:0 0 16px">🍽️ L'Assiette de l'étudiant</p>
<h1 style="font-size:20px;margin:0 0 12px">${title}</h1>
<p style="font-size:15px;line-height:1.5;margin:0 0 24px">${text}</p>
<p style="margin:0 0 24px"><a href="${link}" style="display:inline-block;background:#4aa343;color:#fff;text-decoration:none;font-weight:bold;padding:12px 22px;border-radius:10px">${button}</a></p>
<p style="font-size:12px;line-height:1.5;color:#777;margin:0 0 8px">Si le bouton ne marche pas, copie ce lien dans ton navigateur :<br><span style="word-break:break-all">${link}</span></p>
<p style="font-size:12px;color:#777;margin:0">${foot}</p>
</div></body></html>`;
}

async function sendMail(to, subject, html, text) {
  if (!RESEND_KEY) throw new HttpError(500, "server_not_configured");
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + RESEND_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html, text }),
  });
  if (!res.ok) {
    console.error("Resend", res.status, await res.text());
    throw new HttpError(502, "email_send_failed");
  }
}

async function sendVerifyMail(req, email, token) {
  const link = `${baseUrl(req)}/api/auth/verify?token=${enc(token)}`;
  await sendMail(email, "Confirme ton compte L'Assiette de l'étudiant",
    mailHtml("Confirme ton adresse e-mail",
      "Merci pour ton inscription ! Clique sur le bouton pour confirmer ton adresse : tu seras connecté directement.",
      "Confirmer mon compte", link,
      `Ce lien est valable ${VERIFY_HOURS} h. Si tu n'as rien demandé, ignore cet e-mail.`),
    `Confirme ton compte L'Assiette de l'étudiant : ${link}\nCe lien est valable ${VERIFY_HOURS} h.`);
}

async function sendResetMail(req, email, token) {
  const link = `${baseUrl(req)}/?reset=${enc(token)}`;
  await sendMail(email, "Choisis un nouveau mot de passe",
    mailHtml("Mot de passe oublié ?",
      "Clique sur le bouton pour choisir un nouveau mot de passe pour ton compte L'Assiette de l'étudiant.",
      "Choisir un nouveau mot de passe", link,
      `Ce lien est valable ${RESET_MINUTES} min. Si tu n'as rien demandé, ignore cet e-mail : ton mot de passe ne change pas.`),
    `Nouveau mot de passe pour L'Assiette de l'étudiant : ${link}\nCe lien est valable ${RESET_MINUTES} min.`);
}

const recently = (iso, seconds) => iso && Date.now() - new Date(iso).getTime() < seconds * 1000;

// ---------- actions ----------
async function signup(req, res, body) {
  const email = normEmail(body.email);
  checkEmail(email);
  checkPassword(body.password);
  const hash = await bcrypt.hash(body.password, BCRYPT_COST);
  const existing = await findUserBy("email", email);

  if (existing && existing.email_verified_at) throw new HttpError(409, "already_registered");

  const token = newToken();
  const patch = {
    password_hash: hash,
    verify_token_hash: sha256(token),
    verify_expires_at: addMs(VERIFY_HOURS * 3600e3),
    verify_sent_at: now().toISOString(),
  };

  if (existing) {
    // Compte jamais confirmé : on renvoie un lien (au plus un par minute).
    // Le mot de passe est remplacé : seule la personne qui a la boîte mail pourra confirmer.
    if (recently(existing.verify_sent_at, RESEND_COOLDOWN_S)) return { sent: true };
    await updateUser(existing.id, patch);
  } else {
    await db("POST", "users", Object.assign({ email }, patch), "return=minimal");
  }
  await sendVerifyMail(req, email, token);
  return { sent: true };
}

async function verify(req, res) {
  const token = String((req.query && req.query.token) || "");
  const fail = () => { res.statusCode = 302; res.setHeader("Location", "/?auth=lien-invalide"); res.end(); };
  if (!token) return fail();
  const u = await findUserBy("verify_token_hash", sha256(token));
  if (!u || !u.verify_expires_at || new Date(u.verify_expires_at) < now()) return fail();
  // Le lien reste utilisable jusqu'à son expiration : certaines messageries
  // « ouvrent » les liens pour les analyser avant que l'étudiant clique.
  if (!u.email_verified_at) await updateUser(u.id, { email_verified_at: now().toISOString() });
  await createSession(res, u.id);
  res.statusCode = 302;
  res.setHeader("Location", "/?auth=confirme");
  res.end();
}

async function login(req, res, body) {
  const email = normEmail(body.email);
  const pw = typeof body.password === "string" ? body.password : "";
  if (!email || !pw) throw new HttpError(400, "invalid_credentials");
  const u = await findUserBy("email", email);

  if (u && u.locked_until && new Date(u.locked_until) > now()) throw new HttpError(429, "too_many_attempts");

  const ok = await bcrypt.compare(pw, u ? u.password_hash : DUMMY_HASH);
  if (!u || !ok) {
    if (u) {
      const fails = (u.failed_logins || 0) + 1;
      await updateUser(u.id, fails >= MAX_FAILS
        ? { failed_logins: 0, locked_until: addMs(LOCK_MINUTES * 60e3) }
        : { failed_logins: fails });
    }
    throw new HttpError(401, "invalid_credentials");
  }
  if (!u.email_verified_at) throw new HttpError(403, "email_not_confirmed");
  if (u.failed_logins || u.locked_until) await updateUser(u.id, { failed_logins: 0, locked_until: null });
  await createSession(res, u.id);
  return { email: u.email };
}

async function forgot(req, res, body) {
  const email = normEmail(body.email);
  checkEmail(email);
  const u = await findUserBy("email", email);
  // Même réponse que le compte existe ou non.
  if (!u || !u.email_verified_at || recently(u.reset_sent_at, RESEND_COOLDOWN_S)) return { sent: true };
  const token = newToken();
  await updateUser(u.id, {
    reset_token_hash: sha256(token),
    reset_expires_at: addMs(RESET_MINUTES * 60e3),
    reset_sent_at: now().toISOString(),
  });
  await sendResetMail(req, email, token);
  return { sent: true };
}

async function reset(req, res, body) {
  const token = String(body.token || "");
  checkPassword(body.password);
  const u = token ? await findUserBy("reset_token_hash", sha256(token)) : null;
  if (!u || !u.reset_expires_at || new Date(u.reset_expires_at) < now()) throw new HttpError(400, "invalid_link");
  await updateUser(u.id, {
    password_hash: await bcrypt.hash(body.password, BCRYPT_COST),
    reset_token_hash: null,
    reset_expires_at: null,
    failed_logins: 0,
    locked_until: null,
    // Cliquer sur un lien reçu par e-mail prouve aussi l'adresse.
    email_verified_at: u.email_verified_at || now().toISOString(),
  });
  // Nouveau mot de passe : on déconnecte tous les autres appareils.
  await db("DELETE", `sessions?user_id=eq.${enc(u.id)}`, undefined, "return=minimal");
  await createSession(res, u.id);
  return { email: u.email };
}

async function me(req) {
  const u = await currentUser(req);
  if (!u) throw new HttpError(401, "not_signed_in");
  return { email: u.email };
}

async function logout(req, res) {
  await destroySession(req, res);
  return { ok: true };
}

const POST_ACTIONS = { signup, login, forgot, reset, logout };

async function handle(req, res) {
  const action = String((req.query && req.query.action) || "");
  res.setHeader("Cache-Control", "no-store");
  const send = (status, obj) => {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(obj));
  };
  try {
    if (req.method === "GET" && action === "verify") return await verify(req, res);
    if (req.method === "GET" && action === "me") return send(200, await me(req));
    const fn = POST_ACTIONS[action];
    if (!fn) return send(404, { error: "not_found" });
    if (req.method !== "POST") return send(405, { error: "method_not_allowed" });
    // Exiger du JSON bloque les formulaires envoyés depuis d'autres sites (protection CSRF).
    if (!/^application\/json/i.test(req.headers["content-type"] || "")) return send(415, { error: "json_required" });
    let body = req.body;
    if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { body = {}; } }
    return send(200, await fn(req, res, body || {}));
  } catch (e) {
    if (e instanceof HttpError) return send(e.status, { error: e.code });
    console.error(e);
    return send(500, { error: "server_error" });
  }
}

module.exports = { handle, _internals: { sha256, checkPassword, baseUrl } };
