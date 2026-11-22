-- Tables des comptes de L'Assiette de l'étudiant.
-- Supabase sert uniquement de base de données : RLS activé et aucune policy,
-- donc personne ne peut lire ces tables depuis le navigateur.
-- Seules les fonctions serveur Vercel (clé secrète) y accèdent.

create table if not exists public.users (
  id                 uuid primary key default gen_random_uuid(),
  email              text not null unique check (email = lower(email)),
  password_hash      text not null,
  email_verified_at  timestamptz,
  verify_token_hash  text,
  verify_expires_at  timestamptz,
  verify_sent_at     timestamptz,
  reset_token_hash   text,
  reset_expires_at   timestamptz,
  reset_sent_at      timestamptz,
  failed_logins      integer not null default 0,
  locked_until       timestamptz,
  created_at         timestamptz not null default now()
);
create index if not exists users_verify_token_idx on public.users (verify_token_hash);
create index if not exists users_reset_token_idx on public.users (reset_token_hash);

create table if not exists public.sessions (
  token_hash  text primary key,
  user_id     uuid not null references public.users (id) on delete cascade,
  expires_at  timestamptz not null,
  created_at  timestamptz not null default now()
);
create index if not exists sessions_user_idx on public.sessions (user_id);

alter table public.users enable row level security;
alter table public.sessions enable row level security;

-- Double sécurité : aucun droit pour les clés publiques.
revoke all on public.users, public.sessions from anon, authenticated;
