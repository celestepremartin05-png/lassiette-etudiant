// /api/auth/signup | login | logout | me | forgot | reset | verify
const { handle } = require("../../lib/auth");

module.exports = (req, res) => handle(req, res);
