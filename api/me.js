function parseCookies(req) {
  const h = req.headers.cookie || ''; const out = {};
  h.split(/;\s*/).filter(Boolean).forEach(kv => { const i = kv.indexOf('='); out[kv.slice(0,i)] = kv.slice(i+1); });
  return out;
}

module.exports = async (req, res) => {
  const cookies = parseCookies(req);
  if (!cookies.session) return res.status(401).json({ ok: false });
  try {
    const session = JSON.parse(Buffer.from(cookies.session, 'base64').toString('utf8'));
    return res.json({ ok: true, provider: session.provider, user: session.user });
  } catch {
    return res.status(401).json({ ok: false });
  }
};
