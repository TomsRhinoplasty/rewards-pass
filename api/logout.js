module.exports = async (_req, res) => {
  res.setHeader('Set-Cookie', 'session=cleared; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=1');
  res.json({ ok: true });
};
