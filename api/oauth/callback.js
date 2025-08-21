const crypto = require('crypto');

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function parseCookies(req) {
  const h = req.headers.cookie || ''; const out = {};
  h.split(/;\s*/).filter(Boolean).forEach(kv => { const i = kv.indexOf('='); out[kv.slice(0,i)] = kv.slice(i+1); });
  return out;
}
function serializeCookie(name, value, opts = {}) {
  const p = [ `${name}=${value}` ];
  if (opts.httpOnly) p.push('HttpOnly');
  if (opts.secure) p.push('Secure');
  if (opts.sameSite) p.push(`SameSite=${opts.sameSite}`);
  if (opts.maxAge) p.push(`Max-Age=${opts.maxAge}`);
  p.push(`Path=${opts.path || '/'}`);
  return p.join('; ');
}
function enc(text, secret) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${b64url(iv)}.${b64url(ct)}.${b64url(tag)}`;
}

module.exports = async (req, res) => {
  try {
    const provider = (req.query.provider || '').toLowerCase();
    if (provider !== 'github') return res.status(400).send('Unsupported provider');

    const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, APP_BASE_URL, SESSION_SECRET } = process.env;
    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !APP_BASE_URL || !SESSION_SECRET) return res.status(500).send('Missing env');

    const cookies = parseCookies(req);
    if (!cookies.pkce) return res.status(400).send('Missing PKCE cookie');
    const { state: savedState, code_verifier } = JSON.parse(Buffer.from(cookies.pkce, 'base64').toString('utf8'));

    const state = req.query.state;
    const code = req.query.code;
    if (!code || !state || state !== savedState) return res.status(400).send('Invalid state');

    // Exchange code for token
    const redirect_uri = `${APP_BASE_URL}/api/oauth/callback?provider=github`;
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri,
        grant_type: 'authorization_code',
        code_verifier
      })
    });
    const tok = await tokenRes.json();
    if (!tok.access_token) return res.status(400).send('Token exchange failed');

    // Get user profile (acts like "member record" in a real connector)
    const uRes = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${tok.access_token}`, 'User-Agent': 'rewards-pass' }
    });
    const user = await uRes.json();
    if (!user || !user.id) return res.status(400).send('User fetch failed');

    // Create session cookie with encrypted token
    const session = { provider: 'github', user: { id: user.id, login: user.login, name: user.name || '' }, token: enc(tok.access_token, SESSION_SECRET) };
    const sessVal = Buffer.from(JSON.stringify(session), 'utf8').toString('base64');

    res.setHeader('Set-Cookie', [
      serializeCookie('pkce', 'cleared', { httpOnly: true, secure: true, sameSite: 'Lax', path: '/api/oauth/callback', maxAge: 1 }),
      serializeCookie('session', sessVal, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: 60 * 60 * 24 * 7 }) // 7 days
    ]);

    // Go back to the app root
    res.status(302).setHeader('Location', '/').end();
  } catch (e) {
    res.status(500).send('OAuth error: ' + e.message);
  }
};
