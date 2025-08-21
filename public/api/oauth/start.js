const crypto = require('crypto');

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
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

module.exports = async (req, res) => {
  const provider = (req.query.provider || '').toLowerCase();
  if (provider !== 'github') return res.status(400).json({ error: 'Unsupported provider' });

  const { GITHUB_CLIENT_ID, APP_BASE_URL } = process.env;
  if (!GITHUB_CLIENT_ID || !APP_BASE_URL) return res.status(500).json({ error: 'Missing env' });

  const code_verifier = b64url(crypto.randomBytes(48));
  const code_challenge = b64url(crypto.createHash('sha256').update(code_verifier).digest());
  const state = b64url(crypto.randomBytes(24));

  // Store verifier+state in an HttpOnly cookie for the callback to read
  const payload = Buffer.from(JSON.stringify({ provider, state, code_verifier }), 'utf8').toString('base64');
  res.setHeader('Set-Cookie', serializeCookie('pkce', payload, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/api/oauth/callback' }));

  const redirect_uri = `${APP_BASE_URL}/api/oauth/callback?provider=github`;
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri,
    scope: 'read:user',
    state,
    code_challenge: code_challenge,
    code_challenge_method: 'S256'
  });
  const authUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
  res.json({ authUrl });
};
