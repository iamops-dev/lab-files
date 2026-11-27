// A tiny personal agent for the Cedar Cup demo. It signs the user in with the store (authorization
// code, PKCE, private_key_jwt), shops with the granted scopes, probes the refusals, then revokes.
// It never sees the user's password. Loopback only.
import http from 'node:http';
import crypto from 'node:crypto';

const PORT = Number(process.env.AGENT_PORT || 4611);
const ME = `http://localhost:${PORT}`;
const STORE = process.env.STORE || `http://localhost:${PORT - 1}`;
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'agent-1', alg: 'ES256', use: 'sig' };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
const flows = new Map();
let report = [];
const note = (label, status, detail) => { const line = `${String(status).padEnd(4)} ${label}${detail ? '  ' + detail : ''}`; report.push({ status, line }); console.log(line); };

const assertion = (aud) => {
  const now = Math.floor(Date.now() / 1000);
  const body = `${b64({ alg: 'ES256', kid: 'agent-1' })}.${b64({ iss: `${ME}/agent.json`, sub: `${ME}/agent.json`, aud, iat: now, exp: now + 60, jti: rand(16) })}`;
  return `${body}.${crypto.sign('sha256', Buffer.from(body), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
};
const post = async (url, form, token) => {
  const r = await fetch(url, { method: 'POST', body: new URLSearchParams(form), headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: r.status, body: await r.json() };
};
const get = async (url, token) => {
  const r = await fetch(url, { headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: r.status, body: await r.json() };
};
const authed = (aud, extra) => ({ client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion(aud), ...extra });

async function discover() {
  const poppy = (await get(`${STORE}/.well-known/poppy.json`)).body;
  const prm = (await get(`${STORE}/.well-known/oauth-protected-resource`)).body;
  const as = (await get(`${poppy.auth.issuer}/.well-known/oauth-authorization-server`)).body;
  if (poppy.organization.domain !== new URL(STORE).host || prm.resource !== STORE || as.issuer !== poppy.auth.issuer || !as.protected_resources.includes(STORE)) throw new Error('discovery checks failed');
  return as;
}

async function shop(as, f, code) {
  report = [];
  const base = { grant_type: 'authorization_code', code, redirect_uri: `${ME}/callback` };
  let r = await post(as.token_endpoint, authed(`${as.issuer}/oauth/token`, { ...base, code_verifier: f.verifier }));
  note('token request with the wrong assertion audience', r.status, r.body.error_description);
  r = await post(as.token_endpoint, authed(as.issuer, { ...base, code_verifier: rand() }));
  note('token request with the wrong PKCE verifier', r.status, r.body.error_description);
  r = await post(as.token_endpoint, authed(as.issuer, { ...base, code_verifier: f.verifier }));
  if (r.status !== 200) throw new Error('token request failed');
  const t = r.body; note('token request, correct assertion and verifier', r.status, `scope="${t.scope}"`);
  r = await get(`${STORE}/api/orders`); note('GET /api/orders without a token', r.status, r.body.error);
  r = await post(`${STORE}/api/cart`, { product: 'beans' }, t.access_token); note('POST /api/cart', r.status, r.body.cart ? `items=${r.body.cart.length}` : r.body.error_description);
  r = await get(`${STORE}/api/orders`, t.access_token); note('GET /api/orders', r.status, r.body.orders ? `orders=${r.body.orders.length}` : r.body.error_description);
  r = await post(`${STORE}/api/orders`, {}, t.access_token); note('POST /api/orders', r.status, r.body.orders ? `orders=${r.body.orders.length}` : r.body.error_description);
  r = await post(as.token_endpoint, authed(as.issuer, { grant_type: 'refresh_token', refresh_token: t.refresh_token }));
  note('refresh', r.status, r.body.access_token ? 'new tokens' : r.body.error_description); const t2 = r.body;
  r = await post(as.token_endpoint, authed(as.issuer, { grant_type: 'refresh_token', refresh_token: t.refresh_token }));
  note('refresh again with the old refresh token', r.status, r.body.error_description);
  r = await post(as.revocation_endpoint, authed(as.issuer, { token: t2.refresh_token })); note('revoke', r.status);
  r = await get(`${STORE}/api/cart`, t2.access_token); note('GET /api/cart after revoke', r.status, r.body.error);
  r = await post(as.token_endpoint, authed(as.issuer, { grant_type: 'refresh_token', refresh_token: t2.refresh_token })); note('refresh after revoke', r.status, r.body.error_description);
}

const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (inner) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Demo personal agent</title>
<style>body{margin:0;font:16px/1.5 system-ui,sans-serif;background:#171a2b;color:#eef0fb}main{max-width:760px;margin:36px auto;background:#222741;border:1px solid #343b60;border-radius:18px;padding:28px 30px}
h1{margin:0 0 6px;font-size:24px}a.btn{display:inline-block;margin-top:14px;padding:11px 18px;border-radius:11px;background:#a99bff;color:#171a2b;font-weight:700;text-decoration:none}
li{list-style:none;display:flex;gap:12px;padding:9px 0;border-top:1px solid #343b60;font:14px/1.45 ui-monospace,Menlo,monospace}ul{padding:0}b.ok{color:#79e2a7}b.no{color:#ffb38a}b{min-width:34px}</style><main>${inner}</main></html>`;

http.createServer(async (req, res) => {
  const url = new URL(req.url, ME);
  const send = (status, body, type = 'text/html; charset=utf-8', extra = {}) => { res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', ...extra }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
  try {
    if (url.pathname === '/agent.json') return send(200, { client_id: `${ME}/agent.json`, client_name: 'Demo personal agent', jwks_uri: `${ME}/jwks.json`, redirect_uris: [`${ME}/callback`], token_endpoint_auth_method: 'private_key_jwt' }, 'application/json');
    if (url.pathname === '/jwks.json') return send(200, { keys: [jwk] }, 'application/json');
    if (url.pathname === '/') return send(200, page(`<h1>Demo personal agent</h1><p>I can fill your cart at <b>Cedar Cup</b> and look at your orders, if you let me. You sign in on the store's page, not here.</p><a class="btn" href="/start">Connect to Cedar Cup</a>`));
    if (url.pathname === '/start') {
      const as = await discover(), state = rand(16), verifier = rand();
      flows.set(state, { as, verifier });
      const to = new URL(as.authorization_endpoint);
      to.search = new URLSearchParams({ response_type: 'code', client_id: `${ME}/agent.json`, redirect_uri: `${ME}/callback`, scope: 'cart:write orders:read orders:write', state, code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', prompt: 'consent' });
      return send(302, '', 'text/plain', { location: to.href });
    }
    if (url.pathname === '/callback') {
      const f = flows.get(url.searchParams.get('state'));
      if (!f || url.searchParams.get('iss') !== f.as.issuer) return send(400, page('<h1>Sign-in response refused</h1><p>Unknown state or issuer.</p>'));
      flows.delete(url.searchParams.get('state'));
      if (url.searchParams.get('error')) return send(200, page('<h1>You declined</h1><p>The agent got no access.</p>'));
      await shop(f.as, f, url.searchParams.get('code'));
      return send(303, '', 'text/plain', { location: '/result' });
    }
    if (url.pathname === '/result') return send(200, page(`<h1>What the agent could and could not do</h1><p>Green was accepted, orange was refused by the store.</p><ul>${report.map((r) => `<li><b class="${r.status < 300 ? 'ok' : 'no'}">${r.status}</b><span>${esc(r.line.slice(5))}</span></li>`).join('')}</ul>`));
    return send(404, 'not found', 'text/plain');
  } catch (e) { console.error(e.message); return send(500, page(`<h1>Something failed</h1><p>${esc(e.message)}</p>`)); }
}).listen(PORT, '127.0.0.1', () => console.log(`Demo agent on ${ME}`));
