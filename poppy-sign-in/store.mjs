// Cedar Cup: a local stand-in store with sign-in, for the Poppy lab.
// Teaching demo only. It is NOT a conforming Poppy 1.0 implementation: plain HTTP on loopback,
// no Session header, in-memory data, one test account. Never expose it to a network.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';

const PORT = Number(process.env.STORE_PORT || 4610);
const ISSUER = `http://localhost:${PORT}`;
const AGENT = process.env.AGENT_URL || `http://localhost:${PORT + 1}`;
const CLIENT_ID = `${AGENT}/agent.json`;
const USER = 'demo-shopper';
const LOGIN_FILE = new URL('./.demo-login', import.meta.url);
if (!fs.existsSync(LOGIN_FILE)) fs.writeFileSync(LOGIN_FILE, crypto.randomBytes(12).toString('base64url') + '\n', { mode: 0o600 });
const PASSWORD = fs.readFileSync(LOGIN_FILE, 'utf8').trim();

const SCOPES = {
  'cart:write': 'Add and remove items in your cart',
  'orders:read': 'See your orders',
  'orders:write': 'Place orders in your name',
};
const PRODUCTS = [
  { id: 'beans', name: 'Cedar house beans, 500 g', price: 14 },
  { id: 'filter', name: 'Paper filters, 100', price: 6 },
  { id: 'mug', name: 'Stoneware mug', price: 18 },
];
const pending = new Map(), codes = new Map(), access = new Map(), refresh = new Map(), seenJti = new Set();
const cart = [], orders = [];
const rand = (n = 24) => crypto.randomBytes(n).toString('base64url');
const sha256 = (v) => crypto.createHash('sha256').update(v).digest('base64url');
const same = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

const send = (res, status, body, type = 'application/json', extra = {}) => {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', ...extra });
  res.end(typeof body === 'string' ? body : JSON.stringify(body, null, 2));
};
const fail = (res, status, error, why) => { log(status, error, '-', why); send(res, status, { error, error_description: why }); };
const readForm = (req) => new Promise((ok) => {
  let b = ''; req.on('data', (d) => { b += d; if (b.length > 20000) req.destroy(); });
  req.on('end', () => ok(Object.fromEntries(new URLSearchParams(b))));
});

const page = (title, inner) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>
:root{--ink:#1f2a24;--leaf:#2f6b4f;--cream:#f6f1e7;--card:#fffdf8;--line:#e3dac6}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--cream);color:var(--ink)}
header{padding:18px 28px;font-weight:700;font-size:20px;border-bottom:1px solid var(--line)}header span{color:var(--leaf)}
header small{float:right;font-weight:400;font-size:13px;opacity:.7;padding-top:4px}
main{max-width:430px;margin:36px auto;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:30px;box-shadow:0 12px 30px #0000000d}
h1{margin:0 0 6px;font-size:25px}p{margin:6px 0 16px}label{display:block;font-weight:600;font-size:14px;margin:12px 0 4px}
input[type=text],input[type=password]{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;font:inherit;background:#fff}
.scope{display:flex;gap:11px;align-items:flex-start;border:1px solid var(--line);border-radius:12px;padding:11px 13px;margin:9px 0;font-weight:400}
.scope input{margin-top:5px;accent-color:var(--leaf)}code{font-size:13px;background:#eef3ec;padding:1px 6px;border-radius:5px}
button{font:inherit;font-weight:600;border-radius:11px;padding:11px 18px;border:1px solid var(--leaf);cursor:pointer;background:var(--leaf);color:#fff;margin:16px 8px 0 0}
button.alt{background:transparent;color:var(--leaf)}.err{color:#a4331f;font-weight:600}
</style><header>☕ Cedar <span>Cup</span><small>local demo store</small></header><main>${inner}</main></html>`;

const signInPage = (rid, error = '') => page('Sign in · Cedar Cup', `<h1>Sign in</h1><p>A personal agent wants to shop for you. Sign in on the store's own page: the agent never sees your password.</p>
${error ? `<p class="err">${error}</p>` : ''}<form method="post" action="/oauth/login"><input type="hidden" name="rid" value="${rid}">
<label for="u">Username</label><input id="u" name="username" type="text" autocomplete="username">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">
<button>Sign in</button></form>`);

const consentPage = (rid, r) => page('Approve access · Cedar Cup', `<h1>Approve access</h1><p><b>${esc(r.clientName)}</b> asks to act for <b>${USER}</b>. Untick anything you don't want to give.</p>
<form method="post" action="/oauth/consent"><input type="hidden" name="rid" value="${rid}">
${r.scope.map((s) => `<label class="scope"><input type="checkbox" name="s_${s}" ${s === 'orders:write' ? '' : 'checked'}><span>${SCOPES[s]}<br><code>${s}</code></span></label>`).join('')}
<button name="decision" value="allow">Allow</button><button class="alt" name="decision" value="deny">Decline</button></form>`);

async function clientMetadata(clientId) {
  if (clientId !== CLIENT_ID) throw new Error('unknown client_id');
  const doc = await (await fetch(clientId, { redirect: 'error' })).json();
  if (doc.client_id !== clientId) throw new Error('client_id does not match its document');
  return doc;
}

async function checkAssertion(f) {
  if (f.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' || !f.client_assertion) throw new Error('client assertion missing');
  const [h, p, s] = f.client_assertion.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url')), c = JSON.parse(Buffer.from(p, 'base64url'));
  const alg = { ES256: { kty: 'EC', hash: 'sha256', opts: { dsaEncoding: 'ieee-p1363' } }, PS384: { kty: 'RSA', hash: 'sha384', opts: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 } } }[header.alg];
  if (!alg) throw new Error('alg must be ES256 or PS384');
  const doc = await clientMetadata(c.sub);
  const { keys } = await (await fetch(doc.jwks_uri, { redirect: 'error' })).json();
  const jwk = keys.find((k) => k.kid === header.kid && k.kty === alg.kty);
  if (!jwk) throw new Error('signing key not found');
  const ok = crypto.verify(alg.hash, Buffer.from(`${h}.${p}`), { key: crypto.createPublicKey({ key: jwk, format: 'jwk' }), ...alg.opts }, Buffer.from(s || '', 'base64url'));
  if (!ok) throw new Error('bad signature');
  const now = Math.floor(Date.now() / 1000);
  if (c.iss !== c.sub) throw new Error('iss must equal sub');
  if (c.aud !== ISSUER) throw new Error('aud must be the issuer');
  if (!c.exp || !c.iat || c.exp < now || c.exp - c.iat > 300) throw new Error('expired, or lasts more than 5 minutes');
  if (!c.jti || seenJti.has(c.jti)) throw new Error('jti missing or already used');
  seenJti.add(c.jti);
  return c.sub;
}

const issue = (clientId, scope, family) => {
  const at = rand(), rt = rand();
  access.set(at, { clientId, scope, family, exp: Date.now() + 600000 });
  refresh.set(rt, { clientId, scope, family });
  return { access_token: at, token_type: 'Bearer', expires_in: 600, refresh_token: rt, scope: scope.join(' ') };
};
const dropFamily = (family) => { for (const m of [access, refresh]) for (const [k, v] of m) if (v.family === family) m.delete(k); };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, ISSUER), path = url.pathname, m = req.method;
  try {
    if (m === 'GET' && path === '/.well-known/poppy.json') return send(res, 200, {
      protocol_version: '1.0', organization: { name: 'Cedar Cup (local demo)', domain: `localhost:${PORT}` },
      auth: { issuer: ISSUER, scopes: SCOPES },
      apis: [{ type: 'openapi', url: `${ISSUER}/openapi.json`, description: 'Products, cart and orders' }] });
    if (m === 'GET' && path === '/.well-known/oauth-protected-resource') return send(res, 200, { resource: ISSUER, authorization_servers: [ISSUER], scopes_supported: Object.keys(SCOPES) });
    if (m === 'GET' && path === '/.well-known/oauth-authorization-server') return send(res, 200, {
      issuer: ISSUER, authorization_endpoint: `${ISSUER}/oauth/authorize`, token_endpoint: `${ISSUER}/oauth/token`, revocation_endpoint: `${ISSUER}/oauth/revoke`,
      grant_types_supported: ['authorization_code', 'refresh_token'], response_types_supported: ['code'], code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['private_key_jwt'], token_endpoint_auth_signing_alg_values_supported: ['ES256', 'PS384'],
      authorization_response_iss_parameter_supported: true, scopes_supported: Object.keys(SCOPES), protected_resources: [ISSUER] });
    if (m === 'GET' && path === '/openapi.json') return send(res, 200, { openapi: '3.1.0', info: { title: 'Cedar Cup', version: '1' }, paths: { '/api/products': { get: {} }, '/api/cart': { get: {}, post: {} }, '/api/orders': { get: {}, post: {} } } });

    if (m === 'GET' && path === '/oauth/authorize') {
      const q = Object.fromEntries(url.searchParams);
      let doc; try { doc = await clientMetadata(q.client_id); } catch (e) { return fail(res, 400, 'invalid_client', e.message); }
      if (!doc.redirect_uris.includes(q.redirect_uri)) return fail(res, 400, 'invalid_request', 'redirect_uri is not in the client metadata');
      const scope = (q.scope || '').split(' ').filter((s) => Object.hasOwn(SCOPES, s));
      if (q.response_type !== 'code' || q.code_challenge_method !== 'S256' || !q.code_challenge || !scope.length) return fail(res, 400, 'invalid_request', 'needs response_type=code, PKCE S256 and a known scope');
      const rid = rand(); pending.set(rid, { clientId: q.client_id, clientName: doc.client_name, redirect: q.redirect_uri, state: q.state, challenge: q.code_challenge, scope, user: null });
      log('authorize request from', doc.client_name, scope.join(' '));
      return send(res, 200, signInPage(rid), 'text/html; charset=utf-8');
    }
    if (m === 'POST' && (path === '/oauth/login' || path === '/oauth/consent')) {
      if (req.headers.origin && req.headers.origin !== ISSUER) return fail(res, 403, 'access_denied', 'cross-origin form post');
      const f = await readForm(req), r = pending.get(f.rid);
      if (!r) return fail(res, 400, 'invalid_request', 'sign-in request expired');
      if (path === '/oauth/login') {
        if (f.username !== USER || !same(f.password || '', PASSWORD)) { log('sign-in failed'); return send(res, 401, signInPage(f.rid, 'Wrong username or password.'), 'text/html; charset=utf-8'); }
        r.user = USER; log('user signed in on the store page');
        return send(res, 200, consentPage(f.rid, r), 'text/html; charset=utf-8');
      }
      if (!r.user) return fail(res, 403, 'access_denied', 'sign in first');
      pending.delete(f.rid);
      const to = new URL(r.redirect); if (r.state) to.searchParams.set('state', r.state); to.searchParams.set('iss', ISSUER);
      const granted = r.scope.filter((s) => f[`s_${s}`]);
      if (f.decision !== 'allow' || !granted.length) { to.searchParams.set('error', 'access_denied'); log('user declined'); }
      else { const code = rand(); codes.set(code, { ...r, scope: granted, exp: Date.now() + 60000, used: false }); to.searchParams.set('code', code); log('user approved:', granted.join(' ')); }
      return send(res, 303, '', 'text/plain', { location: to.href });
    }
    if (m === 'POST' && path === '/oauth/token') {
      const f = await readForm(req);
      let clientId; try { clientId = await checkAssertion(f); } catch (e) { return fail(res, 401, 'invalid_client', e.message); }
      if (f.grant_type === 'authorization_code') {
        const c = codes.get(f.code);
        if (!c || c.clientId !== clientId || c.exp < Date.now()) return fail(res, 400, 'invalid_grant', 'unknown or expired code');
        if (c.used) { dropFamily(f.code); return fail(res, 400, 'invalid_grant', 'code already used; its tokens are now revoked'); }
        if (c.redirect !== f.redirect_uri) return fail(res, 400, 'invalid_grant', 'redirect_uri differs');
        if (sha256(f.code_verifier || '') !== c.challenge) return fail(res, 400, 'invalid_grant', 'PKCE verifier does not match');
        c.used = true; log('tokens issued:', c.scope.join(' '));
        return send(res, 200, issue(clientId, c.scope, f.code));
      }
      if (f.grant_type === 'refresh_token') {
        const t = refresh.get(f.refresh_token);
        if (!t || t.clientId !== clientId) return fail(res, 400, 'invalid_grant', 'unknown or revoked refresh token');
        refresh.delete(f.refresh_token); log('refresh token rotated');
        return send(res, 200, issue(clientId, t.scope, t.family));
      }
      return fail(res, 400, 'unsupported_grant_type', 'not offered');
    }
    if (m === 'POST' && path === '/oauth/revoke') {
      const f = await readForm(req);
      let clientId; try { clientId = await checkAssertion(f); } catch (e) { return fail(res, 401, 'invalid_client', e.message); }
      const t = refresh.get(f.token) || access.get(f.token);
      if (t && t.clientId === clientId) { dropFamily(t.family); log('access revoked'); }
      return send(res, 200, {});
    }

    if (path.startsWith('/api/')) {
      if (m === 'GET' && path === '/api/products') return send(res, 200, PRODUCTS);
      const t = access.get((req.headers.authorization || '').replace(/^Bearer /, ''));
      const need = path === '/api/cart' ? 'cart:write' : m === 'GET' ? 'orders:read' : 'orders:write';
      if (!t || t.exp < Date.now()) return fail(res, 401, 'invalid_token', `${m} ${path} needs a valid access token`);
      if (!t.scope.includes(need)) return fail(res, 403, 'insufficient_scope', `${m} ${path} needs ${need}`);
      if (path === '/api/cart' && m === 'POST') {
        const wanted = (await readForm(req)).product, p = PRODUCTS.find((x) => x.id === wanted);
        if (!p) return fail(res, 404, 'not_found', 'no such product');
        cart.push(p); log('added to cart:', p.id); return send(res, 201, { cart });
      }
      if (path === '/api/cart') return send(res, 200, { cart });
      if (path === '/api/orders' && m === 'GET') return send(res, 200, { orders });
      if (path === '/api/orders' && m === 'POST') { orders.push({ id: orders.length + 1, items: cart.splice(0) }); log('order placed'); return send(res, 201, { orders }); }
    }
    return fail(res, 404, 'not_found', path);
  } catch (e) { return fail(res, 500, 'server_error', e.message); }
});
server.listen(PORT, '127.0.0.1', () => { log(`Cedar Cup on ${ISSUER}`); log(`test account ${USER}; its password is in the file .demo-login`); });
