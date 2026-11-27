# Cedar Cup: try an agent sign-in on your own computer

Two small Node.js programs for the lab [Poppy playground](https://iamops.dev/poppy-playground-lab/) on iamops.dev:

| File | What it is | Address |
|---|---|---|
| `store.mjs` | A demo store with its own sign-in server and a small API | `http://localhost:4610` |
| `agent.mjs` | A demo personal agent that signs you in, shops and revokes | `http://localhost:4611` |

**Teaching demo only.** It is not a conforming Poppy 1.0 implementation: plain HTTP on the loopback address, no Session header or User IDs, no device sign-in, no pushed authorization requests, no token binding, one test account, data in memory. Both programs listen on `127.0.0.1` only. Do not expose them to a network.

## Requirements

- Node.js. No packages to install. The lab run used Node.js 26.
- Ports 4610 and 4611 free.

## Run it

Get the files:

```bash
git clone https://github.com/iamops-dev/lab-files.git
cd lab-files/poppy-sign-in
```

Start the store in one terminal:

```bash
node store.mjs
```

Start the agent in a second terminal, in the same folder:

```bash
node agent.mjs
```

The first start writes a random password to `.demo-login` next to `store.mjs`. Show it:

```bash
cat .demo-login
```

Then:

1. Open <http://localhost:4611> and select **Connect to Cedar Cup**.
2. On the store page, sign in as `demo-shopper` with that password.
3. Leave **Place orders in your name** unticked and select **Allow**.
4. Read the result page.

## What you should see

| Request | Status |
|---|---|
| Token request with the wrong assertion audience | 401 |
| Token request with the wrong PKCE verifier | 400 |
| Correct token request (`cart:write orders:read`) | 200 |
| `GET /api/orders` without a token | 401 |
| `POST /api/cart` | 201 |
| `GET /api/orders` | 200 |
| `POST /api/orders` | 403 |
| Refresh, then the old refresh token again | 200, then 400 |
| Revoke, then use the tokens | 200, then 401 and 400 |

If you tick the order permission, `POST /api/orders` succeeds instead.

## Change the ports

Use two consecutive ports, the store first:

```bash
STORE_PORT=5610 node store.mjs
```

```bash
AGENT_PORT=5611 node agent.mjs
```

## Clean up

Stop both programs with Ctrl+C, then delete the password file:

```bash
rm -f .demo-login
```
