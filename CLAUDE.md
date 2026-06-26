# propustka — agent notes

## Deploy (CI only — never from localhost)

Deploys run through the GitHub Actions **Deploy** workflow (`.github/workflows/deploy.yml`),
never from a local machine. The required CF secrets/vars (`CF_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`,
`PROPUSTKA_ACCESS_APPS`, `PROPUSTKA_TEAM`, …) live in GitHub **Environments** (stage/prod), not in
anyone's shell — so `bunx oblaka … --remote` will only ever succeed inside CI.

Triggers:

- **prod** — push to the `deploy/prod` branch (fast-forward it to the desired `main` commit and
  push). To ship the current `main`: `git push origin main:deploy/prod`.
- **stage** — `main` → stage auto-deploy is **OFF** (stage was broken; every main push went red).
  Deploy stage on demand via **workflow_dispatch** (`environment=stage`), e.g.
  `gh workflow run deploy.yml -f environment=stage`.
- Either env can also be deployed manually via `workflow_dispatch` (`environment=stage|prod`).

The pipeline builds the admin SPA, runs `oblaka --remote` (provisions D1 + writes wrangler.jsonc),
applies D1 migrations, `wrangler deploy`, then pushes the runtime Worker secrets. See
`architecture.md` → Provisioning/Deploy for the full model.

The runtime `CF_API_TOKEN` secret needs **both** Access scopes: _Service Tokens — Edit_ (API-key
provisioning) **and** _Apps and Policies — Edit_ (the `PUT /admin/apps/:app/access` reusable-policy
reconcile). Cloudflare Access **edge rules** are Access-as-code:

- **propustka declares its OWN front door** in committed code (`packages/worker/propustka.access.ts`,
  hostname from `PROPUSTKA_HOSTNAME`). The operator BOOTSTRAP `scripts/provision-access.ts` reconciles
  just that one app directly into Cloudflare (the irreducible chicken-and-egg) and prints the
  `PROPUSTKA_ACCESS_APPS` value.
- **propustka owns the human audience centrally** — `HUMAN_EMAIL_DOMAINS` / `HUMAN_EMAILS` (deploy vars
  `PROPUSTKA_HUMAN_EMAIL_DOMAINS` / `PROPUSTKA_HUMAN_EMAILS`) decide WHO may pass Access as a human, for
  EVERY app. Apps declare only which paths are human-gated vs public, never the audience; any per-app
  `emailDomains`/`emails` on a `human` rule are ignored.
- **each downstream app** declares its own `propustka.access.ts` (+ schema) and self-reconciles via
  the admin endpoint at deploy time (`scripts/provision-access-rules.ts` / the app's own
  `provision:access`), authenticated with a **propustka-issued provisioning key** — mint one per app
  with `scripts/provision-key.ts` (or the admin UI's api-keys) and store it as the app's
  `PROPUSTKA_ACCESS_CLIENT_ID/SECRET`.

See `architecture.md` → Access-as-code provisioning.

## propustka-native auth (in progress — `propustka-native-spec.md`)

We are absorbing Cloudflare Access's job INTO propustka: its own SSO (any OIDC provider), its own
per-app tokens, and its own credentials (API keys / share links / passthrough JWTs) — so apps stop
depending on CF Access and we stop paying for / syncing with Access Teams. The foundation is built
and runs ALONGSIDE the Access path (incremental migration); CF Access machinery is deleted in a
later follow-up.

- propustka now ISSUES short-lived per-app permission tokens (ES256, `PROPUSTKA_SIGNING_KEYS`) that
  embed the resolved permissions, so the SDK (`PropustkaAuth` in `@propustka/client`) authorizes
  **locally** — no per-request RPC. Login is generic OIDC at `/auth/login` (the provider is set by
  `PROPUSTKA_OIDC_ISSUER` and discovered via `/.well-known/openid-configuration` — Google/Auth0/Okta/
  Keycloak/Entra) → opaque SSO session (`px_session`); the SDK mints/refreshes a `px_token` via the
  `mintToken` binding RPC.
- The wire token is ONE shape (no `kind`): `perms` + optional principal (`ptype`); `can(action,
  scope?)` is always `permits()`. The unified **credential primitive** is built (`credentials` table):
  `issueKey` mints an opaque revocable `px_` credential (optional principal binding, optional inline
  grants/downscope), `issueJwt` signs a stateless passthrough token; `mintFromKey` resolves a `px_`
  bearer → access token. `PropustkaAuth` accepts an `Authorization: Bearer` `px_` key (exchanged +
  cached) or a passthrough JWT (local verify) in addition to the `px_session` cookie. The capability
  tokens are now FULLY FOLDED into credentials (migration `0006`): `capability_tokens`/
  `capability_grants` dropped, `redeemCapability`→`mintFromKey`, `issueCapability`→`issueKey`,
  `revokeCapability`→`revokeKey`, the admin "Share links" page issues anonymous credentials, and the
  audit linkage column is `credential_id` (kind='redeem' retired). STILL on the CF path (add-only,
  follow-ups): `issueServiceToken` (the CF service-token half — native `px_` key minted alongside),
  the per-path rule schema, CF removal.
- New deploy vars/secrets: `PROPUSTKA_HOSTNAME` (now also the token `iss`), `PROPUSTKA_OIDC_ISSUER`,
  `PROPUSTKA_OIDC_CLIENT_ID` (+ optional `PROPUSTKA_OIDC_SCOPES`, `PROPUSTKA_OIDC_REQUIRE_VERIFIED_EMAIL`),
  and the SECRETS `PROPUSTKA_SIGNING_KEYS` (JSON array of EC P-256 private JWKs) +
  `PROPUSTKA_OIDC_CLIENT_SECRET` (`wrangler secret put` remote / `.dev.vars` local, like CF_API_TOKEN).
- **Read `propustka-native-spec.md` before touching this** — it has the unified model (stateful key
  vs passthrough JWT), what's built, and the follow-ups (repoint service tokens, the per-path rule
  schema, CF Access removal, Access bypass for `/auth/*`). The current design docs are just
  `propustka-native-spec.md` (auth model) + `architecture.md` (layout/provisioning/deploy); the
  superseded `iam-service-spec.md` / `admin-ui-spec.md` were deleted in the capability fold.

npm releases (`@propustka/core`, `@propustka/client`) publish on a `v*` tag via `release.yml`
(OIDC trusted publishing — no npm token).
