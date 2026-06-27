# propustka — agent notes

## Deploy (CI only — never from localhost)

Deploys run through the GitHub Actions **Deploy** workflow (`.github/workflows/deploy.yml`),
never from a local machine. The required deploy vars/secrets (`PROPUSTKA_HOSTNAME`,
`PROPUSTKA_HUMAN_EMAIL_DOMAINS`, `PROPUSTKA_OIDC_ISSUER`, `PROPUSTKA_OIDC_CLIENT_ID`, the secrets
`PROPUSTKA_SIGNING_KEYS` / `PROPUSTKA_OIDC_CLIENT_SECRET`, …) live in GitHub **Environments**
(stage/prod), not in anyone's shell — so `bunx oblaka … --remote` will only ever succeed inside CI.

Triggers:

- **prod** — push to the `deploy/prod` branch (fast-forward it to the desired `main` commit and
  push). To ship the current `main`: `git push origin main:deploy/prod`.
- **stage** — `main` → stage auto-deploy is **OFF** (stage was broken; every main push went red).
  Deploy stage on demand via **workflow_dispatch** (`environment=stage`), e.g.
  `gh workflow run deploy.yml -f environment=stage`.
- Either env can also be deployed manually via `workflow_dispatch` (`environment=stage|prod`).

The pipeline builds the admin SPA, runs `oblaka --remote` (provisions D1 + writes wrangler.jsonc),
applies D1 migrations, `wrangler deploy`, then pushes the runtime Worker secrets
(`PROPUSTKA_SIGNING_KEYS`, `PROPUSTKA_OIDC_CLIENT_SECRET`). See `architecture.md` →
Provisioning/Deploy for the full model.

## Native auth — propustka IS the auth layer (no Cloudflare Access)

Cloudflare Access has been **removed entirely**. propustka does its own SSO (any OIDC provider),
issues its own per-app tokens, owns its own credentials (API keys / share links / passthrough
JWTs), and gates every path in-process. There is no CF Access edge, no `Cf-Access-Jwt-Assertion`,
no service tokens, no Access Teams, no `ACCESS_APPS`/`TEAM`/`CF_API_TOKEN`/`CF_ACCOUNT_ID`.

- **Humans** log in via generic OIDC at `/auth/login` (provider set by `PROPUSTKA_OIDC_ISSUER`,
  discovered via `/.well-known/openid-configuration` — Google/Auth0/Okta/Keycloak/Entra) → opaque
  SSO session (`px_session` cookie). The SDK (`PropustkaAuth` in `@propustka/client`) mints/refreshes
  a short-lived signed per-app access token (`px_token`) via the `mintToken` binding RPC, then
  authorizes **locally** — no per-request RPC.
- **Machines** present an opaque `px_` key (`Authorization: Bearer`, exchanged via `mintFromKey` +
  cached) or a passthrough JWT (verified locally). Both are propustka-native; no CF client_id/secret.
- The wire token is ONE shape (no `kind`): `perms` + optional principal (`ptype`); `can(action,
  scope?)` is always `permits()` (ES256, signed with `PROPUSTKA_SIGNING_KEYS`, verifiable locally
  via the JWKS the SDK fetches once over the binding).
- **Per-path gating is in-process**, not an edge reconcile. Each app declares an `AppGates` (in
  `@propustka/core`) — an ordered list of `{ path, kind }` rules (`public` / `service` / `human`),
  first-match-wins, **fail-closed** when nothing matches — and passes it to `PropustkaAuth`. There is
  NO worker endpoint and NO reconcile for gates; they are pure SDK config (see
  `examples/app/propustka.gates.ts`). `/auth/*` + `/.well-known/jwks.json` live on propustka's OWN
  host, so apps never declare them.
- **propustka owns the human audience centrally** — `HUMAN_EMAIL_DOMAINS` / `HUMAN_EMAILS` (deploy
  vars `PROPUSTKA_HUMAN_EMAIL_DOMAINS` / `PROPUSTKA_HUMAN_EMAILS`) are the login-admission allowlist:
  WHO may self-provision a new identity at `/auth/callback`. A `*` entry in either list = admit-all;
  otherwise an exact email or matching domain. Bootstrap admins (`IAM_BOOTSTRAP_ADMINS`) and
  already-known/invited principals are always admitted. Empty allowlist with no `*` → only
  bootstrap/known may log in (fail-closed).

### Admin gate + provisioning (also native)

- **`/admin/*`** (the admin SPA + JSON API) is gated by propustka itself at app `propustka`:
  a `px_session` cookie (humans) or `Authorization: Bearer px_<admin key>` (CI/scripts), then
  `permits(perms, 'iam.admin')`. A CSRF/cross-origin guard is kept. Locally, a dev bypass resolves a
  fixed `local-dev-admin` when `ENVIRONMENT=local` && `PROPUSTKA_SIGNING_KEYS` empty && no credential.
- **App registry** is DB-derived: `db.listKnownApps()` = distinct `app` across `app_actions ∪
  app_scopes ∪ roles`. An app's FIRST `PUT /admin/apps/:app/schema` reconcile is what registers it.
- **Each downstream app** declares its own authz vocabulary (`propustka.schema.ts`, a typed
  `AppSchema`) and self-reconciles via `PUT /admin/apps/:app/schema` at deploy time
  (`scripts/provision-schemas.ts` / `reconcileSchema` in `@propustka/client`), authenticated with a
  **propustka-issued `px_` admin key** sent as `Authorization: Bearer`. Mint one per app with
  `scripts/provision-key.ts` (or the admin UI's api-keys page) — it creates a native service principal
  - bound `px_` key — and store the returned key as the app's `PROPUSTKA_ADMIN_KEY` CI secret.
- **Seeded provisioning key (control-plane bootstrap).** Setting the `PROPUSTKA_PROVISIONING_KEY` secret
  (one operator-generated `px_`, held only in env — never in the DB) makes `resolveCaller` admit a bearer
  matching it as a synthetic global-admin `provisioning-admin` — the MACHINE analog of
  `IAM_BOOTSTRAP_ADMINS`. It lets a control plane (vozka) reconcile schemas / issue the first admin key
  BEFORE any DB-backed admin credential exists, so there's no mint-then-store chicken-and-egg. Optional
  (empty = disabled), idempotent, rotatable (change the env). Migration `0008` seeds the stable
  `provisioning-admin` principal so its audit `principal_id` FK resolves.
- `group_role_mappings` is **dropped** (migration `0007`): no IdP-group→role resolution. Permission
  resolution is explicit grants ∪ bootstrap only.

### Deploy vars/secrets

- Vars: `PROPUSTKA_HOSTNAME` (also the token `iss` / OIDC redirect base),
  `PROPUSTKA_HUMAN_EMAIL_DOMAINS` (+ optional `PROPUSTKA_HUMAN_EMAILS`),
  `PROPUSTKA_OIDC_ISSUER`, `PROPUSTKA_OIDC_CLIENT_ID` (+ optional `PROPUSTKA_OIDC_SCOPES`,
  `PROPUSTKA_OIDC_REQUIRE_VERIFIED_EMAIL`, `PROPUSTKA_SESSION_COOKIE_DOMAIN`,
  `PROPUSTKA_BOOTSTRAP_ADMINS`).
- Secrets (out-of-band: `wrangler secret put` remote / `.dev.vars` local, never in `vars`):
  `PROPUSTKA_SIGNING_KEYS` (JSON array of EC P-256 private JWKs) + `PROPUSTKA_OIDC_CLIENT_SECRET`
  (+ optional `PROPUSTKA_PROVISIONING_KEY`, the seeded control-plane bootstrap bearer).

**Design docs:** `propustka-native-spec.md` (the auth model — unified credential primitive, the
access token shape, the login flow, per-path gates) + `architecture.md` (repository layout, package
graph, provisioning, deploy). Read `propustka-native-spec.md` before touching the auth core.

npm releases (`@propustka/core`, `@propustka/client`) publish on a `v*` tag via `release.yml`
(OIDC trusted publishing — no npm token).
