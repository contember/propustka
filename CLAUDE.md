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

npm releases (`@propustka/core`, `@propustka/client`) publish on a `v*` tag via `release.yml`
(OIDC trusted publishing — no npm token).
