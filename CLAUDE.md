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

npm releases (`@propustka/core`, `@propustka/client`) publish on a `v*` tag via `release.yml`
(OIDC trusted publishing — no npm token).
