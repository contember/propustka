/**
 * The IAM Worker's CF bindings + vars/secrets. Single source of truth — every
 * other file imports from here, never re-declares the shape. JSON-typed vars
 * (`HUMAN_EMAIL_DOMAINS`, `HUMAN_EMAILS`, `IAM_BOOTSTRAP_ADMINS`, `DOMAIN_DEFAULT_GRANTS`)
 * are parsed once in `buildServices`.
 */
export interface Env {
	/** D1 holding both policy tables and append-only audit tables (one database). */
	DB: D1Database
	/** Admin SPA static assets (served at the Worker root for non-`/admin/*` paths). */
	ASSETS: Fetcher
	/**
	 * JSON array of email domains admitted as a HUMAN at login (e.g. `["mangoweb.cz","contember.com"]`).
	 * A `*` entry means admit anyone. propustka owns this centrally — the login-admission allowlist for
	 * self-provisioning a new identity. Consumed by `/auth/callback`.
	 */
	HUMAN_EMAIL_DOMAINS: string
	/** JSON array of specific emails admitted as a HUMAN, in ADDITION to the domains (a `*` = admit-all). */
	HUMAN_EMAILS: string
	/** JSON array of bootstrap-admin emails (normally empty). Always admitted; resolution-time only. */
	IAM_BOOTSTRAP_ADMINS: string
	/**
	 * JSON array of default role grants keyed by email domain, e.g.
	 * `[{"domain":"contember.com","app":"revizor","role":"user"}]`. Every entry matching a
	 * logging-in human's email domain is ensured (grant-if-missing) as a plain role grant at
	 * EVERY `/auth/callback` login — so config additions reach existing principals on their next
	 * sign-in. Empty (`[]`) disables the feature. Removing an entry stops future ensures but does
	 * not revoke rows already granted (delete those in the admin UI).
	 */
	DOMAIN_DEFAULT_GRANTS: string
	/** `local` / `stage` / `prod`. */
	ENVIRONMENT: string

	// ── propustka-native auth (propustka issues its own tokens; see token.ts / signing.ts) ──

	/**
	 * propustka's OWN origin, e.g. `https://propustka.example.com` — the `iss` of every minted
	 * token AND the base for the Google OIDC redirect URI. Derived from `PROPUSTKA_HOSTNAME` at
	 * deploy time; a localhost value locally.
	 */
	ISSUER: string
	/**
	 * **Secret.** JSON array of ES256 (EC P-256) PRIVATE JWKs. Index 0 is the active signer; all are
	 * published in the JWKS so a rotation key verifies before it signs. Empty locally → an ephemeral
	 * key is generated per isolate (dev only). Never placed in `vars` — provisioned as a Worker secret
	 * (`wrangler secret put` remote / `.dev.vars` local).
	 */
	PROPUSTKA_SIGNING_KEYS: string
	/**
	 * **Secret.** A single operator-generated provisioning `px_` key, or empty to disable (the default).
	 * Held ONLY here — never in the DB. A bearer whose hash matches it resolves a synthetic global-admin
	 * in `resolveCaller` (the machine analog of `IAM_BOOTSTRAP_ADMINS`): it lets a control plane bootstrap
	 * itself — reconcile app schemas / issue the first admin key — before any DB-backed admin credential
	 * exists. Provisioned as a Worker secret (`wrangler secret put` remote / `.dev.vars` local), never in
	 * `vars`. Rotate by changing the env value.
	 */
	PROPUSTKA_PROVISIONING_KEY: string
	/**
	 * Cookie `Domain` for the SSO session cookie, e.g. `.example.com`, so one login is shared across
	 * `*.example.com` apps. Empty → host-only (single-host / local dev).
	 */
	SESSION_COOKIE_DOMAIN: string
	/**
	 * OIDC provider issuer URL (e.g. `https://accounts.google.com`, an Auth0/Okta/Keycloak/Entra
	 * tenant). propustka discovers the endpoints from `${OIDC_ISSUER}/.well-known/openid-configuration`
	 * — so ANY OIDC provider works via config, no per-provider code.
	 */
	OIDC_ISSUER: string
	/** OIDC client id (public). The SSO upstream — propustka federates here for human login. */
	OIDC_CLIENT_ID: string
	/** **Secret.** OIDC client secret (the code-exchange credential). */
	OIDC_CLIENT_SECRET: string
	/** Space-separated OIDC scopes; empty → `openid email profile`. */
	OIDC_SCOPES: string
	/** `'false'` to accept logins whose `email_verified` claim is absent (an IdP that omits it); else verified is required. */
	OIDC_REQUIRE_VERIFIED_EMAIL: string
}
