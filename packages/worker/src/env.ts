/**
 * The IAM Worker's CF bindings + vars/secrets. Single source of truth — every
 * other file imports from here, never re-declares the shape. JSON-typed vars
 * (`ACCESS_APPS`, `IAM_BOOTSTRAP_ADMINS`) are parsed once in `buildServices`.
 */
export interface Env {
	/** D1 holding both policy tables and append-only audit tables (one database). */
	DB: D1Database
	/** Admin SPA static assets (served at the Worker root for non-`/admin/*` paths). */
	ASSETS: Fetcher
	/**
	 * JSON object `{ "<aud-tag>": "<app-id>" }` — the JWT audience set AND the
	 * verified app-identity map. `jose` validates the token `aud` against
	 * `Object.keys(ACCESS_APPS)`; the matched value is the verified app id.
	 */
	ACCESS_APPS: string
	/** Access team domain (e.g. `https://acme.cloudflareaccess.com`) — the JWKS issuer. */
	TEAM: string
	/**
	 * JSON array of email domains that may pass Cloudflare Access as a HUMAN, for EVERY app propustka
	 * fronts (e.g. `["mangoweb.cz","contember.com"]`). propustka owns this centrally — apps declare
	 * only which paths are human-gated vs public, never the audience. Consumed by `reconcileAccess`.
	 */
	HUMAN_EMAIL_DOMAINS: string
	/** JSON array of specific emails that may pass Access as a HUMAN, in ADDITION to the domains. */
	HUMAN_EMAILS: string
	/** JSON array of bootstrap-admin emails (normally empty). Resolution-time only. */
	IAM_BOOTSTRAP_ADMINS: string
	/**
	 * Cloudflare API token used for Access provisioning (admin-only; never exposed to app callers).
	 * Needs BOTH *Access: Service Tokens — Edit* (API-key / service-token provisioning) AND
	 * *Access: Apps and Policies — Edit* (the `PUT /admin/apps/:app/access` reusable-policy reconcile).
	 */
	CF_API_TOKEN: string
	/** Cloudflare account id, for the Access API. */
	CF_ACCOUNT_ID: string
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
	 * key is generated per isolate (dev only). Never placed in `vars` — provisioned like CF_API_TOKEN.
	 */
	PROPUSTKA_SIGNING_KEYS: string
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
