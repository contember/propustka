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
	/** JSON array of bootstrap-admin emails (normally empty). Resolution-time only. */
	IAM_BOOTSTRAP_ADMINS: string
	/**
	 * Cloudflare API token with *Access: Service Tokens Edit* — used for API-key
	 * (service-token) provisioning. Admin-only; never exposed to app callers.
	 */
	CF_API_TOKEN: string
	/** Cloudflare account id, for the Access API. */
	CF_ACCOUNT_ID: string
	/** `local` / `stage` / `prod`. */
	ENVIRONMENT: string
}
