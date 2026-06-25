-- SSO sessions — propustka issues its own login session now (it is the IdP relying party).
--
-- Background: until now authn was Cloudflare Access (the request arrived with a verified Access
-- JWT). propustka now federates to Google directly and mints its OWN session: the long-lived,
-- opaque SSO credential a browser carries. The session is the source of truth for "who is logged
-- in"; from it the Worker mints short-lived per-app permission tokens (the SDK verifies those
-- locally, no round-trip). Deleting/revoking the session is what makes a NEW permission token
-- impossible — outstanding tokens still run until their own (short) expiry.
--
-- Only the SHA-256 hash of the opaque cookie value is stored (same as capability_tokens): a DB
-- leak yields no usable session. `id` is our UUIDv7; the cookie carries the plaintext token.

CREATE TABLE sessions (
	id           TEXT PRIMARY KEY,                  -- UUIDv7, ours
	token_hash   TEXT NOT NULL UNIQUE,              -- SHA-256 of the opaque session cookie value; never plaintext
	principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
	idp_sub      TEXT NOT NULL,                      -- upstream IdP subject (Google `sub`)
	email        TEXT,                               -- snapshot, for the admin session list / display
	created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
	expires_at   INTEGER NOT NULL,                   -- absolute session expiry (unix seconds)
	revoked_at   INTEGER                             -- explicit logout / admin kill; NULL = active
);

CREATE INDEX idx_sessions_principal ON sessions(principal_id);
-- Prune scans by expiry (the daily cron deletes expired/revoked rows).
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
