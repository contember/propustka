-- Unified opaque credentials — propustka's stored credential primitive (API keys + share links).
--
-- This replaces the api-key-vs-capability split (see propustka-native-spec.md): there is ONE stored
-- thing, an opaque `px_` secret (only its SHA-256 hash kept), that propustka resolves into a short
-- signed access token. Two optional dimensions, not two tables:
--   - principal_id set  → the credential carries that principal's LIVE resolved permissions (and is
--                          revoked by disabling the principal); a machine API key / personal token.
--   - principal_id NULL → an anonymous credential whose FROZEN inline grants (credential_grants) are
--                          the whole permission set; a share link.
-- Inline grants on a principal-bound credential act as a DOWNSCOPE restriction (effective =
-- resolve(principal) ∩ grants). No use counter: single-use is the app's operation state, not a token
-- property (see the spec). `capability_tokens` is migrated onto this in a follow-up.

CREATE TABLE credentials (
	id           TEXT PRIMARY KEY,                  -- UUIDv7, ours
	token_hash   TEXT NOT NULL UNIQUE,              -- SHA-256 of the opaque `px_` secret; never plaintext
	label        TEXT,                              -- human-readable, e.g. 'opice CI — ingest'
	principal_id TEXT REFERENCES principals(id) ON DELETE CASCADE, -- NULL = anonymous (frozen inline grants)
	issued_by    TEXT REFERENCES principals(id),    -- resolved server-side at issue, never self-asserted
	expires_at   INTEGER,                           -- absolute expiry (unix seconds); NULL = no expiry
	revoked_at   INTEGER,                           -- explicit revoke; NULL = active
	created_at   INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_credentials_principal ON credentials(principal_id);
-- Prune scans by expiry (the daily cron can sweep expired/revoked rows).
CREATE INDEX idx_credentials_expires ON credentials(expires_at);

-- What an inline-grant credential confers: 1..N (action, scope) entries, matched by permits().
-- scope_type/scope_value are both-or-neither (both NULL = global), mirroring the grants table.
CREATE TABLE credential_grants (
	credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
	action        TEXT NOT NULL,
	scope_type    TEXT,
	scope_value   TEXT,
	CHECK ((scope_type IS NULL) = (scope_value IS NULL))
);

CREATE INDEX idx_credential_grants_credential ON credential_grants(credential_id);
