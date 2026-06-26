-- Fold capability tokens into the unified credentials primitive.
--
-- The `capability_tokens` / `capability_grants` tables and the redeemCapability path are gone:
-- a share link is now just an ANONYMOUS credential (a `credentials` row with principal_id NULL
-- + `credential_grants`), resolved through `mintFromKey` like any other `px_` key, and its
-- permissions are matched by `permits()` (action + scope), not the old exact (action, resource)
-- pair. See propustka-native-spec.md → Migration.
--
-- This migration drops the retired tables, renames the anonymous-actor audit linkage column
-- `capability_token_id` → `credential_id` (in `audit_events` + `auth_log`), and retires the now
-- unused `auth_log` kind='redeem' (mintFromKey logs as 'authenticate').

DROP TABLE capability_grants;
DROP TABLE capability_tokens;

-- audit_events: rename the anonymous-actor linkage column (now any anonymous credential).
ALTER TABLE audit_events RENAME COLUMN capability_token_id TO credential_id;

-- auth_log: rename the column AND drop 'redeem' from the kind CHECK. SQLite can't ALTER a CHECK
-- in place, so rebuild the table (it is never FK'd — a plain rowid PK). Historical 'redeem' rows
-- fold to 'authenticate' (a capability redeem WAS an authentication of a credential).
CREATE TABLE auth_log_new (
	id            INTEGER PRIMARY KEY,
	request_id    TEXT NOT NULL,
	app           TEXT NOT NULL,
	kind          TEXT NOT NULL CHECK (kind IN ('authenticate')),
	principal_id  TEXT REFERENCES principals(id) ON DELETE SET NULL,
	credential_id TEXT,
	decision      TEXT NOT NULL CHECK (decision IN ('allow','deny')),
	reason        TEXT,
	created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO auth_log_new (id, request_id, app, kind, principal_id, credential_id, decision, reason, created_at)
	SELECT id, request_id, app, 'authenticate', principal_id, capability_token_id, decision, reason, created_at
	FROM auth_log;
DROP TABLE auth_log;
ALTER TABLE auth_log_new RENAME TO auth_log;
CREATE INDEX idx_auth_log_principal ON auth_log(principal_id, created_at);
CREATE INDEX idx_auth_log_request   ON auth_log(request_id);
