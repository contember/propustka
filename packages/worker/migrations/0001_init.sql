-- Propustka IAM — initial schema.
--
-- Two concerns with opposite characteristics live here:
--   * policies — mutable current state, read on every request.
--   * audit    — append-only history, written often, read rarely.
-- They are distinct table groups (logical separation, one D1) with different
-- retention: prune `auth_log` after weeks, keep `audit_events` long.
--
-- All self-owned string ids are UUIDv7 (time-sortable), generated in-Worker —
-- the TEXT id columns are never filled by SQL. `auth_log` is the one exception:
-- it uses a plain INTEGER rowid (densest table, cheapest insert, never FK'd) —
-- and deliberately NOT AUTOINCREMENT (the more expensive variant, no benefit here).
-- `unixepoch()` defaults stamp creation time in seconds.

-- ── Policies ────────────────────────────────────────────────────────────────

CREATE TABLE principals (
	id          TEXT PRIMARY KEY,                 -- UUIDv7, ours; STABLE — grants & audit reference this, never external_id
	type        TEXT NOT NULL CHECK (type IN ('user','service')),
	external_id TEXT,                              -- Access `sub` (user) / client_id (service). NULL = user INVITED, not yet claimed (first login pending)
	email       TEXT,                             -- users: invite-match key + label source; NULL for services
	label       TEXT NOT NULL,                     -- email / token name, human-readable
	disabled_at INTEGER,                           -- soft-disable, NULL = active
	created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Status is derived: invited (external_id IS NULL) → claimed/active → disabled (disabled_at set).
-- external_id is NULL for invited-not-yet-claimed users, so a plain UNIQUE(type, external_id)
-- would treat those NULLs as distinct. Partial unique indexes (same pattern as grants):
CREATE UNIQUE INDEX idx_principals_uq_external ON principals(type, external_id)
	WHERE external_id IS NOT NULL;
-- At most one user principal per email (the invite target, then the claimed identity):
CREATE UNIQUE INDEX idx_principals_uq_email ON principals(email)
	WHERE type = 'user' AND email IS NOT NULL;

CREATE TABLE projects (
	id         TEXT PRIMARY KEY,                   -- UUIDv7
	slug       TEXT NOT NULL UNIQUE,
	name       TEXT NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE grants (
	id           TEXT PRIMARY KEY,                 -- UUIDv7
	principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
	role_key     TEXT NOT NULL,                    -- validated against the code role registry
	project_id   TEXT REFERENCES projects(id) ON DELETE CASCADE,  -- NULL = global / all projects
	granted_by   TEXT REFERENCES principals(id),
	expires_at   INTEGER,                          -- NULL = permanent
	created_at   INTEGER NOT NULL DEFAULT (unixepoch())
);

-- SQLite treats NULLs as distinct in UNIQUE constraints, so a plain
-- UNIQUE(principal_id, role_key, project_id) would allow unlimited duplicate
-- global grants (project_id IS NULL). Two partial unique indexes instead:
CREATE UNIQUE INDEX idx_grants_uq_scoped ON grants(principal_id, role_key, project_id)
	WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX idx_grants_uq_global ON grants(principal_id, role_key)
	WHERE project_id IS NULL;

CREATE INDEX idx_grants_principal ON grants(principal_id);

CREATE TABLE group_role_mappings (
	id         TEXT PRIMARY KEY,                   -- UUIDv7
	provider   TEXT NOT NULL,                      -- 'github'
	group_ref  TEXT NOT NULL,                      -- 'my-org/core-devs' (org/team slug, lowercase)
	role_key   TEXT NOT NULL,                      -- validated against the code role registry
	project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,  -- NULL = global
	created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Same NULL-in-UNIQUE caveat as grants: partial unique indexes.
CREATE UNIQUE INDEX idx_group_mappings_uq_scoped
	ON group_role_mappings(provider, group_ref, role_key, project_id)
	WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX idx_group_mappings_uq_global
	ON group_role_mappings(provider, group_ref, role_key)
	WHERE project_id IS NULL;

CREATE INDEX idx_group_mappings_ref ON group_role_mappings(provider, group_ref);

-- ── Audit ───────────────────────────────────────────────────────────────────

-- domain events: what actually changed (produced by apps)
CREATE TABLE audit_events (
	id                  TEXT PRIMARY KEY,           -- UUIDv7 = time-sortable
	request_id          TEXT NOT NULL,              -- correlates with auth log
	principal_id        TEXT REFERENCES principals(id) ON DELETE SET NULL,
	principal_label     TEXT NOT NULL,              -- SNAPSHOT, survives principal deletion
	capability_token_id TEXT,                       -- set when acting under a capability; principal_id is NULL then
	app                 TEXT NOT NULL,              -- self-asserted caller id (audit() carries no token; see hard req 3)
	action              TEXT NOT NULL,              -- 'project.settings.update'
	resource_type       TEXT NOT NULL,              -- 'project'
	resource_id         TEXT,
	diff                TEXT CHECK (diff IS NULL OR json_valid(diff)),       -- {"field":["old","new"]}
	metadata            TEXT CHECK (metadata IS NULL OR json_valid(metadata)),
	created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_audit_resource  ON audit_events(resource_type, resource_id, created_at);
CREATE INDEX idx_audit_principal ON audit_events(principal_id, created_at);
CREATE INDEX idx_audit_request   ON audit_events(request_id);

-- auth log: every authenticate()/redeemCapability() outcome (produced by IAM Worker)
CREATE TABLE auth_log (
	id                  INTEGER PRIMARY KEY,        -- plain rowid: densest table, cheapest insert, never FK'd
	request_id          TEXT NOT NULL,
	app                 TEXT NOT NULL,              -- aud-derived (verified) when a valid token was presented; self-asserted otherwise
	kind                TEXT NOT NULL CHECK (kind IN ('authenticate','redeem')),
	principal_id        TEXT REFERENCES principals(id) ON DELETE SET NULL,
	capability_token_id TEXT,                       -- set for kind='redeem'
	decision            TEXT NOT NULL CHECK (decision IN ('allow','deny')),
	reason              TEXT,                        -- failure reason on deny; 'groups_unavailable' flag noted here too
	created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_auth_log_principal ON auth_log(principal_id, created_at);
CREATE INDEX idx_auth_log_request   ON auth_log(request_id);

-- ── Capability tokens (anonymous, scoped, short-lived) ───────────────────────

CREATE TABLE capability_tokens (
	id          TEXT PRIMARY KEY,                 -- UUIDv7
	token_hash  TEXT NOT NULL UNIQUE,             -- SHA-256 of the token; never store plaintext
	label       TEXT,                             -- 'Client ACME — report Q2', human-readable
	issued_by   TEXT REFERENCES principals(id),   -- resolved server-side at issue time, never self-asserted
	expires_at  INTEGER,
	max_uses    INTEGER,                           -- NULL = unlimited (coarse whole-token cap)
	used_count  INTEGER NOT NULL DEFAULT 0,        -- incremented on EVERY successful redeem (telemetry)
	revoked_at  INTEGER,
	created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- what the token can do: 1..N (action, resource) pairs
CREATE TABLE capability_grants (
	token_id  TEXT NOT NULL REFERENCES capability_tokens(id) ON DELETE CASCADE,
	action    TEXT NOT NULL,                       -- 'report.read' | 'report.feedback.create'
	resource  TEXT NOT NULL,                       -- 'report:q2-acme'
	PRIMARY KEY (token_id, action, resource)
);
