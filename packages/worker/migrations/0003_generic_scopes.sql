-- Generic flat scopes + app-owned vocabulary + AWS-IAM-style policies.
--
-- Until now a grant's scope was a single hardcoded dimension: `project_id`, a FK
-- into a Propustka-owned `projects` table. That baked one app's mental model into
-- the IAM core. Real apps disagree: opice scopes by organization/team, poplach by
-- project, the next app by something else entirely. So scope goes GENERIC and FLAT:
--   * scope_type  — the dimension name ('organization' | 'team' | 'project' | …)
--   * scope_value — an OPAQUE, app-owned identifier (we never FK or interpret it)
-- Propustka stops owning scope values; each app owns its own and just hands us the
-- (type, value) pair. The `projects` table is therefore retired.
--
-- The legal dimensions/actions/roles are no longer hardcoded in Worker TS either —
-- they're a VOCABULARY each app declares in code and we reconcile into three tables
-- (app_scopes, app_actions, roles) so the admin UI can render real choices instead
-- of free-text. Permissions become AWS-IAM-style: a grant carries either a named
-- role (a reusable bundle, app-declared or admin-composed) OR an inline JSON action
-- set — exactly one, like an inline policy vs. an attached managed policy.
--
-- SQLite mechanics that shape this migration:
--   * No DROP COLUMN that also rewrites CHECKs, and no ALTER of a CHECK in place.
--     `grants` and `group_role_mappings` change shape (drop project_id, add columns,
--     add new CHECKs), so each is rebuilt via the canonical create-new → copy →
--     drop-old → rename pattern.
--   * D1 runs migrations with foreign_keys ON. The rebuild order matters: we copy
--     rows BEFORE dropping the source, and we drop `projects` only AFTER `grants`
--     and `group_role_mappings` (which referenced it) have been rebuilt without that
--     FK — otherwise the DROP would violate / the rebuild would dangle. RENAME does
--     not rewrite child FKs here because nothing references grants/mappings.
--   * NULLs are distinct in a UNIQUE index, so "one global grant per (principal,
--     role, app)" still needs partial unique indexes with COALESCE(app,'*') — same
--     trap, same fix as 0001/0002.

-- ── App-declared vocabulary (reconciled from each app's code) ─────────────────

-- The scope DIMENSIONS an app understands. authenticate() doesn't need this (scope
-- matching is opaque string equality); it exists so the admin UI can offer a real
-- dropdown of scope types per app instead of free text. PK (app, scope_type) — a
-- dimension is unique within an app, different apps may reuse the same name.
CREATE TABLE app_scopes (
	app        TEXT NOT NULL,
	scope_type TEXT NOT NULL,                       -- 'organization' | 'team' | 'project' | …
	label      TEXT,                                -- human label for the admin UI
	PRIMARY KEY (app, scope_type)
);

-- The ACTION CATALOG per app — every concrete action the app authorizes against.
-- Roles/inline permissions reference these by string (or glob pattern); this table
-- is the source of truth the admin UI lists and validates against. PK (app, action).
CREATE TABLE app_actions (
	app         TEXT NOT NULL,
	action      TEXT NOT NULL,                      -- concrete action, e.g. 'project.read'
	description TEXT,
	PRIMARY KEY (app, action)
);

-- Named permission BUNDLES (AWS "managed policies"). Either reconciled from app code
-- (origin='app' — the app ships a canonical 'editor'/'viewer') or composed by an
-- admin in the UI (origin='custom'). `permissions` is a JSON array of action patterns
-- (e.g. ["project.read","report.*"]); json_valid keeps malformed JSON out at write
-- time so the read path can JSON-parse without defensive guards. PK (app, role_key).
CREATE TABLE roles (
	app         TEXT NOT NULL,
	role_key    TEXT NOT NULL,
	name        TEXT NOT NULL,
	description TEXT,
	permissions TEXT NOT NULL CHECK (json_valid(permissions)),     -- JSON array of action patterns
	origin      TEXT NOT NULL CHECK (origin IN ('app', 'custom')),  -- 'app'=reconciled from code, 'custom'=admin-made
	created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
	PRIMARY KEY (app, role_key)
);

-- ── grants — rebuilt for generic scope + inline-or-role permissions ───────────
--
-- New shape vs. 0001/0002: project_id is gone; scope is the generic (scope_type,
-- scope_value) pair; permissions can be inline. A grant is EITHER role-based
-- (role_key set) OR inline (permissions set) — exactly one, enforced by the XOR
-- CHECK below. Scope is both-or-neither (a dangling scope_type with no value, or
-- vice versa, is meaningless). role_key is NOT FK'd to roles(app, role_key): a grant
-- may set app=NULL (cross-app) while a role row always has a concrete app, so an FK
-- can't express it — roles are validated in the Worker against the reconciled set.
CREATE TABLE grants_new (
	id           TEXT PRIMARY KEY,                  -- UUIDv7
	principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
	app          TEXT,                              -- NULL = all apps (cross-app, e.g. super-admin)
	role_key     TEXT,                              -- named role/policy; XOR permissions
	permissions  TEXT CHECK (permissions IS NULL OR json_valid(permissions)),  -- inline action set; XOR role_key
	scope_type   TEXT,                              -- NULL = global (all scopes)
	scope_value  TEXT,                              -- opaque, app-owned; NULL = global
	granted_by   TEXT REFERENCES principals(id),
	expires_at   INTEGER,                           -- NULL = permanent
	created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
	CHECK ((role_key IS NULL) <> (permissions IS NULL)),  -- exactly one of role_key / inline permissions
	CHECK ((scope_type IS NULL) = (scope_value IS NULL))  -- scope is both-or-neither
);

-- Migrate existing rows. Every pre-0003 grant was role-based (no inline column
-- existed), so permissions copies as NULL and the XOR holds. project_id maps to the
-- generic ('project', <id>) pair; a NULL project_id (global) maps to (NULL, NULL).
-- `app` carries over verbatim from 0002.
INSERT INTO grants_new (id, principal_id, app, role_key, permissions, scope_type, scope_value, granted_by, expires_at, created_at)
	SELECT id, principal_id, app, role_key, NULL,
	       CASE WHEN project_id IS NULL THEN NULL ELSE 'project' END,
	       project_id, granted_by, expires_at, created_at
	FROM grants;

DROP TABLE grants;
ALTER TABLE grants_new RENAME TO grants;

-- Recreate the partial unique indexes. KEY DIFFERENCE: they constrain ONLY
-- role-based grants (role_key IS NOT NULL). Inline grants are intentionally
-- unconstrained — each inline permission set is its own distinct attachment (like
-- two separate inline policies), so duplicates across (principal, scope, app) are
-- allowed and meaningful. NULL app folds to '*' so two NULL-app globals still
-- collide (raw NULLs would be treated as distinct).
CREATE UNIQUE INDEX idx_grants_uq_scoped ON grants(principal_id, role_key, scope_type, scope_value, COALESCE(app, '*'))
	WHERE role_key IS NOT NULL AND scope_value IS NOT NULL;
CREATE UNIQUE INDEX idx_grants_uq_global ON grants(principal_id, role_key, COALESCE(app, '*'))
	WHERE role_key IS NOT NULL AND scope_value IS NULL;

CREATE INDEX idx_grants_principal ON grants(principal_id);

-- ── group_role_mappings — rebuilt for generic scope ──────────────────────────
--
-- Same project_id → (scope_type, scope_value) move as grants. Mappings stay
-- ROLE-ONLY (no inline permissions): a group maps to a named role, never to an
-- ad-hoc action set. `app` (from 0002) carries over. Both-or-neither scope CHECK
-- added to mirror grants.
CREATE TABLE group_role_mappings_new (
	id         TEXT PRIMARY KEY,                    -- UUIDv7
	provider   TEXT NOT NULL,                       -- 'github'
	group_ref  TEXT NOT NULL,                       -- 'my-org/core-devs' (org/team slug, lowercase)
	role_key   TEXT NOT NULL,                       -- validated against the app's reconciled roles
	app        TEXT,                                -- NULL = all apps (from 0002)
	scope_type TEXT,                                -- NULL = global
	scope_value TEXT,                               -- opaque, app-owned; NULL = global
	created_at INTEGER NOT NULL DEFAULT (unixepoch()),
	CHECK ((scope_type IS NULL) = (scope_value IS NULL))  -- scope is both-or-neither
);

INSERT INTO group_role_mappings_new (id, provider, group_ref, role_key, app, scope_type, scope_value, created_at)
	SELECT id, provider, group_ref, role_key, app,
	       CASE WHEN project_id IS NULL THEN NULL ELSE 'project' END,
	       project_id, created_at
	FROM group_role_mappings;

DROP TABLE group_role_mappings;
ALTER TABLE group_role_mappings_new RENAME TO group_role_mappings;

-- Recreate the partial unique indexes (now keyed on the generic scope columns) and
-- the lookup index. Same NULL-app→'*' fold as grants.
CREATE UNIQUE INDEX idx_group_mappings_uq_scoped
	ON group_role_mappings(provider, group_ref, role_key, scope_type, scope_value, COALESCE(app, '*'))
	WHERE scope_value IS NOT NULL;
CREATE UNIQUE INDEX idx_group_mappings_uq_global
	ON group_role_mappings(provider, group_ref, role_key, COALESCE(app, '*'))
	WHERE scope_value IS NULL;

CREATE INDEX idx_group_mappings_ref ON group_role_mappings(provider, group_ref);

-- ── Retire the projects table ────────────────────────────────────────────────
--
-- Scope values are app-owned now; Propustka no longer stores them. Dropped LAST,
-- after grants/group_role_mappings were rebuilt without the FK that referenced it,
-- so no dangling reference remains. Its indexes (the implicit slug UNIQUE) go with
-- it automatically.
DROP TABLE projects;
