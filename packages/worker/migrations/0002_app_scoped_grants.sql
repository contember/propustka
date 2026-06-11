-- App-scoped grants + group mappings.
--
-- Propustka serves many apps (opice, poplach, …) over the same service binding. A
-- grant/mapping previously had no app dimension, so its permissions applied to EVERY
-- app — a `project.read` editor was an editor everywhere. authenticate() now filters
-- a principal's permissions by the aud-verified calling app: a grant counts only when
-- its `app` equals the calling app OR is NULL (cross-app, e.g. the super-admin).
--
-- `app` is the app id from ACCESS_APPS (the value side, e.g. 'opice'), NULL = all apps.

ALTER TABLE grants ADD COLUMN app TEXT;
ALTER TABLE group_role_mappings ADD COLUMN app TEXT;

-- Recreate the uniqueness to include `app`: a principal may legitimately hold the
-- same role for different apps (editor@opice AND editor@poplach). NULL app is folded
-- to '*' via COALESCE so two NULL-app global grants still collide (SQLite treats raw
-- NULLs as distinct in a UNIQUE index — COALESCE restores the "one per" intent).
DROP INDEX idx_grants_uq_scoped;
DROP INDEX idx_grants_uq_global;
CREATE UNIQUE INDEX idx_grants_uq_scoped ON grants(principal_id, role_key, project_id, COALESCE(app, '*'))
	WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX idx_grants_uq_global ON grants(principal_id, role_key, COALESCE(app, '*'))
	WHERE project_id IS NULL;

DROP INDEX idx_group_mappings_uq_scoped;
DROP INDEX idx_group_mappings_uq_global;
CREATE UNIQUE INDEX idx_group_mappings_uq_scoped
	ON group_role_mappings(provider, group_ref, role_key, project_id, COALESCE(app, '*'))
	WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX idx_group_mappings_uq_global
	ON group_role_mappings(provider, group_ref, role_key, COALESCE(app, '*'))
	WHERE project_id IS NULL;
