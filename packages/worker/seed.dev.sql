-- Dev-only seed data for local clicking-through (NOT a migration, never deployed).
-- Apply to the local lopata D1:  bunx lopata d1 execute propustka --file seed.dev.sql
-- Idempotent (INSERT OR IGNORE), so it's safe to re-run.
--
-- Models the generic-scopes world (migration 0003): two sample apps declare their
-- own vocabulary, and grants exercise role-based, global, and inline shapes.

-- ── App vocabulary (normally reconciled from each app's declared schema) ──────

-- opice scopes by organization/team; poplach scopes by project. The admin UI reads
-- app_scopes to offer real scope-type dropdowns per app.
INSERT OR IGNORE INTO app_scopes (app, scope_type, label) VALUES
  ('opice',   'organization', 'Organization'),
  ('opice',   'team',         'Team'),
  ('poplach', 'project',      'Project');

-- Action catalogs. Inline grants and role permissions reference these strings.
INSERT OR IGNORE INTO app_actions (app, action, description) VALUES
  ('opice',   'project.read',            'Read project data'),
  ('opice',   'project.settings.update', 'Update project settings'),
  ('opice',   'report.read',             'Read reports'),
  ('opice',   'report.export',           'Export reports'),
  ('poplach', 'project.read',            'Read project data'),
  ('poplach', 'report.read',             'Read reports'),
  ('poplach', 'report.export',           'Export reports');

-- Roles. origin='app' are the canonical bundles the app ships; origin='custom' is an
-- admin-composed policy. permissions is a JSON array of action patterns ('*' globs ok).
INSERT OR IGNORE INTO roles (app, role_key, name, description, permissions, origin, created_at) VALUES
  ('opice',   'editor', 'Editor', 'Read + manage settings',  '["project.read","project.settings.update","report.read"]', 'app',    unixepoch() - 90000),
  ('opice',   'viewer', 'Viewer', 'Read-only access',        '["project.read","report.read"]',                          'app',    unixepoch() - 90000),
  ('poplach', 'editor', 'Editor', 'Read + export reports',   '["project.read","report.read","report.export"]',          'app',    unixepoch() - 90000),
  ('poplach', 'viewer', 'Viewer', 'Read-only access',        '["project.read","report.read"]',                          'app',    unixepoch() - 90000),
  -- One admin-composed custom policy: exporters can read everything and export reports.
  ('opice',   'report-exporter', 'Report Exporter', 'Read all + export reports', '["project.read","report.*"]',        'custom', unixepoch() - 50000);

-- ── Principals ───────────────────────────────────────────────────────────────
-- `local-dev-admin` is the identity the worker's ENVIRONMENT=local bypass resolves
-- to (see src/auth.ts) — seeding it makes audit/auth-log foreign keys resolve.
INSERT OR IGNORE INTO principals (id, type, external_id, email, label, disabled_at, created_at) VALUES
  ('local-dev-admin', 'user',    'local-dev-admin', 'admin@local.test', 'local-dev-admin',  NULL, unixepoch() - 86400),
  ('p-alice',         'user',    'sub-alice',       'alice@firma.cz',   'alice@firma.cz',   NULL, unixepoch() - 72000),
  ('p-bob-invited',   'user',    NULL,              'bob@firma.cz',     'bob@firma.cz',     NULL, unixepoch() - 3600),
  ('p-carol',         'user',    'sub-carol',       'carol@firma.cz',   'carol@firma.cz',   unixepoch() - 100, unixepoch() - 50000),
  ('p-svc-reports',   'service', NULL,              NULL,               'reports-exporter', NULL, unixepoch() - 60000);

-- ── Grants ───────────────────────────────────────────────────────────────────
-- Scope values (scope_value) are OPAQUE app-owned ids — Propustka never interprets
-- them. Demonstrates the new shapes:
--   * role-based + scoped  — editor on organization=acme in opice
--   * role-based + global  — viewer everywhere in opice (scope NULL)
--   * inline               — ad-hoc permissions JSON, no role_key (note app + scope set)
-- Note `p-bob-invited` gets a grant BEFORE first login (invite/claim flow).
INSERT OR IGNORE INTO grants (id, principal_id, app, role_key, permissions, scope_type, scope_value, granted_by, expires_at, created_at) VALUES
  ('grant-alice-org',    'p-alice',       'opice',   'editor', NULL,                                  'organization', 'acme', 'local-dev-admin', NULL, unixepoch() - 70000),
  ('grant-alice-global', 'p-alice',       'opice',   'viewer', NULL,                                  NULL,           NULL,   'local-dev-admin', NULL, unixepoch() - 70000),
  ('grant-bob-project',  'p-bob-invited', 'poplach', 'editor', NULL,                                  'project',      'p-42', 'local-dev-admin', NULL, unixepoch() - 3600),
  -- Inline grant: a one-off permission set with no named role (XOR — role_key NULL).
  ('grant-svc-inline',   'p-svc-reports', 'poplach', NULL,     '["report.read","report.export"]',     'project',      'p-42', 'local-dev-admin', NULL, unixepoch() - 60000),
  -- Cross-app super-admin style global grant (app NULL = all apps).
  ('grant-admin-all',    'local-dev-admin', NULL,    'editor', NULL,                                  NULL,           NULL,   'local-dev-admin', NULL, unixepoch() - 86000);

-- ── Share link = anonymous credential (principal_id NULL; hash only, plaintext never stored). ─
INSERT OR IGNORE INTO credentials (id, token_hash, label, principal_id, issued_by, expires_at, revoked_at, created_at) VALUES
  ('cred-q2', 'seed-sha256-q2-acme-not-a-real-hash', 'Share: report Q2 (ACME)', NULL, 'local-dev-admin', unixepoch() + 2592000, NULL, unixepoch() - 40000);
-- Frozen inline grants, matched by permits() (action + scope), not an exact resource.
INSERT OR IGNORE INTO credential_grants (credential_id, action, scope_type, scope_value) VALUES
  ('cred-q2', 'report.read',            'report', 'q2-acme'),
  ('cred-q2', 'report.feedback.create', 'report', 'q2-acme');

-- ── Domain audit events (TEXT ids chosen to sort by time, newest last) ───────
INSERT OR IGNORE INTO audit_events (id, request_id, principal_id, principal_label, credential_id, app, action, resource_type, resource_id, diff, metadata, created_at) VALUES
  ('aud-001', 'req-seed-1', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.grant.create',     'grant',     'grant-alice-org',   NULL, '{"role":"editor","scope":"organization=acme"}', unixepoch() - 70000),
  ('aud-002', 'req-seed-2', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.role.create',      'role',      'opice/report-exporter', NULL, '{"origin":"custom"}', unixepoch() - 50000),
  ('aud-003', 'req-seed-3', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.principal.invite', 'principal', 'p-bob-invited',     NULL, '{"email":"bob@firma.cz"}', unixepoch() - 3600),
  ('aud-004', 'req-seed-4', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.credential.create','credential','cred-q2',           NULL, '{"label":"Share: report Q2 (ACME)"}', unixepoch() - 40000),
  ('aud-005', 'req-seed-5', 'p-alice', 'alice@firma.cz', NULL, 'opice', 'project.settings.update', 'project', 'acme', '{"name":["Acme","Acme (renamed)"]}', NULL, unixepoch() - 1000);

-- ── Auth log (rowid PK — omit id) ────────────────────────────────────────────
INSERT OR IGNORE INTO auth_log (request_id, app, kind, principal_id, credential_id, decision, reason, created_at) VALUES
  ('req-seed-5', 'opice',   'authenticate', 'p-alice', NULL, 'allow', NULL, unixepoch() - 1000),
  ('req-seed-6', 'opice',   'authenticate', NULL, NULL, 'deny', 'unknown_principal', unixepoch() - 900),
  ('req-seed-7', 'poplach', 'authenticate', NULL, 'cred-q2', 'allow', 'mint_key', unixepoch() - 800);
