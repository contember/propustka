-- Dev-only seed data for local clicking-through (NOT a migration, never deployed).
-- Apply to the local lopata D1:  bunx lopata d1 execute propustka --file seed.dev.sql
-- Idempotent (INSERT OR IGNORE), so it's safe to re-run.

-- Principals. `local-dev-admin` is the identity the worker's ENVIRONMENT=local bypass resolves
-- to (see src/auth.ts) — seeding it makes audit/auth-log foreign keys resolve.
INSERT OR IGNORE INTO principals (id, type, external_id, email, label, disabled_at, created_at) VALUES
  ('local-dev-admin', 'user',    'local-dev-admin', 'admin@local.test', 'local-dev-admin',  NULL, unixepoch() - 86400),
  ('p-alice',         'user',    'sub-alice',       'alice@firma.cz',   'alice@firma.cz',   NULL, unixepoch() - 72000),
  ('p-bob-invited',   'user',    NULL,              'bob@firma.cz',     'bob@firma.cz',     NULL, unixepoch() - 3600),
  ('p-carol',         'user',    'sub-carol',       'carol@firma.cz',   'carol@firma.cz',   unixepoch() - 100, unixepoch() - 50000),
  ('p-svc-reports',   'service', 'svc-reports-cid', NULL,               'reports-exporter', NULL, unixepoch() - 60000);

-- Projects (the shared scope dimension).
INSERT OR IGNORE INTO projects (id, slug, name, created_at) VALUES
  ('proj-alpha', 'alpha', 'Alpha', unixepoch() - 80000),
  ('proj-beta',  'beta',  'Beta',  unixepoch() - 79000);

-- Grants. Note `p-bob-invited` gets an editor grant on Beta BEFORE first login (invite/claim).
INSERT OR IGNORE INTO grants (id, principal_id, role_key, project_id, granted_by, expires_at, created_at) VALUES
  ('grant-alice-alpha',  'p-alice',       'editor', 'proj-alpha', 'local-dev-admin', NULL, unixepoch() - 70000),
  ('grant-alice-global', 'p-alice',       'viewer', NULL,         'local-dev-admin', NULL, unixepoch() - 70000),
  ('grant-bob-beta',     'p-bob-invited', 'editor', 'proj-beta',  'local-dev-admin', NULL, unixepoch() - 3600),
  ('grant-svc-global',   'p-svc-reports', 'viewer', NULL,         'local-dev-admin', NULL, unixepoch() - 60000);

-- Group → role mappings.
INSERT OR IGNORE INTO group_role_mappings (id, provider, group_ref, role_key, project_id, created_at) VALUES
  ('gm-coredevs', 'github', 'my-org/core-devs', 'editor', 'proj-alpha', unixepoch() - 65000),
  ('gm-admins',   'github', 'my-org/admins',    'admin',  NULL,         unixepoch() - 65000);

-- A capability token (hash only; the plaintext is never stored). used_count shows telemetry.
INSERT OR IGNORE INTO capability_tokens (id, token_hash, label, issued_by, expires_at, max_uses, used_count, revoked_at, created_at) VALUES
  ('cap-q2', 'seed-sha256-q2-acme-not-a-real-hash', 'Share: report Q2 (ACME)', 'local-dev-admin', unixepoch() + 2592000, NULL, 2, NULL, unixepoch() - 40000);
INSERT OR IGNORE INTO capability_grants (token_id, action, resource) VALUES
  ('cap-q2', 'report.read',            'report:q2-acme'),
  ('cap-q2', 'report.feedback.create', 'report:q2-acme');

-- Domain audit events (TEXT ids chosen to sort by time, newest last).
INSERT OR IGNORE INTO audit_events (id, request_id, principal_id, principal_label, capability_token_id, app, action, resource_type, resource_id, diff, metadata, created_at) VALUES
  ('aud-001', 'req-seed-1', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.project.create',  'project',    'proj-alpha', NULL, '{"slug":"alpha"}', unixepoch() - 80000),
  ('aud-002', 'req-seed-2', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.project.create',  'project',    'proj-beta',  NULL, '{"slug":"beta"}',  unixepoch() - 79000),
  ('aud-003', 'req-seed-3', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.grant.create',    'grant',      'grant-alice-alpha', NULL, '{"role":"editor","project":"alpha"}', unixepoch() - 70000),
  ('aud-004', 'req-seed-4', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.principal.invite','principal',  'p-bob-invited', NULL, '{"email":"bob@firma.cz"}', unixepoch() - 3600),
  ('aud-005', 'req-seed-5', 'local-dev-admin', 'local-dev-admin', NULL, 'iam-admin', 'iam.capability.create','capability','cap-q2', NULL, '{"label":"Share: report Q2 (ACME)"}', unixepoch() - 40000),
  ('aud-006', 'req-seed-6', 'p-alice', 'alice@firma.cz', NULL, 'app-projects', 'project.settings.update', 'project', 'proj-alpha', '{"name":["Alpha","Alpha (renamed)"]}', NULL, unixepoch() - 1000);

-- Auth log (rowid PK — omit id).
INSERT OR IGNORE INTO auth_log (request_id, app, kind, principal_id, capability_token_id, decision, reason, created_at) VALUES
  ('req-seed-6', 'app-projects', 'authenticate', 'p-alice', NULL, 'allow', NULL, unixepoch() - 1000),
  ('req-seed-7', 'app-projects', 'authenticate', NULL, NULL, 'deny', 'unknown_principal', unixepoch() - 900),
  ('req-seed-8', 'reports', 'redeem', NULL, 'cap-q2', 'allow', NULL, unixepoch() - 800);
