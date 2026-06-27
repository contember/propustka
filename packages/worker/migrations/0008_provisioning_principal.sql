-- The SEEDED PROVISIONING identity. `resolveCaller` (src/auth.ts) resolves a bearer matching the
-- PROPUSTKA_PROVISIONING_KEY secret to a synthetic global-admin with this id — the machine analog of
-- the IAM_BOOTSTRAP_ADMINS email bootstrap, used to bring up a control plane (e.g. vozka) before any
-- DB-backed admin credential exists. Seed a stable `service` principal so the audit that key drives
-- (iam.app.schema.reconcile, issued_by on issueKey, …) resolves its principal_id FK. The prod-applied
-- analog of the dev admin's seed.dev.sql row. Idempotent (INSERT OR IGNORE) — safe to re-run.
INSERT OR IGNORE INTO principals (id, type, external_id, email, label, disabled_at, created_at) VALUES
  ('provisioning-admin', 'service', NULL, NULL, 'provisioning', NULL, unixepoch());
