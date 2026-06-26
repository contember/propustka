-- 0007_drop_group_access — remove the group → role mapping machinery.
--
-- propustka-native auth federates humans via its own OIDC session; there are no IdP groups in the
-- permission decision anymore (resolution is explicit grants ∪ bootstrap). The `group_role_mappings`
-- table, its admin surface, and the `IdentityClient`/get-identity path are gone — drop the table.
-- SQLite drops a table's indexes with it, so the three `idx_group_mappings_*` indexes go too.

DROP TABLE IF EXISTS group_role_mappings;
