# IAM Admin UI — Implementation Spec (v1, basic)

Companion to `iam-service-spec.md`. That spec already defines a **minimal admin
REST API** on the IAM Worker ("Admin surface") but leaves the UI as _optionally a small
UI_. This document specifies that UI at a basic, implementable level.

Scope: a small **SPA built on [buzola](https://github.com/.../buzola)** that drives the
existing `/admin/*` API — a handful of pages to manage principals, grants, custom policies,
group→role mappings, API keys and capabilities, inspect each app's reconciled schema and role
catalog, plus an audit log viewer. Keep it boring: table-heavy CRUD, no client-side state
management beyond buzola loaders.

This is an **internal admin tool for tens of users** — do not over-engineer (mirrors the
core spec's stance).

## Where it lives & how it authenticates

- **Served by the IAM Worker itself**, as static assets (Workers static assets / Assets
  binding). **The SPA is served at the Worker root `/`** (buzola routes `/principals`,
  `/audit`, …); the **JSON API stays at `/admin/*`** — the core spec's endpoint paths
  verbatim (`POST /admin/api-keys`, `GET /admin/roles`, …). No collision: the Worker's
  `fetch()` routes any `/admin/*` request to the JSON handlers and everything else falls
  through to the SPA assets (`run_worker_first` + SPA `not_found_handling`, see
  `architecture.md`). One Worker, one origin — SPA and API are same-origin so the browser
  attaches the Access cookie automatically.
- **Behind Cloudflare Access with an admin-only policy** (edge gate), exactly as the core
  spec states for the admin surface.
- **Defense in depth, enforced in-Worker:** every `/admin/*` handler resolves the
  caller via the same `authenticate()` path (forwarded Access JWT + `CF_Authorization`
  cookie) and requires the resolved principal to hold a global admin permission —
  `can('iam.admin')` (a **pinned sentinel action**: no `iam.*` role is defined, so only the
  `admin` role's `*` wildcard and bootstrap admins satisfy it; `editor`/`viewer` do not).
  Not-admin → `403`. The Access policy is the gate; this is the belt-and-suspenders so a
  misconfigured policy can't expose admin writes.
- **Bootstrap admins reach the UI too** — they resolve to global `admin` via
  `IAM_BOOTSTRAP_ADMINS` (core spec), so the very first admin can open the UI and create the
  first real grants before any grant rows exist.
- **All audit-on-write stays server-side.** The UI never writes `audit_events`; the
  existing `/admin/*` handlers already emit `iam.grant.create`, `iam.apikey.create`, etc.
  The UI just calls them.

## Tech & project shape

- **buzola SPA** (React, `@buzola/router` + codegen plugin). Vite or Bun adapter — match
  whatever the IAM Worker build uses; default Vite.
- Lives in its own package, **`packages/admin-ui`** (decided — see `architecture.md`), built
  to static assets the Worker serves.
- **Data fetching = buzola loaders** (decided; react-query was the opice precedent but is
  redundant over buzola's own loader cache for an admin this small). A page `loader` does
  `fetch('/admin/...')` and returns JSON; the component renders `data`; mutations are plain
  `fetch` (POST/PATCH/DELETE) followed by `invalidate()` (via `useInvalidate`). buzola's
  loader cache (stale-while-revalidate) is enough at this scale; no extra data lib. Types come
  from the Worker's admin-API DTOs imported **type-only** (the opice pattern — `import type`
  from the worker, end-to-end typed, no codegen).
- A tiny typed `api()` helper wraps `fetch` (base path, JSON, error mapping) so pages don't
  repeat boilerplate. It surfaces `401`/`403`/network as typed errors the buzola
  `ErrorBoundary` / page error handler renders.
- **Session-expiry handling:** if a same-origin `/admin/*` fetch comes back as an Access
  login redirect (opaque/HTML instead of JSON, or a 302 to the team domain), the `api()`
  helper triggers a full `location.reload()` so Access re-challenges. SPA fetch can't follow
  the cross-origin Access login; a hard reload is the simplest correct recovery.

### Route tree (buzola conventions)

```
src/routes/
  _layout.tsx              # app shell: sidebar nav + <Outlet/>; loader fetches "who am I"
  _404.tsx
  index.tsx                # route '/', redirects to 'principals'
  principals/
    index.tsx              # '/principals'            — list users + service principals
    detail.tsx             # '/principals/:id'        — effective perms + grants; grant/revoke; disable
  group-mappings/
    index.tsx              # '/group-mappings'        — list, create, delete
  api-keys/
    index.tsx              # '/api-keys'              — list, provision, rotate, revoke
  capabilities/
    index.tsx              # '/capabilities'          — list, issue, revoke
  audit/
    index.tsx              # '/audit'                 — domain audit_events, filterable
    auth-log.tsx           # '/audit/auth-log'        — auth_log (authenticate/redeem outcomes)
  policies/
    index.tsx              # '/policies?app='         — custom policies (origin=custom) per app: create/edit/delete
  roles.tsx                # '/roles?app='            — read-only reference of grantable roles (built-in + app + custom)
  schema/
    index.tsx              # '/schema?app='           — read-only view of an app's reconciled vocabulary
```

Several pages (`policies`, `roles`, `schema`) are **per-app**: they take a `?app=` query param
(an `ACCESS_APPS` value) and render that app's scopes / actions / roles. The picker for grants,
mappings and API keys also derives its role / scope / action choices from the chosen app.

`_layout.tsx` renders the persistent nav and an `<Outlet/>`; its loader hits
`GET /admin/me` to show the current admin's label and gate-fail early with a clear
"you are not an IAM admin" screen if `403`.

## Admin API additions needed (reads)

The core spec enumerates the **write/CRUD** endpoints (they emit audit events). The SPA also
needs **read** endpoints; add these GETs (read-only, same admin gate, no audit event):

| Method & path                                                                               | Returns                                                                                                                                                      |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /admin/me`                                                                             | current admin principal + resolved permissions (for nav + gate)                                                                                              |
| `GET /admin/principals?type=&status=&q=`                                                    | list principals (filter by type, status invited/active/disabled, search label/email/external_id)                                                             |
| `GET /admin/principals/{id}`                                                                | principal (incl. status, email, external_id) + its grants + **effective permissions with `source`** (grant / bootstrap / `group:<org/team>`) + `disabled_at` |
| `GET /admin/apps`                                                                           | configured app ids (the `ACCESS_APPS` values) — the source for every per-app picker                                                                          |
| `GET /admin/apps/{app}/schema`                                                              | an app's reconciled vocabulary: scope dimensions, action catalog, origin=`app` roles                                                                         |
| `GET /admin/apps/{app}/policies`                                                            | an app's admin-composed custom policies (origin=`custom` roles)                                                                                              |
| `GET /admin/group-mappings`                                                                 | list group→role mappings                                                                                                                                     |
| `GET /admin/roles?app=`                                                                     | roles grantable for `app`: built-in (cross-app) + the app's app/custom roles, each with `origin`                                                             |
| `GET /admin/api-keys`                                                                       | list service principals provisioned as API keys (no secrets)                                                                                                 |
| `GET /admin/capabilities`                                                                   | list capability tokens (metadata only: label, expiry, used_count, revoked_at — **never** hash/plaintext) + their `(action, resource)` grants                 |
| `GET /admin/audit?resourceType=&resourceId=&principalId=&action=&requestId=&before=&limit=` | page of `audit_events` (cursor by UUIDv7 / `created_at`)                                                                                                     |
| `GET /admin/auth-log?principalId=&requestId=&decision=&before=&limit=`                      | page of `auth_log` rows                                                                                                                                      |

Writes (namespaced under `/admin/`): `POST/DELETE` grants, group-mappings, capabilities;
`POST/.../rotate/DELETE` api-keys; `PATCH/DELETE` principals; **`PUT /admin/apps/{app}/schema`**
(reconcile an app's declared vocabulary — normally driven by `scripts/provision-schemas.ts`, not
the UI); and **`POST/PUT/DELETE /admin/apps/{app}/policies[/{key}]`** (manage custom policies).
There is no `projects` resource — Propustka no longer owns a project list (scope values are
app-owned, see the scope picker below).

Pagination: keep it simple — `limit` + a `before` cursor (audit ids are time-sortable
UUIDv7; auth_log is rowid). No total counts.

## Pages

### 1. Principals (`/principals`)

- **List:** table of principals — type (user/service) badge, label, external_id, status
  (**invited** / active / disabled), created_at. Filter by type; text search. Service
  principals link to the API-keys view where relevant.
- **Invite user** (`POST /admin/principals` with `{ email }` → `iam.principal.invite`):
  pre-creates an _invited_ user principal (no `sub` yet) so an admin can grant **before the
  person's first login**; the form optionally adds a grant in the same flow. Invited rows show
  an `invited` badge until the user's first `authenticate()` claims them (binds their Access
  `sub`). For team-wide pre-authorization use group→role mappings instead.
- **Detail (`/principals/:id`):** the core authorization screen.
  - **Effective permissions** table: `action`, scope (rendered as `type:value`, or _Global_ for
    a scope-less entry), and **`source`** (`grant` / `bootstrap` / `group:<org/team>`). This is
    the "why does this user have this permission?" view the core spec calls out — render
    `source` verbatim.
  - **Grants** table (explicit rows only): role **or** inline action set, app (or _All apps_),
    scope, expiry, granted_by, created_at, with a **Revoke** action (`DELETE` grant →
    `iam.grant.revoke`). A role grant shows the `role_key`; an inline grant shows its action
    chips.
  - **Add grant** form (the shared **grant composer**): pick an **app** (one app, or _All apps_
    = cross-app, `app = null`); then **EITHER a named role/policy OR an inline action set** —
    exactly one (the role picker lists the app's built-in/app/custom roles; the action picker
    multi-selects from the app's action catalog, and is only available for a concrete app);
    then a **scope** (generic dimension + opaque value, or Global — see the scope-picker note
    below); optional expiry → `POST` grant (`iam.grant.create`). The role list, scope
    dimensions and action catalog all derive from the chosen app's reconciled schema.
  - **Disable / enable** principal (soft-disable via `disabled_at`).
  - **Dangling role flag:** if a grant's `role_key` no longer resolves to a known role (built-in
    or one of the app's `roles` rows), show it highlighted as _dangling (resolves to zero
    permissions)_ — core spec requirement.
  - Users are lazily created on first login, or pre-created via **Invite** (above). Grant/revoke
    works the same on an `invited` principal as on an active one — grants pre-created on an
    invite take effect the moment that user first logs in (claim).

### 2. Group → role mappings (`/group-mappings`)

- List provider (github), `group_ref`, role, app, scope. **Create** form: provider (github,
  fixed v1), `group_ref` input with inline hint on the **`<org>/<team>` lowercase**
  normalization (so admin input matches identity data), **app picker** (one app or _All apps_),
  **role picker** (the app's roles — a mapping is **role-only**, no inline action set), **scope
  picker** (generic dimension + value, from the app's schema) → `POST`
  (`iam.groupmapping.create`). **Delete** → `iam.groupmapping.delete`.
- Short copy explaining group perms are **login-time, not live** (removing a mapping takes
  effect next `authenticate()` within cache TTL; removing team membership only on Access
  session refresh) — sets admin expectations, straight from the core spec.

### 3. API keys / service tokens (`/api-keys`)

- List provisioned service principals: label, status, app, role/inline-actions, scope, expiry.
- **Provision** form: label + the shared **grant composer** (app, role-or-inline, scope —
  same as Add grant) + optional expiry → `POST /admin/api-keys`. On success the response
  carries `client_id` + **`client_secret` shown exactly once** → render the **once-shown secret
  modal** (see cross-cutting). Surface the Cloudflare "copy now, not retrievable later"
  warning. Also surface the v1 caveat from the core spec: whether the token was auto-added to
  the app's Service Auth policy or that step is manual.
- **Rotate** (`POST .../rotate`) → new secret, once-shown modal again.
- **Revoke** (`DELETE`) → confirmation; explains it deletes the Access token + grants
  immediately.
- If provisioning half-failed (orphaned Access token / `iam.apikey.orphaned`), show it as a
  reconciliation warning row.

### 4. Capabilities (`/capabilities`)

- List tokens: label, grants `(action, resource)`, expiry, used_count, max_uses, status
  (active / expired / revoked). **Never** show hash or plaintext.
- **Issue** form: repeatable `(action, resource)` rows, each with an optional per-row
  **scope** (`type` + `value`, both-or-neither — the generic dimension/value pair, used only
  for the delegation check, not stored), label, expiry, optional max_uses → `POST
  /admin/capabilities` (calls `issueCapability()` with the **admin's own forwarded
  credentials**; delegation rule applies — admins hold `*` so it passes). Response returns
  the **plaintext token once** → once-shown modal.
- **Revoke** (`DELETE`) → `iam.capability.revoke`, effective immediately.
- The issue form is intentionally raw (action/resource strings) — capability resources are an
  app-owned shared namespace (`report:`, `invoice:`…); v1 has no picker, just a hint listing
  known resource-type prefixes.

### 5. Audit log (`/audit` + `/audit/auth-log`)

- **`/audit` — domain events (`audit_events`):** table of created_at, actor
  (`principal_label`, or _capability_ + `capability_token_id`), `app`, `action`,
  `resource_type`/`resource_id`, with an **expandable `diff`/`metadata`** (rendered as
  read-only JSON). Filters: resource type+id, principal, action, request_id, time range.
  `request_id` is a link that pivots to all rows (audit + auth) for that request.
- **`/audit/auth-log` — auth outcomes (`auth_log`):** created_at, app, kind
  (authenticate/redeem), principal (or capability token id), decision (allow/deny), reason.
  Filters: principal, request_id, decision. This is where you debug "login looks broken" —
  e.g. `reason = 'aud_not_configured'` (forgotten onboarding) or a `groups_unavailable`
  note.
- Read-only. Retention is server-side (auth_log pruned after weeks; audit kept long) — the UI
  just reflects what's there.

### 6. Policies (`/policies?app=`)

- **Admin-composed custom policies** (origin=`custom` roles) for one app — named, reusable
  permission sets the admin builds from the app's action catalog, grantable like any role.
  Requires picking a concrete app (policies are per-app; never cross-app).
- **List** (`GET /admin/apps/{app}/policies`): key, name, permission chips, created_at.
- **Create** form: key, name, optional description, and an **action picker** multi-selecting
  from the app's action catalog (`GET /admin/apps/{app}/schema` → `actions`) → `POST
  /admin/apps/{app}/policies` (`iam.policy.create`). A key that collides with a built-in role
  or an existing role is rejected (surface the API error inline).
- **Edit** (inline) → `PUT .../policies/{key}` (`iam.policy.update`); **Delete** → `DELETE`
  (`iam.policy.delete`), with a confirm noting that existing grants referencing it become
  dangling. The endpoints refuse to touch origin=`app` (reconciled) roles — only custom
  policies are editable here.
- This is the AWS-IAM "managed policy" surface: the app ships canonical origin=`app` roles via
  reconcile; admins layer origin=`custom` policies on top here, and reconcile never disturbs them.

### 7. Roles (`/roles?app=`)

- Read-only reference of the **roles grantable for an app** (`GET /admin/roles?app=…`): name,
  `origin` badge (built-in / app / custom), description, permission patterns. With no app
  chosen, only the cross-app built-ins (e.g. `admin`) show. Doubles as the legend for the role
  pickers elsewhere and the place to see what `*` / `prefix.*` expand to. Roles are not edited
  here — app roles are declared in app code and reconciled; custom policies are managed on the
  Policies page.

### 8. App schema (`/schema?app=`)

- Read-only view of an app's **reconciled vocabulary** (`GET /admin/apps/{app}/schema`),
  declared in the app's code and pushed via `PUT /admin/apps/{app}/schema` (normally by
  `scripts/provision-schemas.ts`) — not editable here. Three tables for the chosen app:
  - **Scope dimensions** (`app_scopes`): `type` + optional `label` — the dimensions the scope
    picker offers for this app.
  - **Action catalog** (`app_actions`): `action` + description — what inline grants and policies
    validate against.
  - **App roles** (origin=`app`): key, name, permission patterns — the canonical bundles the
    app ships (custom policies live on the Policies page).

## Cross-cutting UI behaviors

- **Once-shown secrets (API key secret, rotated secret, capability plaintext).** Returned
  once by the API and **never persisted**. Render in a blocking modal with a copy button and
  an explicit "this will not be shown again" warning. Do not put the secret/token in the URL,
  in a buzola param, or in any link. For capability tokens specifically, any view that
  renders a tokenized share URL must send **`Referrer-Policy: no-referrer`** (core spec) —
  set it on the admin UI responses, or render the token as copyable text only, never as a
  navigable anchor.
- **Generic scope picker (two explicit states).** A grant / mapping is either **Global (all
  scopes)** → stored `scope_type = scope_value = NULL`, or **scoped to one flat dimension** →
  a `scope_type` (a dimension from the chosen app's `app_scopes`, picked from a dropdown) plus a
  free-text `scope_value`. **Scope values are opaque, app-owned strings** — Propustka never
  validates or enumerates them, so the value is a plain text box, not a list (the old
  Propustka-owned project list is gone). The picker has an explicit "Global / all scopes" option
  distinct from "Scoped to a dimension" — the `null` vs. `(type, value)` distinction the core
  spec treats as load-bearing. Never default silently to global; make the admin choose. (The
  read-side three-state — `null` / `[]` / non-empty from `scopedTo(action, dimension)` — is an
  SDK concern, not the admin UI's, but the _grant_ side must not blur global vs. scoped.)
- **App picker (two explicit states).** Mirroring the scope picker, a grant / mapping / API key
  is either **scoped to one app** or **All apps (cross-app**, `app = null`, e.g. a super-admin).
  Defaults to unset so the admin chooses deliberately. The chosen app drives the role list,
  scope dimensions and action catalog (loaded from that app's schema).
- **Role-vs-inline grant choice.** A grant / API key carries **exactly one** of a named
  role/policy (`role_key`) or an inline action set (`permissions`). The composer offers a
  radio between "Named role / policy" (role picker) and "Inline actions" (action picker over the
  app's catalog); inline is only available for a concrete app (a cross-app inline set has no
  catalog to validate against). Group mappings are role-only — no inline option. The API rejects
  an unknown role or an action pattern outside the app's catalog; surface that inline.
- **Confirm destructive actions** (revoke grant / API key / capability, disable principal)
  with a small confirm dialog naming the target. These are the most audit-sensitive
  operations.
- **Error surfaces.** `401`/Access-redirect → hard reload (above). `403` on a write → inline
  "not allowed" (shouldn't normally happen for an admin, but surfaces a delegation/permission
  gap). Validation errors from the API (e.g. unknown `role_key` rejected at creation, bad
  `group_ref`) render against the offending field.
- **No client-side permission logic.** The UI is dumb about authorization — it shows what the
  API returns and lets the API reject. The only client gate is the nav-level "are you an
  admin" check from `GET /me`, purely for UX (the server re-checks every call).

## Out of scope (v1)

- No editing of an app's reconciled vocabulary (scopes / actions / origin=`app` roles are
  declared in app code and pushed via `PUT .../schema` by the operator script; `/schema` and
  `/roles` are read-only). Admins **can** compose origin=`custom` policies on `/policies` — that
  is the one runtime-editable role surface.
- No scope-dimension hierarchy/containment (dimensions are flat & independent), no
  resource-level ACL editor, or per-`can()` decision log viewer (out of scope in the core spec;
  nothing to render).
- No project management page — Propustka no longer owns a project list (scope values are
  app-owned). No bulk operations, no CSV export, no charts/dashboards — plain tables.
- No theming/branding beyond a clean default. **UI is minimal hand-rolled** (decided): plain
  HTML + a little CSS, boring tables — no component kit / design system in v1.
- No offline / optimistic UI — every mutation refetches via `invalidate()`.

## Resolved decisions

All prior open questions are now decided:

1. **Package layout:** separate **`packages/admin-ui`** built to static assets the Worker
   serves (see `architecture.md`).
2. **URL scheme:** **SPA at root `/`**, JSON at **`/admin/*`** (core-spec paths verbatim) — no
   collision, no endpoint renaming.
3. **Data layer:** **buzola loaders** (no react-query).
4. **Component kit:** **minimal hand-rolled** (plain HTML + a little CSS), no design system.
5. **Capability issue form:** **raw `(action, resource)` inputs** for v1, with a hint listing
   known resource-type prefixes — no curated picker yet.
6. **Admin gate:** in-Worker `can('iam.admin')` sentinel, on top of the Access admin policy.

```
```
