# IAM Admin UI — Implementation Spec (v1, basic)

Companion to `iam-service-spec.md`. That spec already defines a **minimal admin
REST API** on the IAM Worker ("Admin surface") but leaves the UI as _optionally a small
UI_. This document specifies that UI at a basic, implementable level.

Scope: a small **SPA built on [buzola](https://github.com/.../buzola)** that drives the
existing `/admin/*` API — a handful of pages to manage principals, grants, projects,
group→role mappings, API keys and capabilities, plus an audit log viewer. Keep it boring:
table-heavy CRUD, no client-side state management beyond buzola loaders.

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
  projects/
    index.tsx              # '/projects'              — list, create, rename
  group-mappings/
    index.tsx              # '/group-mappings'        — list, create, delete
  api-keys/
    index.tsx              # '/api-keys'              — list, provision, rotate, revoke
  capabilities/
    index.tsx              # '/capabilities'          — list, issue, revoke
  audit/
    index.tsx              # '/audit'                 — domain audit_events, filterable
    auth-log.tsx           # '/audit/auth-log'        — auth_log (authenticate/redeem outcomes)
  roles.tsx                # '/roles'                 — read-only reference of code-defined roles
```

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
| `GET /admin/projects`                                                                       | list projects                                                                                                                                                |
| `GET /admin/group-mappings`                                                                 | list group→role mappings                                                                                                                                     |
| `GET /admin/roles`                                                                          | code role registry (already specified: `GET /admin/roles`)                                                                                                   |
| `GET /admin/api-keys`                                                                       | list service principals provisioned as API keys (no secrets)                                                                                                 |
| `GET /admin/capabilities`                                                                   | list capability tokens (metadata only: label, expiry, used_count, revoked_at — **never** hash/plaintext) + their `(action, resource)` grants                 |
| `GET /admin/audit?resourceType=&resourceId=&principalId=&action=&requestId=&before=&limit=` | page of `audit_events` (cursor by UUIDv7 / `created_at`)                                                                                                     |
| `GET /admin/auth-log?principalId=&requestId=&decision=&before=&limit=`                      | page of `auth_log` rows                                                                                                                                      |

Writes are the ones already in the core spec (`POST/DELETE/PATCH` for grants, projects,
group-mappings, api-keys, capabilities), namespaced under `/admin/`.

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
  - **Effective permissions** table: `action`, scope (project name or _Global_), and
    **`source`** (`grant` / `bootstrap` / `group:<org/team>`). This is the "why does this
    user have this permission?" view the core spec calls out — render `source` verbatim.
  - **Grants** table (explicit rows only): role, scope, expiry, granted_by, created_at, with
    a **Revoke** action (`DELETE` grant → `iam.grant.revoke`).
  - **Add grant** form: role picker (from `GET /roles`), **scope picker** (see three-state
    note below), optional expiry → `POST` grant (`iam.grant.create`).
  - **Disable / enable** principal (soft-disable via `disabled_at`).
  - **Dangling role flag:** if a grant's `role_key` is no longer in the code registry, show
    it highlighted as _dangling (resolves to zero permissions)_ — core spec requirement.
  - Users are lazily created on first login, or pre-created via **Invite** (above). Grant/revoke
    works the same on an `invited` principal as on an active one — grants pre-created on an
    invite take effect the moment that user first logs in (claim).

### 2. Projects (`/projects`)

- List slug, name, created_at. **Create** (`POST` → `iam.project.create`) and **rename**
  (`PATCH` → `iam.project.update`). Admin-managed only in v1; no delete in v1 (projects are
  referenced by grants/mappings — out of scope, note it).

### 3. Group → role mappings (`/group-mappings`)

- List provider (github), `group_ref`, role, scope. **Create** form: provider (github, fixed
  v1), `group_ref` input with inline hint on the **`<org>/<team>` lowercase** normalization
  (so admin input matches identity data), role picker, scope picker → `POST`
  (`iam.groupmapping.create`). **Delete** → `iam.groupmapping.delete`.
- Short copy explaining group perms are **login-time, not live** (removing a mapping takes
  effect next `authenticate()` within cache TTL; removing team membership only on Access
  session refresh) — sets admin expectations, straight from the core spec.

### 4. API keys / service tokens (`/api-keys`)

- List provisioned service principals: label, status, role/scope, expiry.
- **Provision** form: label, role, optional project scope, optional expiry → `POST
  /admin/api-keys`. On success the response carries `client_id` + **`client_secret` shown
  exactly once** → render the **once-shown secret modal** (see cross-cutting). Surface the
  Cloudflare "copy now, not retrievable later" warning. Also surface the v1 caveat from the
  core spec: whether the token was auto-added to the app's Service Auth policy or that step
  is manual.
- **Rotate** (`POST .../rotate`) → new secret, once-shown modal again.
- **Revoke** (`DELETE`) → confirmation; explains it deletes the Access token + grants
  immediately.
- If provisioning half-failed (orphaned Access token / `iam.apikey.orphaned`), show it as a
  reconciliation warning row.

### 5. Capabilities (`/capabilities`)

- List tokens: label, grants `(action, resource)`, expiry, used_count, max_uses, status
  (active / expired / revoked). **Never** show hash or plaintext.
- **Issue** form: repeatable `(action, resource)` rows, optional per-row `projectId` (used
  only for the delegation check), label, expiry, optional max_uses → `POST
  /admin/capabilities` (calls `issueCapability()` with the **admin's own forwarded
  credentials**; delegation rule applies — admins hold `*` so it passes). Response returns
  the **plaintext token once** → once-shown modal.
- **Revoke** (`DELETE`) → `iam.capability.revoke`, effective immediately.
- The issue form is intentionally raw (action/resource strings) — capability resources are an
  app-owned shared namespace (`report:`, `invoice:`…); v1 has no picker, just a hint listing
  known resource-type prefixes.

### 6. Audit log (`/audit` + `/audit/auth-log`)

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

### 7. Roles (`/roles`)

- Read-only reference of the **code-defined** roles (`GET /admin/roles`): name, description,
  permission patterns. Copy: "roles live in code, not editable here." Doubles as the legend
  for role pickers elsewhere and the place to see what `*`/`project.*` expand to.

## Cross-cutting UI behaviors

- **Once-shown secrets (API key secret, rotated secret, capability plaintext).** Returned
  once by the API and **never persisted**. Render in a blocking modal with a copy button and
  an explicit "this will not be shown again" warning. Do not put the secret/token in the URL,
  in a buzola param, or in any link. For capability tokens specifically, any view that
  renders a tokenized share URL must send **`Referrer-Policy: no-referrer`** (core spec) —
  set it on the admin UI responses, or render the token as copyable text only, never as a
  navigable anchor.
- **Three-state scope picker.** A grant / mapping is either **Global (all projects)** →
  stored `project_id = NULL`, or **scoped to one project**. The picker has an explicit
  "Global / all projects" option distinct from "pick a project" — this is the `null` vs.
  project-id distinction that the core spec treats as load-bearing. Never default silently to
  global; make the admin choose. (The read-side three-state — `null` / `[]` / non-empty from
  `scopedTo()` — is an SDK concern, not the admin UI's, but the _grant_ side must not blur
  global vs. scoped.)
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

- No runtime role editing (roles are code; `/roles` is read-only).
- No project hierarchy, resource-level ACL editor, or per-`can()` decision log viewer
  (those features are out of scope in the core spec; nothing to render).
- No project delete, no bulk operations, no CSV export, no charts/dashboards — plain tables.
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
