# Example app — consuming Propustka over a service binding

A minimal app Worker that uses **`@propustka/client`** to authenticate a request through the
IAM Worker via a service binding (`oblaka` `ServiceReference('propustka-worker')`), then does
local `can()` / `scopedTo()` checks and emits a fire-and-forget audit event. See
[`src/index.ts`](./src/index.ts).

In a real app you would add only the `IAM` binding to your existing Worker; here it is a whole
tiny Worker so the example runs standalone.

## Run it locally (multi-worker lopata)

```bash
# from the repo root: build the admin assets the IAM worker serves, then generate both configs
cd packages/worker && bun run oblaka
cd ../../examples/app && bun run oblaka

# run the example as the main worker with the IAM Worker wired in as an auxiliary worker
bun run dev          # lopata on http://127.0.0.1:18190

curl http://127.0.0.1:18190/
```

Expected output (no Cloudflare Access in front locally → no Access JWT on the request):

```
HTTP 401
{"authenticated":false,"reason":"missing_token"}
```

That response **is** the end-to-end proof: `env.IAM.authenticate()` reached the IAM Worker
over the in-process service binding (`Wired service binding: IAM -> propustka-worker` in the
lopata log) and the structured failure came back through it. Behind real Access, the same call
returns a resolved principal and `can()` / `scopedTo()` reflect their grants.

## Note: the harmless `auth_log` error

In this standalone setup the auxiliary IAM Worker's local D1 is a fresh, unmigrated database
(the example dir has its own `.lopata/`), so the fire-and-forget `auth_log` write fails with
`no such table: auth_log` in the logs. **This does not affect the response** — which is exactly
the point of audit hard-requirement #6 (audit/auth writes use `waitUntil` and must never fail
or delay the user-facing operation). To silence it, apply the worker's migrations to the D1
this lopata instance uses, or run the IAM Worker standalone (`packages/worker`, where the D1 is
migrated) and point an app at it.
