// Deploy-time schema reconcile — authz-vocabulary as code.
//
// Each app OWNS its authz vocabulary (scope dimensions, action catalog, roles) and declares it
// in its own code as an `AppSchema`. At deploy time the app reconciles that declaration into
// Propustka by PUTting it to the idempotent admin endpoint `PUT /admin/apps/:app/schema`, so the
// IAM Worker's DB always mirrors what the app actually checks at runtime. An app's FIRST schema
// reconcile is also how it REGISTERS itself in propustka's app registry.
//
// This is a DEPLOY/OPERATOR helper, NOT a runtime one: it talks HTTP to the admin origin (not the
// `IAM` service binding) and authenticates with a propustka-issued `px_` ADMIN key as a bearer —
// reconcile is a privileged admin operation. Call it from a deploy step / provisioning script,
// never from request handling.
//
// Idempotent: the endpoint upserts scopes/actions/origin='app' roles and deletes app-origin rows
// absent from the body; origin='custom' policies are never touched. Re-running is safe.

import type { AppSchema } from '@propustka/core'

export interface ReconcileSchemaOptions {
	/** The IAM Worker's admin origin, e.g. `https://propustka.example.com` (trailing slash ok). */
	url: string
	/** The app id; its FIRST reconcile registers it in propustka's app registry. */
	app: string
	/** The app's declared vocabulary. */
	schema: AppSchema
	/**
	 * A propustka-issued `px_` ADMIN key, sent as `Authorization: Bearer`. Omit for a LOCAL run —
	 * the Worker's `ENVIRONMENT=local` + empty `PROPUSTKA_SIGNING_KEYS` resolves a fixed global-admin
	 * for credential-less calls.
	 */
	adminKey?: string
}

/** Thrown when the admin endpoint rejects the reconcile; `status` is the HTTP status. */
export class ReconcileSchemaError extends Error {
	constructor(message: string, readonly status: number) {
		super(message)
		this.name = 'ReconcileSchemaError'
	}
}

/** Pull a human-readable message out of the admin API's `{ error }` body, if present. */
function errorMessage(value: unknown): string | null {
	if (typeof value !== 'object' || value === null || !('error' in value)) {
		return null
	}
	const message = value.error
	return typeof message === 'string' ? message : null
}

/**
 * Reconcile one app's declared `AppSchema` into Propustka (idempotent). Resolves on success;
 * throws `ReconcileSchemaError` on a non-2xx response, or `Error` on a half-set service token.
 */
export async function reconcileSchema(options: ReconcileSchemaOptions): Promise<void> {
	const { url, app, schema, adminKey } = options

	const headers: Record<string, string> = { 'content-type': 'application/json' }
	if (adminKey !== undefined) {
		headers['authorization'] = `Bearer ${adminKey}`
	}

	// Trim a trailing slash so `${base}${path}` never doubles up.
	const base = url.replace(/\/+$/, '')
	const response = await fetch(`${base}/admin/apps/${encodeURIComponent(app)}/schema`, {
		method: 'PUT',
		headers,
		body: JSON.stringify(schema),
	})
	if (!response.ok) {
		const payload: unknown = await response.json().catch(() => null)
		const detail = errorMessage(payload) ?? response.statusText
		throw new ReconcileSchemaError(`PUT /admin/apps/${app}/schema failed (${response.status}): ${detail}`, response.status)
	}
}
