import { IamClient } from '@propustka/client'
import type { Env } from './env'

// Minimal example app: authenticates the request through the IAM Worker over a service
// binding, then makes local `can()` / `scopedTo()` checks and emits a domain audit event.
//
// Behind Cloudflare Access this receives a real Access JWT and resolves a real principal.
// Run locally (no Access) it returns `missing_token` — which still proves the end-to-end
// app↔IAM RPC path: env.IAM.authenticate() reaches the IAM Worker over the binding and the
// structured failure comes back through it.
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const iam = new IamClient(env.IAM, 'example-app')

		const auth = await iam.authenticate(request)
		if (!auth.ok) {
			return Response.json({ authenticated: false, reason: auth.reason }, { status: auth.status })
		}

		const body = {
			authenticated: true,
			canEditDemoProject: auth.can('project.settings.update', { project: 'demo' }),
			readableProjects: auth.scopedTo('project.read'),
		}

		// Fire-and-forget domain audit — never blocks the response.
		ctx.waitUntil(auth.audit({ action: 'example.viewed', resourceType: 'example', resourceId: 'demo' }))

		return Response.json(body)
	},
}
