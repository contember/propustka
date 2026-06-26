import { PropustkaAuth } from '@propustka/client'
import { exampleGates } from '../propustka.gates'
import type { Env } from './env'

// Minimal example app on the propustka-NATIVE auth path. `PropustkaAuth` is the whole front door:
// it enforces the per-path gates (`propustka.gates.ts`) in-process — there is no Cloudflare Access
// edge — then resolves the matched credential, verifying the per-app permission token LOCALLY
// against propustka's JWKS (no per-request round-trip). A human with no session is handed a login
// URL to bounce to propustka's OIDC login; a `public` path needs no credential at all.
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const auth = new PropustkaAuth(env.IAM, 'example-app', { issuer: env.PROPUSTKA_ISSUER, gates: exampleGates })

		const result = await auth.authenticate(request)
		if (!result.ok) {
			// A human-gated miss carries a login URL (bounce the browser); anything else is a flat status.
			if (result.loginUrl !== undefined) {
				return Response.redirect(result.loginUrl, 302)
			}
			return new Response(result.reason, { status: result.status })
		}

		// Authorization is identical everywhere — `can()` / `scopedTo()` over the resolved permissions,
		// here read straight from the locally-verified token's claims. A `public` request is anonymous
		// (`principal: null`, empty perms), so `can()` is always false there.
		const body = {
			authenticated: true,
			principal: result.context.principal,
			canEditDemoProject: result.context.can('example.settings.update', { type: 'project', value: 'demo' }),
			readableProjects: result.context.scopedTo('example.read', 'project'),
		}

		// Fire-and-forget domain audit — never blocks the response.
		ctx.waitUntil(result.context.audit({ action: 'example.view', resourceType: 'example', resourceId: 'demo' }))

		const response = Response.json(body)
		// When the token was just (re)minted, persist it so the next request hits the local fast path.
		if (result.setCookie) {
			response.headers.append('Set-Cookie', result.setCookie)
		}
		return response
	},
}
