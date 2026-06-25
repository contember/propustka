import { PropustkaAuth } from '@propustka/client'
import type { Env } from './env'

// Minimal example app on the propustka-NATIVE auth path: instead of sitting behind Cloudflare
// Access and resolving a CF JWT over RPC on every request, it runs `PropustkaAuth` as middleware.
//
// PropustkaAuth verifies the per-app permission token LOCALLY against propustka's JWKS (no
// per-request round-trip); when there's no valid token it mints one from the browser's SSO session
// (a single `mintToken` over the binding, ≈ once per token TTL), and when there's no session at all
// it hands back a login URL to bounce the browser to propustka's Google login.
//
// (The legacy `IamClient.authenticate(request)` path — for apps still fronted by Cloudflare Access —
// still exists; an app picks whichever front door it's migrated to.)
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const auth = new PropustkaAuth(env.IAM, 'example-app', { issuer: env.PROPUSTKA_ISSUER })

		const result = await auth.authenticate(request)
		if (!result.ok) {
			// No valid session → send the browser to log in, returning here afterwards.
			return Response.redirect(result.loginUrl, 302)
		}

		// Authorization is identical to the RPC path — `can()` / `scopedTo()` over the resolved
		// permissions, here read straight from the locally-verified token's claims.
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
