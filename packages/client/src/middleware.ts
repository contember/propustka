/**
 * The SHARED middleware contract — structurally identical to the one a server framework (trasa) is
 * built against in parallel, so the functions `createIam(...)` produces drop straight into trasa's
 * pipeline. There is NO import from trasa: a `Middleware<Ctx>` here is just a function of this exact
 * shape, and trasa accepts any function of this shape.
 *
 * A middleware runs in order; it may:
 *   - mutate `ctx` (e.g. set `ctx.auth`),
 *   - short-circuit by returning a Response WITHOUT calling `next()`,
 *   - or wrap `next()` — await it, then append headers (e.g. a `Set-Cookie`) to the returned Response.
 */

import type { AuthContext } from './types'

/**
 * A request-pipeline middleware over a caller-owned context `Ctx`. Runs in registration order. Return
 * a Response without awaiting `next()` to short-circuit; await `next()` and return its (possibly
 * header-augmented) Response to continue.
 */
export type Middleware<Ctx> = (request: Request, ctx: Ctx, next: () => Promise<Response>) => Promise<Response>

/**
 * The minimal shape an auth middleware needs of the pipeline context: a writable `auth` slot it sets to
 * the resolved `AuthContext` (or leaves null/undefined for an unresolved/anonymous caller). The
 * caller's real context may carry far more — this is only what the auth middlewares touch.
 */
export interface AuthCarrier {
	auth?: AuthContext | null
}
