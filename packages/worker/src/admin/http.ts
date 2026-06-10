/** JSON response helper for the admin API. */
export function json(body: unknown, init?: ResponseInit): Response {
	return new Response(JSON.stringify(body), {
		...init,
		headers: { 'content-type': 'application/json; charset=utf-8', ...init?.headers },
	})
}

/** A structured JSON error with an HTTP status. */
export function error(status: number, message: string): Response {
	return json({ error: message }, { status })
}

/**
 * Parse a JSON request body as `unknown` (undefined on parse failure). Callers
 * narrow fields with the readers in `../json` — no `as` casts on untrusted input.
 */
export async function readJson(request: Request): Promise<unknown> {
	try {
		return await request.json()
	} catch {
		return undefined
	}
}
