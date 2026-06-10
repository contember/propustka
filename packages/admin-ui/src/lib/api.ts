// Typed fetch helper for the admin JSON API.
//
// Same-origin (`/admin/...`), `credentials: 'include'`, JSON in/out. Non-2xx maps to a
// typed `ApiError`. Session-expiry handling: if a response looks like a Cloudflare Access
// login redirect (opaque, non-JSON/HTML, cross-origin 302) or a 401, we trigger a full
// `location.reload()` so Access can re-challenge — a SPA fetch can't follow the
// cross-origin Access login page.

/** A typed non-2xx API failure surfaced to pages / error boundaries. */
export class ApiError extends Error {
	readonly status: number

	constructor(status: number, message: string) {
		super(message)
		this.name = 'ApiError'
		this.status = status
	}
}

const BASE = '/admin'

/** Hard reload so Cloudflare Access re-challenges the (now expired) session. */
function reloadForAccess(): never {
	location.reload()
	// `location.reload()` doesn't actually return; throw to satisfy the type system and
	// stop any further processing while the navigation kicks in.
	throw new ApiError(401, 'Session expired — reloading to re-authenticate.')
}

function looksLikeAccessRedirect(res: Response): boolean {
	// Opaque (cross-origin redirect that we couldn't read) — the classic Access bounce.
	if (res.type === 'opaque' || res.type === 'opaqueredirect') return true
	// A 200/30x that returns HTML instead of JSON is the Access login page.
	const contentType = res.headers.get('content-type') ?? ''
	if (res.ok && !contentType.includes('application/json')) return true
	return false
}

async function readError(res: Response): Promise<ApiError> {
	let message = `Request failed (${res.status})`
	try {
		const contentType = res.headers.get('content-type') ?? ''
		if (contentType.includes('application/json')) {
			const body: unknown = await res.json()
			if (
				body !== null
				&& typeof body === 'object'
				&& 'message' in body
				&& typeof body.message === 'string'
			) {
				message = body.message
			} else if (
				body !== null
				&& typeof body === 'object'
				&& 'error' in body
				&& typeof body.error === 'string'
			) {
				message = body.error
			}
		} else {
			const text = await res.text()
			if (text.trim().length > 0 && text.length < 500) message = text
		}
	} catch {
		// Keep the default message.
	}
	return new ApiError(res.status, message)
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const headers: Record<string, string> = { accept: 'application/json' }
	if (body !== undefined) headers['content-type'] = 'application/json'

	let res: Response
	try {
		res = await fetch(`${BASE}${path}`, {
			method,
			headers,
			credentials: 'include',
			redirect: 'manual',
			body: body === undefined ? undefined : JSON.stringify(body),
		})
	} catch (cause) {
		const message = cause instanceof Error ? cause.message : 'Network request failed'
		throw new ApiError(0, message)
	}

	// 401 or an Access login bounce → hard reload to re-challenge.
	if (res.status === 401 || looksLikeAccessRedirect(res)) reloadForAccess()

	if (!res.ok) throw await readError(res)

	// Read the body as text and parse it. An empty body (204 / no content) normalizes to
	// `null` so mutation callers that ignore the result get a defined value. `JSON.parse`
	// returns `any`, so the caller's generic `T` applies at this boundary without a cast.
	const text = await res.text()
	return JSON.parse(text.trim() === '' ? 'null' : text)
}

export const api = {
	get<T>(path: string): Promise<T> {
		return request<T>('GET', path)
	},
	post<T = unknown>(path: string, body?: unknown): Promise<T> {
		return request<T>('POST', path, body ?? {})
	},
	patch<T = unknown>(path: string, body?: unknown): Promise<T> {
		return request<T>('PATCH', path, body ?? {})
	},
	del<T = unknown>(path: string): Promise<T> {
		return request<T>('DELETE', path)
	},
}
