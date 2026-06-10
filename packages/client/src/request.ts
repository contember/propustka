// Reading the forwarded Access credentials off the incoming Request. Mirrors the
// extraction the IAM Worker's admin router does, so both sides agree on exactly which
// header/cookie carries what. None of this is a security boundary — it's plumbing that
// hands the verified-at-the-edge token to the IAM Worker, which validates it.

/** Cloudflare Access injects the app token as this header on every request behind Access. */
const ACCESS_TOKEN_HEADER = 'Cf-Access-Jwt-Assertion'
/** The browser carries the Access session as this cookie; needed for get-identity (users). */
const ACCESS_COOKIE_NAME = 'CF_Authorization'
/** Cloudflare's per-request ray id; we use it as the correlation request id. */
const RAY_HEADER = 'cf-ray'

export interface ForwardedCredentials {
	/** Cf-Access-Jwt-Assertion value, or null if absent (no Access in front). */
	token: string | null
	/** CF_Authorization cookie value parsed from the Cookie header, or null. */
	cookie: string | null
	/** The app's own origin (scheme + host), for the IAM Worker's get-identity call. */
	origin: string
	/** cf-ray, or a fresh UUID when absent (e.g. local dev). */
	requestId: string
}

/**
 * Pull the forwarded Access credentials and a correlation id off the request. The token
 * and cookie may be null (e.g. a Bypass path with no Access in front); the IAM Worker
 * decides what that means.
 */
export function readCredentials(req: Request): ForwardedCredentials {
	return {
		token: req.headers.get(ACCESS_TOKEN_HEADER),
		cookie: parseCookie(req.headers.get('Cookie'), ACCESS_COOKIE_NAME),
		origin: new URL(req.url).origin,
		requestId: req.headers.get(RAY_HEADER) ?? crypto.randomUUID(),
	}
}

/** Read a single cookie value out of a raw Cookie header. Returns null when absent. */
function parseCookie(header: string | null, name: string): string | null {
	if (!header) {
		return null
	}
	for (const part of header.split(';')) {
		const eq = part.indexOf('=')
		if (eq === -1) {
			continue
		}
		if (part.slice(0, eq).trim() === name) {
			return part.slice(eq + 1).trim()
		}
	}
	return null
}
