// Reading the propustka-native credential off the incoming Request, to forward to the IAM Worker's
// management RPCs (issueKey / issueJwt / revokeKey / listPrincipals). Same precedence PropustkaAuth
// uses: an `Authorization: Bearer` (a machine `px_` key or a passthrough JWT) first, else the
// browser's `px_token` access cookie. None of this is a security boundary — the Worker re-resolves
// and re-authorizes the caller server-side from this credential.

import { TOKEN_COOKIE } from '@propustka/core'

/** Cloudflare's per-request ray id; we use it as the correlation request id. */
const RAY_HEADER = 'cf-ray'

export interface ForwardedCredentials {
	/** The native credential (a `px_` key / passthrough JWT / `px_token`), or null when absent. */
	credential: string | null
	/** cf-ray, or a fresh UUID when absent (e.g. local dev). */
	requestId: string
}

/** Pull the native credential and a correlation id off the request. `credential` may be null. */
export function readCredentials(req: Request): ForwardedCredentials {
	return {
		credential: readBearer(req.headers.get('Authorization')) ?? parseCookie(req.headers.get('Cookie'), TOKEN_COOKIE),
		requestId: req.headers.get(RAY_HEADER) ?? crypto.randomUUID(),
	}
}

/** Read the token out of an `Authorization: Bearer <token>` header. Null when absent/non-bearer. */
function readBearer(header: string | null): string | null {
	if (header === null) {
		return null
	}
	const match = /^Bearer\s+(.+)$/i.exec(header.trim())
	return match ? (match[1]?.trim() ?? null) : null
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
