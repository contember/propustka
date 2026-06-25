/**
 * Cookie (de)serialization for the auth flow. Minimal — only what login/callback/logout need:
 * a `Set-Cookie` builder and a single-cookie reader off the `Cookie` header.
 */

export interface CookieOptions {
	domain?: string
	/** Lifetime in seconds. Omit for a session cookie; 0 to expire immediately. */
	maxAge?: number
	httpOnly?: boolean
	secure?: boolean
	sameSite?: 'Lax' | 'Strict' | 'None'
	path?: string
}

/** Build a `Set-Cookie` value. */
export function serializeCookie(name: string, value: string, opts: CookieOptions = {}): string {
	const parts = [`${name}=${value}`, `Path=${opts.path ?? '/'}`]
	if (opts.domain) {
		parts.push(`Domain=${opts.domain}`)
	}
	if (opts.maxAge !== undefined) {
		parts.push(`Max-Age=${opts.maxAge}`)
	}
	if (opts.httpOnly) {
		parts.push('HttpOnly')
	}
	if (opts.secure) {
		parts.push('Secure')
	}
	if (opts.sameSite) {
		parts.push(`SameSite=${opts.sameSite}`)
	}
	return parts.join('; ')
}

/** A `Set-Cookie` that immediately expires `name` (logout / one-shot cookie cleanup). */
export function clearCookie(name: string, opts: Pick<CookieOptions, 'domain' | 'path' | 'secure'> = {}): string {
	return serializeCookie(name, '', { ...opts, maxAge: 0, httpOnly: true, sameSite: 'Lax' })
}

/** Read a single cookie value out of a raw `Cookie` header. Returns null when absent. */
export function readCookie(header: string | null, name: string): string | null {
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
