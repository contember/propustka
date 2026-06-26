/**
 * Opaque-secret helpers shared by every stored credential (API keys, share links, SSO sessions):
 * generate a high-entropy token and hash it for storage. Only the SHA-256 hash is ever persisted,
 * so a DB leak yields no usable secret.
 */

/** SHA-256 hex of a token. Only the hash is stored — a DB leak yields no usable token. */
export async function hashToken(token: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Generate a high-entropy random token (160 bits, > the 128-bit minimum) as
 * URL-safe base64url. The plaintext is shown once at issue and never stored.
 */
export function generateToken(): string {
	const bytes = new Uint8Array(20)
	crypto.getRandomValues(bytes)
	let binary = ''
	for (const b of bytes) {
		binary += String.fromCharCode(b)
	}
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}
