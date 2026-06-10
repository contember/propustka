/**
 * Generate a UUIDv7 (RFC 9562): time-sortable, 128 bits.
 *
 * Layout:
 *   - bytes 0..5  : 48-bit big-endian Unix-millis timestamp
 *   - byte  6     : version nibble `7` in the high 4 bits, random in the low 4
 *   - byte  8     : RFC 4122 variant bits `10` in the high 2 bits, random in the low 6
 *   - the remaining 74 bits are random (`crypto.getRandomValues`)
 *
 * Because the timestamp occupies the most-significant bytes, two ids generated at
 * different milliseconds sort lexicographically in time order. No dependency.
 */
export function uuidv7(): string {
	const bytes = new Uint8Array(16)

	// 48-bit big-endian Unix-millis timestamp in the first 6 bytes.
	const millis = Date.now()
	// `millis` fits in 48 bits (well under 2^53), so the high bits are zero.
	bytes[0] = Math.floor(millis / 0x10000000000) & 0xff
	bytes[1] = Math.floor(millis / 0x100000000) & 0xff
	bytes[2] = Math.floor(millis / 0x1000000) & 0xff
	bytes[3] = Math.floor(millis / 0x10000) & 0xff
	bytes[4] = Math.floor(millis / 0x100) & 0xff
	bytes[5] = millis & 0xff

	// Fill the remaining 10 bytes (74 usable random bits + the nibble/variant slots) with randomness.
	const random = new Uint8Array(10)
	crypto.getRandomValues(random)
	bytes.set(random, 6)

	// Version: high nibble of byte 6 = 0b0111 (7).
	bytes[6] = (bytes[6]! & 0x0f) | 0x70
	// Variant: high two bits of byte 8 = 0b10.
	bytes[8] = (bytes[8]! & 0x3f) | 0x80

	const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'))

	return `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-${hex[6]}${hex[7]}-${hex[8]}${hex[9]}-${hex[10]}${hex[11]}${hex[12]}${hex[13]}${
		hex[14]
	}${hex[15]}`
}
