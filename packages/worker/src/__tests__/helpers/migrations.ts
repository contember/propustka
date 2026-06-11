import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * The cumulative schema: every `migrations/*.sql` concatenated in filename order.
 * Tests stand up an in-memory sqlite from this so they run against the SAME schema
 * a deployed worker reaches after `wrangler d1 migrations apply` (not just 0001).
 */
export function allMigrations(): string {
	const dir = join(import.meta.dir, '..', '..', '..', 'migrations')
	return readdirSync(dir)
		.filter((f) => f.endsWith('.sql'))
		.sort()
		.map((f) => readFileSync(join(dir, f), 'utf8'))
		.join('\n')
}
