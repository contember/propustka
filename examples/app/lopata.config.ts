// Multi-worker local dev: this example app is the main worker; the IAM Worker runs
// alongside it as an auxiliary worker so the `IAM` service binding resolves in-process.
// Run `bun run oblaka` in BOTH this dir and packages/worker first to generate the
// wrangler.jsonc files referenced below.
export default {
	main: 'wrangler.jsonc',
	workers: [
		{
			name: 'propustka-worker',
			config: '../../packages/worker/wrangler.jsonc',
		},
	],
}
