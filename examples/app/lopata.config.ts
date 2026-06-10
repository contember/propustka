// Standalone run of just this example app, with the IAM Worker as an auxiliary worker, to
// exercise the app→IAM RPC path in isolation (`env.IAM.authenticate()` over the binding).
//
// For the FULL demo — the admin UI plus this app sharing one local D1 — run `bun run dev` from
// `packages/worker` instead (its lopata.config.ts runs this app as an auxiliary at `/demo`).
export default {
	main: 'wrangler.jsonc',
	workers: [
		{
			name: 'propustka-worker',
			config: '../../packages/worker/wrangler.jsonc',
		},
	],
}
