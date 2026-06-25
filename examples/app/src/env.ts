import type { IamRpc } from '@propustka/client'

export interface Env {
	// The IAM Worker, reached over a service binding (oblaka `ServiceReference('propustka-worker')`).
	// Typed as the `IamRpc` contract re-exported by the SDK — the app needs no dependency on the
	// worker package itself.
	IAM: IamRpc
	// Dev flag: in real apps, select `FakeIamClient` when this is set so `wrangler dev` needs no
	// Access and no IAM Worker. This example always uses the real binding to exercise the RPC path.
	DEV: string
	// propustka's origin — the base for the login redirect and the `iss`/JWKS the SDK verifies
	// minted permission tokens against (see PropustkaAuth in src/index.ts).
	PROPUSTKA_ISSUER: string
}
