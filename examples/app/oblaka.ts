import { define, ServiceReference, Worker } from 'oblaka-iac'

// A standalone app that consumes the IAM Worker over a service binding. In its OWN
// repo an app would add just this `IAM` binding to its existing Worker; here it is a
// whole tiny Worker so the example runs on its own.
//
// `ServiceReference('propustka-worker')` resolves to the deployed IAM Worker by name.
// Locally, lopata wires the two workers in-process (see lopata.config.ts).
export default define(() =>
	new Worker({
		dir: '.',
		name: 'propustka-example-app',
		main: './src/index.ts',
		compatibility_flags: ['nodejs_compat_v2'],
		compatibility_date: '2025-10-01',
		observability: { enabled: true },
		// Path routes so this app is reachable under the combined local demo (lopata runs the
		// IAM Worker as the main/fallback serving the admin UI, this app as an auxiliary worker).
		// Domain is stripped locally — only the `/demo` path matters.
		routes: ['*/demo', '*/demo/*'],
		bindings: {
			IAM: new ServiceReference('propustka-worker'),
		},
		vars: {
			DEV: 'true',
			// propustka's origin — where the session middleware sends the browser to log in, and
			// the `iss`/JWKS the SDK verifies minted tokens against. Locally the IAM Worker's dev
			// origin; in a real app the deployed propustka hostname (PROPUSTKA_HOSTNAME).
			PROPUSTKA_ISSUER: 'http://localhost:18191',
		},
	})
)
