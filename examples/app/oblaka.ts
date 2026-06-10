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
		bindings: {
			IAM: new ServiceReference('propustka-worker'),
		},
		vars: {
			DEV: 'true',
		},
	})
)
