// @propustka/client — the app-facing IAM SDK (the only package published to npm).
//
// Depends ONLY on @propustka/core: the binding is typed as the `IamRpc` contract (so the SDK
// never imports the Worker), and `can()`/`scopedTo()` reuse core's `permits`/`matchAction`.

export { IamClient } from './client'
export { FakeIamClient } from './fake'
export type { FakeIamConfig, FakePersona } from './fake'
export { applyScope } from './scope'
export type {
	AuthContext,
	AuthFailure,
	Capability,
	CapabilityFailure,
	IssueCapabilityRequest,
	IssuedCapability,
	IssueFailure,
	PrincipalIdentity,
	RevokedCapability,
	RevokeFailure,
} from './types'

// Re-export from core so apps need only depend on the SDK: DomainEvent (one event shape),
// IamRpc (the binding contract — apps type their `env.IAM` as IamRpc without importing core),
// and Scope (the `{ type, value }` coordinate apps pass to `can()`).
export type { DomainEvent, IamRpc, Scope } from '@propustka/core'
