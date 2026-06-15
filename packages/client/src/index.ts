// @propustka/client — the app-facing IAM SDK (the only package published to npm).
//
// Depends ONLY on @propustka/core: the binding is typed as the `IamRpc` contract (so the SDK
// never imports the Worker), and `can()`/`scopedTo()` reuse core's `permits`/`matchAction`.

export { IamClient } from './client'
export { FakeIamClient } from './fake'
export type { FakeIamConfig, FakePersona } from './fake'
export { applyScope } from './scope'
// Deploy-time helper: reconcile an app's declared AppSchema into Propustka (HTTP admin call,
// NOT over the service binding). Import from a deploy/provisioning step, never request handling.
export { reconcileSchema, ReconcileSchemaError } from './provision'
export type { ReconcileSchemaOptions } from './provision'
export type {
	AuthContext,
	AuthFailure,
	Capability,
	CapabilityFailure,
	IssueCapabilityRequest,
	IssuedCapability,
	IssuedServiceToken,
	IssueFailure,
	IssueServiceTokenFailure,
	IssueServiceTokenRequest,
	PrincipalIdentity,
	RevokedCapability,
	RevokedServiceToken,
	RevokeFailure,
	RevokeServiceTokenFailure,
	RotatedServiceToken,
	RotateServiceTokenFailure,
} from './types'

// Re-export from core so apps need only depend on the SDK: DomainEvent (one event shape),
// IamRpc (the binding contract — apps type their `env.IAM` as IamRpc without importing core),
// Scope (the `{ type, value }` coordinate apps pass to `can()`), and the AppSchema vocabulary
// types apps use to DECLARE their `propustka.schema.ts` for `reconcileSchema()`.
export type { AppActionDef, AppSchema, AppScopeDef, DomainEvent, IamRpc, RoleDef, Scope } from '@propustka/core'
