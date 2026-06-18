// @propustka/client — the app-facing IAM SDK (the only package published to npm).
//
// Depends ONLY on @propustka/core: the binding is typed as the `IamRpc` contract (so the SDK
// never imports the Worker), and `can()`/`scopedTo()` reuse core's `permits`/`matchAction`.

export { IamClient } from './client'
export { FakeIamClient } from './fake'
export type { FakeIamConfig, FakePersona } from './fake'
export { applyScope } from './scope'
// Deploy-time helpers: reconcile an app's declared AppSchema (authz vocabulary) and AppAccess
// (Cloudflare Access edge rules) into Propustka (HTTP admin calls, NOT over the service binding).
// Import from a deploy/provisioning step, never request handling.
export { reconcileAccess, ReconcileAccessError, reconcileSchema, ReconcileSchemaError } from './provision'
export type { ReconcileAccessOptions, ReconcileSchemaOptions } from './provision'
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
	ListPrincipalsFailure,
	PrincipalIdentity,
	PrincipalList,
	RevokedCapability,
	RevokedServiceToken,
	RevokeFailure,
	RevokeServiceTokenFailure,
	RotatedServiceToken,
	RotateServiceTokenFailure,
} from './types'

// Re-export from core so apps need only depend on the SDK: DomainEvent (one event shape),
// IamRpc (the binding contract — apps type their `env.IAM` as IamRpc without importing core),
// Scope (the `{ type, value }` coordinate apps pass to `can()`), the AppSchema vocabulary types
// apps use to DECLARE their `propustka.schema.ts` for `reconcileSchema()`, and the AppAccess edge
// types apps DECLARE in their `propustka.access.ts` for `reconcileAccess()`.
export type {
	AccessAppDecl,
	AccessRule,
	AppAccess,
	AppActionDef,
	AppSchema,
	AppScopeDef,
	DomainEvent,
	IamRpc,
	PrincipalListItem,
	RoleDef,
	Scope,
} from '@propustka/core'
