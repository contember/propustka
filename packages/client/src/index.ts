// @propustka/client — the app-facing IAM SDK (the only package published to npm).
//
// Depends ONLY on @propustka/core: the binding is typed as the `IamRpc` contract (so the SDK
// never imports the Worker), and `can()`/`scopedTo()` reuse core's `permits`/`matchAction`.

export { IamClient } from './client'
export { FakeIamClient } from './fake'
export type { FakeIamConfig, FakePersona } from './fake'
export { applyScope } from './scope'
// propustka-native session auth: the middleware an app puts in front of its request handler. It
// enforces the per-path gate schema (`AppGates`) in-process, then verifies a per-app permission
// token LOCALLY (no per-request RPC), minting a fresh one from the SSO session when needed.
export { PropustkaAuth } from './session'
export type { SessionAuthConfig, SessionAuthResult } from './session'
// Deploy-time helper: reconcile an app's declared AppSchema (authz vocabulary) into Propustka (an
// HTTP admin call, NOT over the service binding). Import from a deploy/provisioning step.
export { reconcileSchema, ReconcileSchemaError } from './provision'
export type { ReconcileSchemaOptions } from './provision'
export type {
	AuthContext,
	IssuedJwt,
	IssuedKey,
	IssueFailure,
	IssueJwtRequest,
	IssueKeyRequest,
	ListPrincipalsFailure,
	PrincipalIdentity,
	PrincipalList,
	RevokedKey,
	RevokeFailure,
} from './types'

// Re-export from core so apps need only depend on the SDK: DomainEvent (one event shape),
// IamRpc (the binding contract — apps type their `env.IAM` as IamRpc without importing core),
// Scope (the `{ type, value }` coordinate apps pass to `can()`), the AppSchema vocabulary types
// apps DECLARE in `propustka.schema.ts` for `reconcileSchema()`, and the per-path gate types
// (`AppGates` & co.) apps DECLARE and pass to `PropustkaAuth`.
export type {
	AppActionDef,
	AppGates,
	AppSchema,
	AppScopeDef,
	CredentialLocation,
	DomainEvent,
	GateKind,
	GateRule,
	IamRpc,
	PrincipalListItem,
	RoleDef,
	Scope,
} from '@propustka/core'
