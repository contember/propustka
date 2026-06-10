// @propustka/client — the app-facing IAM SDK (the only package published to npm).
//
// Depends ONLY on @propustka/core: the binding is typed as the `IamRpc` contract (so the SDK
// never imports the Worker), and `can()`/`scopedTo()` reuse core's `permits`/`matchAction`.

export { IamClient } from './client'
export { FakeIamClient } from './fake'
export type { FakeIamConfig } from './fake'
export { applyScope } from './scope'
export type { AuthContext, AuthFailure, Capability, CapabilityFailure, IssueCapabilityRequest, IssuedCapability, IssueFailure } from './types'

// Re-export DomainEvent from core so apps converge on one shape without a second import.
export type { DomainEvent } from '@propustka/core'
