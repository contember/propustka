import type { AppDto } from '@propustka/worker/admin'
import { useState } from 'react'
import { useAppVocab } from '../lib/useAppVocab'
import { ActionPicker } from './ActionPicker'
import { AppPicker, type AppValue, resolveApp } from './AppPicker'
import { RolePicker } from './RolePicker'
import { resolveScope, ScopePicker, type ScopeValue } from './ScopePicker'

/**
 * The authorization a grant / API-key / mapping confers, composed here:
 *  - `app`        — the app the grant counts for (null = cross-app).
 *  - role XOR inline — exactly one of `roleKey` / `permissions` (enforced by the form).
 *  - scope        — `scopeType` / `scopeValue` (both null = global).
 *
 * This is the subset of `CreateGrantRequest` / `ProvisionApiKeyRequest` the composer owns;
 * callers add `principalId` / `label` / `expiresAt` around it.
 */
export interface GrantAuthorization {
	app: string | null
	roleKey?: string
	permissions?: string[]
	scopeType: string | null
	scopeValue: string | null
}

/** 'role' = a named role/policy; 'inline' = an ad-hoc action set. Exactly one applies. */
type Mode = 'role' | 'inline'

interface GrantComposerProps {
	apps: AppDto[]
	/** Called with a validated authorization, or throws an Error with a user message. */
	state: GrantComposerState
	idPrefix: string
}

/** Hoisted state so the parent form can read/reset it and run `build()` on submit. */
export interface GrantComposerState {
	appValue: AppValue
	setAppValue: (value: AppValue) => void
	mode: Mode
	setMode: (mode: Mode) => void
	roleKey: string
	setRoleKey: (key: string) => void
	permissions: string[]
	setPermissions: (permissions: string[]) => void
	scope: ScopeValue
	setScope: (scope: ScopeValue) => void
}

/** A fresh, empty composer state (defaults to role mode, unset app, global scope). */
export function useGrantComposerState(): GrantComposerState & { reset: () => void; build: () => GrantAuthorization } {
	const [appValue, setAppValue] = useState<AppValue>({ kind: 'unset' })
	const [mode, setMode] = useState<Mode>('role')
	const [roleKey, setRoleKey] = useState('')
	const [permissions, setPermissions] = useState<string[]>([])
	const [scope, setScope] = useState<ScopeValue>({ kind: 'global' })

	function reset() {
		setAppValue({ kind: 'unset' })
		setMode('role')
		setRoleKey('')
		setPermissions([])
		setScope({ kind: 'global' })
	}

	/** Validate and assemble the authorization, throwing an Error with a user-facing message. */
	function build(): GrantAuthorization {
		const app = resolveApp(appValue) // throws if app is still unset
		const { scopeType, scopeValue } = resolveScope(scope)
		if (mode === 'role') {
			if (roleKey === '') throw new Error('Pick a role.')
			return { app, roleKey, scopeType, scopeValue }
		}
		if (permissions.length === 0) throw new Error('Pick at least one action for an inline grant.')
		return { app, permissions, scopeType, scopeValue }
	}

	return { appValue, setAppValue, mode, setMode, roleKey, setRoleKey, permissions, setPermissions, scope, setScope, reset, build }
}

/**
 * The shared grant body: pick an app, then EITHER a named role OR an inline action set,
 * plus a scope. The role list, scope dimensions and action catalog all derive from the
 * chosen app (loaded reactively via `useAppVocab`). The parent owns submit / expiry.
 */
export function GrantComposer({ apps, state, idPrefix }: GrantComposerProps) {
	const { appValue, setAppValue, mode, setMode, roleKey, setRoleKey, permissions, setPermissions, scope, setScope } = state
	const app = appValue.kind === 'unset' ? undefined : appValue.kind === 'all' ? null : appValue.app
	const vocab = useAppVocab(app)

	return (
		<>
			<AppPicker apps={apps} value={appValue} onChange={setAppValue} idPrefix={`${idPrefix}-app`} />

			{vocab.status === 'loading' && <p className="hint">Loading app roles & actions…</p>}
			{vocab.status === 'error' && <p className="error-text" role="alert">{vocab.message}</p>}

			<fieldset className="grant-mode">
				<legend>Permissions</legend>
				<label className="radio">
					<input
						type="radio"
						name={`${idPrefix}-mode`}
						checked={mode === 'role'}
						onChange={() => setMode('role')}
					/>
					Named role / policy
				</label>
				<label className="radio">
					<input
						type="radio"
						name={`${idPrefix}-mode`}
						checked={mode === 'inline'}
						onChange={() => setMode('inline')}
						disabled={appValue.kind !== 'app'}
					/>
					Inline actions
				</label>
			</fieldset>

			{mode === 'role'
				? (
					<label>
						Role
						<RolePicker roles={vocab.status === 'ok' ? vocab.vocab.roles : []} value={roleKey} onChange={setRoleKey} />
					</label>
				)
				: (
					<ActionPicker
						actions={vocab.status === 'ok' ? vocab.vocab.actions : []}
						value={permissions}
						onChange={setPermissions}
						idPrefix={`${idPrefix}-action`}
					/>
				)}

			<ScopePicker
				scopes={vocab.status === 'ok' ? vocab.vocab.scopes : []}
				value={scope}
				onChange={setScope}
				idPrefix={`${idPrefix}-scope`}
			/>
		</>
	)
}
