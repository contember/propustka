import type { AppScopeDef } from '@propustka/worker/admin'

/**
 * The chosen scope for a grant / mapping. Two explicit states:
 *  - `{ kind: 'global' }` — all scopes → stored `scope_type = scope_value = null`
 *  - `{ kind: 'scoped', type, value }` — one flat dimension + an opaque app-owned value
 *
 * Scope dimensions come from the chosen app's reconciled schema (`app_scopes`). The
 * value is an OPAQUE app-owned string — never validated, never offered from a known list.
 */
export type ScopeValue =
	| { kind: 'global' }
	| { kind: 'scoped'; type: string; value: string }

/** Resolve a ScopeValue to the API `scopeType` / `scopeValue` pair (both null = global). */
export function resolveScope(value: ScopeValue): { scopeType: string | null; scopeValue: string | null } {
	if (value.kind === 'global') return { scopeType: null, scopeValue: null }
	const type = value.type.trim()
	const val = value.value.trim()
	if (type === '' || val === '') throw new Error('Pick a scope dimension and enter a value, or choose Global.')
	return { scopeType: type, scopeValue: val }
}

interface ScopePickerProps {
	/** Scope dimensions for the chosen app (from GET schema); empty when no app picked. */
	scopes: AppScopeDef[]
	value: ScopeValue
	onChange: (value: ScopeValue) => void
	idPrefix?: string
}

/**
 * Generic scope picker: Global, or one flat dimension (`type`, from the app's
 * `app_scopes`) plus an opaque text value. Defaults to Global. The value box is a free
 * text input — scope values are app-owned and never validated or enumerated here.
 */
export function ScopePicker({ scopes, value, onChange, idPrefix = 'scope' }: ScopePickerProps) {
	const globalId = `${idPrefix}-global`
	const scopedId = `${idPrefix}-scoped`
	const firstType = scopes[0]?.type ?? ''

	return (
		<fieldset className="scope-picker">
			<legend>Scope</legend>
			<label htmlFor={globalId}>
				<input
					id={globalId}
					type="radio"
					name={idPrefix}
					checked={value.kind === 'global'}
					onChange={() => onChange({ kind: 'global' })}
				/>
				Global / all scopes
			</label>
			<label htmlFor={scopedId}>
				<input
					id={scopedId}
					type="radio"
					name={idPrefix}
					checked={value.kind === 'scoped'}
					onChange={() => onChange({ kind: 'scoped', type: firstType, value: '' })}
					disabled={scopes.length === 0}
				/>
				Scoped to a dimension
			</label>
			{value.kind === 'scoped' && (
				<div className="scope-fields">
					<select
						aria-label="Scope dimension"
						value={value.type}
						onChange={(e) => onChange({ kind: 'scoped', type: e.target.value, value: value.value })}
					>
						{scopes.map((s) => <option key={s.type} value={s.type}>{s.label ? `${s.label} (${s.type})` : s.type}</option>)}
					</select>
					<input
						aria-label="Scope value"
						value={value.value}
						onChange={(e) => onChange({ kind: 'scoped', type: value.type, value: e.target.value })}
						placeholder="opaque value"
					/>
				</div>
			)}
			{scopes.length === 0 && <p className="hint">Pick an app with declared scope dimensions to scope this; otherwise it stays global.</p>}
		</fieldset>
	)
}
