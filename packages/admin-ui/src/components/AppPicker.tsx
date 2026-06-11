import type { AppDto } from '@propustka/worker/admin'

/**
 * Which app a grant / mapping applies to. Three explicit states (mirrors ScopePicker)
 * so a cross-app grant is never made by accident:
 *  - `{ kind: 'unset' }` — nothing chosen yet; the admin MUST pick
 *  - `{ kind: 'all' }`   — every app → stored `app = null` (cross-app, e.g. super-admin)
 *  - `{ kind: 'app', app }` — scoped to one app (opice / poplach / …)
 */
export type AppValue =
	| { kind: 'unset' }
	| { kind: 'all' }
	| { kind: 'app'; app: string }

/** Resolve an AppValue to the API `app` field; throws if still unset. */
export function resolveApp(value: AppValue): string | null {
	if (value.kind === 'all') return null
	if (value.kind === 'app') return value.app
	throw new Error('Pick an app first.')
}

interface AppPickerProps {
	apps: AppDto[]
	value: AppValue
	onChange: (value: AppValue) => void
	idPrefix?: string
}

/**
 * Explicit All-apps-vs-one-app picker. Authorization is app-scoped: a grant counts only
 * for its app (or every app when "All apps"). Defaults to "unset" so the admin chooses
 * deliberately — "All apps" is a distinct, conscious option, not a silent default.
 */
export function AppPicker({ apps, value, onChange, idPrefix = 'app' }: AppPickerProps) {
	const allId = `${idPrefix}-all`
	const oneId = `${idPrefix}-one`

	return (
		<fieldset className="scope-picker">
			<legend>App</legend>
			<label htmlFor={allId}>
				<input
					id={allId}
					type="radio"
					name={idPrefix}
					checked={value.kind === 'all'}
					onChange={() => onChange({ kind: 'all' })}
				/>
				All apps (cross-app)
			</label>
			<label htmlFor={oneId}>
				<input
					id={oneId}
					type="radio"
					name={idPrefix}
					checked={value.kind === 'app'}
					onChange={() => onChange(apps[0] ? { kind: 'app', app: apps[0].id } : { kind: 'unset' })}
					disabled={apps.length === 0}
				/>
				Specific app
			</label>
			{value.kind === 'app' && (
				<select
					aria-label="App"
					value={value.app}
					onChange={(e) => onChange({ kind: 'app', app: e.target.value })}
				>
					{apps.map((a) => <option key={a.id} value={a.id}>{a.id}</option>)}
				</select>
			)}
			{apps.length === 0 && <p className="hint">No apps configured (ACCESS_APPS empty) — grants can only be cross-app.</p>}
		</fieldset>
	)
}
