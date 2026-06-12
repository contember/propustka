import type { AppActionDef } from '@propustka/worker/admin'

interface ActionPickerProps {
	/** The chosen app's action catalog (from GET schema); empty when no app picked. */
	actions: AppActionDef[]
	/** Currently selected action patterns (concrete catalog actions). */
	value: string[]
	onChange: (value: string[]) => void
	idPrefix?: string
}

/**
 * Multi-select over an app's action catalog (`app_actions`), used to compose inline grant
 * permissions or a custom policy's permission set. Each picked entry is a concrete catalog
 * action — always a valid pattern the worker will accept (the worker also allows `prefix.*`
 * / `*`, but this picker keeps composition explicit by listing concrete actions only).
 */
export function ActionPicker({ actions, value, onChange, idPrefix = 'action' }: ActionPickerProps) {
	const selected = new Set(value)

	function toggle(action: string, on: boolean) {
		const next = new Set(selected)
		if (on) next.add(action)
		else next.delete(action)
		onChange([...next])
	}

	if (actions.length === 0) {
		return <p className="hint">Pick an app with a declared action catalog to compose inline permissions.</p>
	}

	return (
		<fieldset className="action-picker">
			<legend>Actions</legend>
			<div className="action-list">
				{actions.map((a) => {
					const id = `${idPrefix}-${a.action}`
					return (
						<label key={a.action} htmlFor={id} className="checkbox" title={a.description}>
							<input
								id={id}
								type="checkbox"
								checked={selected.has(a.action)}
								onChange={(e) => toggle(a.action, e.target.checked)}
							/>
							<code>{a.action}</code>
							{a.description && <span className="muted small">{a.description}</span>}
						</label>
					)
				})}
			</div>
		</fieldset>
	)
}
