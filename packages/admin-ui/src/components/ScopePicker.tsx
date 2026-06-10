import type { ProjectDto } from '@propustka/worker/admin'

/**
 * The chosen scope for a grant / mapping. Three explicit states:
 *  - `{ kind: 'unset' }`  — nothing chosen yet; the admin MUST pick (never silently global)
 *  - `{ kind: 'global' }` — all projects → stored `project_id = null`
 *  - `{ kind: 'project', projectId }` — scoped to one project
 */
export type ScopeValue =
	| { kind: 'unset' }
	| { kind: 'global' }
	| { kind: 'project'; projectId: string }

/** Resolve a ScopeValue to the API `projectId` field; throws if still unset. */
export function resolveScope(value: ScopeValue): string | null {
	if (value.kind === 'global') return null
	if (value.kind === 'project') return value.projectId
	throw new Error('Pick a scope first.')
}

interface ScopePickerProps {
	projects: ProjectDto[]
	value: ScopeValue
	onChange: (value: ScopeValue) => void
	idPrefix?: string
}

/**
 * Explicit Global-vs-project scope picker. Defaults to "unset" so the admin must choose;
 * "Global / all projects" is a distinct option from picking a specific project.
 */
export function ScopePicker({ projects, value, onChange, idPrefix = 'scope' }: ScopePickerProps) {
	const globalId = `${idPrefix}-global`
	const projectId = `${idPrefix}-project`

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
				Global / all projects
			</label>
			<label htmlFor={projectId}>
				<input
					id={projectId}
					type="radio"
					name={idPrefix}
					checked={value.kind === 'project'}
					onChange={() =>
						onChange(
							projects[0]
								? { kind: 'project', projectId: projects[0].id }
								: { kind: 'unset' },
						)}
					disabled={projects.length === 0}
				/>
				Specific project
			</label>
			{value.kind === 'project' && (
				<select
					aria-label="Project"
					value={value.projectId}
					onChange={(e) => onChange({ kind: 'project', projectId: e.target.value })}
				>
					{projects.map((p) => (
						<option key={p.id} value={p.id}>{p.name} ({p.slug})</option>
					))}
				</select>
			)}
			{projects.length === 0 && (
				<p className="hint">No projects yet — create one to scope grants to a project.</p>
			)}
		</fieldset>
	)
}
