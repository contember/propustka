import type { RoleDto } from '@propustka/worker/admin'

interface RolePickerProps {
	/** Roles for the chosen app — built-in (cross-app) + the app's app/custom roles. */
	roles: RoleDto[]
	value: string
	onChange: (roleKey: string) => void
	id?: string
}

/**
 * A `<select>` of named roles available for the chosen app (from `GET /roles?app=…`).
 * Options are grouped by origin (built-in / app / custom). The empty option forces an
 * explicit pick.
 */
export function RolePicker({ roles, value, onChange, id }: RolePickerProps) {
	const byOrigin: Record<RoleDto['origin'], RoleDto[]> = { builtin: [], app: [], custom: [] }
	for (const role of roles) byOrigin[role.origin].push(role)
	const groups: { origin: RoleDto['origin']; label: string }[] = [
		{ origin: 'builtin', label: 'Built-in' },
		{ origin: 'app', label: 'App roles' },
		{ origin: 'custom', label: 'Custom policies' },
	]

	return (
		<select
			id={id}
			aria-label="Role"
			value={value}
			onChange={(e) => onChange(e.target.value)}
		>
			<option value="">Select a role…</option>
			{groups.map(({ origin, label }) =>
				byOrigin[origin].length === 0 ? null : (
					<optgroup key={origin} label={label}>
						{byOrigin[origin].map((role) => (
							<option key={role.key} value={role.key}>
								{role.name} ({role.key})
							</option>
						))}
					</optgroup>
				)
			)}
		</select>
	)
}
