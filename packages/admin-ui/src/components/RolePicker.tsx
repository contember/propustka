import type { RoleDto } from '@propustka/worker/admin'

interface RolePickerProps {
	roles: RoleDto[]
	value: string
	onChange: (roleKey: string) => void
	id?: string
}

/** A `<select>` of code-defined roles. The empty option forces an explicit pick. */
export function RolePicker({ roles, value, onChange, id }: RolePickerProps) {
	return (
		<select
			id={id}
			aria-label="Role"
			value={value}
			onChange={(e) => onChange(e.target.value)}
		>
			<option value="">Select a role…</option>
			{roles.map((role) => (
				<option key={role.key} value={role.key}>
					{role.name} ({role.key})
				</option>
			))}
		</select>
	)
}
