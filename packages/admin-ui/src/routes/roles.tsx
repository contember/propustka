import type { ListResponse, RoleDto } from '@propustka/worker/admin'
import { createPage } from '@buzola/router'
import { Table } from '../components/Table'
import { api } from '../lib/api'

export default createPage()
	.loader(async () => {
		const roles = await api.get<ListResponse<RoleDto>>('/roles')
		return { roles: roles.items }
	})
	.route('/roles')
	.render(({ data }) => (
		<>
			<div className="page-head">
				<h1>Roles</h1>
				<p className="hint">
					Roles live in code, not editable here. This is the reference for what each role
					expands to — and the legend for the role pickers elsewhere.
				</p>
			</div>

			<Table
				colSpan={3}
				isEmpty={data.roles.length === 0}
				empty="No roles registered."
				head={
					<tr>
						<th>Role</th>
						<th>Description</th>
						<th>Permission patterns</th>
					</tr>
				}
			>
				{data.roles.map((role) => (
					<tr key={role.key}>
						<td>
							<strong>{role.name}</strong>
							<div className="muted small"><code>{role.key}</code></div>
						</td>
						<td>{role.description ?? <span className="muted">—</span>}</td>
						<td>
							{role.permissions.length === 0
								? <span className="muted">none</span>
								: role.permissions.map((p) => <code key={p} className="perm-chip">{p}</code>)}
						</td>
					</tr>
				))}
			</Table>
		</>
	))
