import { createPage, useNavigate } from '@buzola/router'
import type { AppDto, ListResponse, RoleDto } from '@propustka/worker/admin'
import { Badge } from '../components/Badge'
import { Table } from '../components/Table'
import { api } from '../lib/api'

/** A label per role origin, for the reference table's badge. */
const ORIGIN_LABEL: Record<RoleDto['origin'], string> = {
	builtin: 'built-in',
	app: 'app',
	custom: 'custom',
}

/**
 * Reference for the roles grantable for an app: built-in (cross-app) plus the app's app
 * and custom roles (`GET /roles?app=…`). The app is chosen via the `?app` query param;
 * without it, only the built-ins show.
 */
export default createPage()
	.params({ app: '?string' })
	.loader(async ({ params }) => {
		const apps = await api.get<ListResponse<AppDto>>('/apps')
		const app = params.app && apps.items.some((a) => a.id === params.app) ? params.app : null
		const path = app === null ? '/roles' : `/roles?app=${encodeURIComponent(app)}`
		const roles = await api.get<ListResponse<RoleDto>>(path)
		return { apps: apps.items, app, roles: roles.items }
	})
	.route('/roles')
	.render(({ data }) => {
		const navigate = useNavigate()

		return (
			<>
				<div className="page-head">
					<h1>Roles</h1>
					<p className="hint">
						What each grantable role expands to — the legend for the role pickers. Built-ins are cross-app; app and custom roles are per-app.
					</p>
				</div>

				<div className="toolbar">
					<label>
						App{' '}
						<select
							value={data.app ?? ''}
							onChange={(e) => navigate('roles', { params: { app: e.target.value || undefined }, replace: true })}
						>
							<option value="">Built-in only</option>
							{data.apps.map((a) => <option key={a.id} value={a.id}>{a.id}</option>)}
						</select>
					</label>
				</div>

				<Table
					colSpan={4}
					isEmpty={data.roles.length === 0}
					empty="No roles."
					head={
						<tr>
							<th>Role</th>
							<th>Origin</th>
							<th>Description</th>
							<th>Permission patterns</th>
						</tr>
					}
				>
					{data.roles.map((role) => (
						<tr key={role.key}>
							<td>
								<strong>{role.name}</strong>
								<div className="muted small">
									<code>{role.key}</code>
								</div>
							</td>
							<td>
								<Badge tone="muted">{ORIGIN_LABEL[role.origin]}</Badge>
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
		)
	})
