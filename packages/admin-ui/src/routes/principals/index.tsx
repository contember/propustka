import { createPage, Link, useNavigate } from '@buzola/router'
import type { CreateGrantRequest, InviteRequest, ListResponse, PrincipalListItem, ProjectDto, RoleDto } from '@propustka/worker/admin'
import { useState } from 'react'
import { StatusBadge } from '../../components/Badge'
import { RolePicker } from '../../components/RolePicker'
import { resolveScope, ScopePicker, type ScopeValue } from '../../components/ScopePicker'
import { Table } from '../../components/Table'
import { api, ApiError } from '../../lib/api'
import { fmtDate, parseDateTimeLocal } from '../../lib/format'

/** '' = all types, otherwise a principal type. */
type TypeFilter = '' | PrincipalListItem['type']

export default createPage()
	.loader(async () => {
		const [principals, roles, projects] = await Promise.all([
			api.get<ListResponse<PrincipalListItem>>('/principals'),
			api.get<ListResponse<RoleDto>>('/roles'),
			api.get<ListResponse<ProjectDto>>('/projects'),
		])
		return {
			principals: principals.items,
			roles: roles.items,
			projects: projects.items,
		}
	})
	.route('/principals')
	.render(({ data, invalidate }) => {
		const [type, setType] = useState<TypeFilter>('')
		const [query, setQuery] = useState('')

		function onTypeChange(value: string) {
			if (value === 'user' || value === 'service') setType(value)
			else setType('')
		}

		const q = query.trim().toLowerCase()
		const filtered = data.principals.filter((p) => {
			if (type && p.type !== type) return false
			if (q === '') return true
			return [p.label, p.email, p.externalId]
				.some((v) => v !== null && v !== undefined && v.toLowerCase().includes(q))
		})

		return (
			<>
				<div className="page-head">
					<h1>Principals</h1>
				</div>

				<InviteForm roles={data.roles} projects={data.projects} onDone={invalidate} />

				<div className="toolbar">
					<label>
						Type{' '}
						<select value={type} onChange={(e) => onTypeChange(e.target.value)}>
							<option value="">All</option>
							<option value="user">User</option>
							<option value="service">Service</option>
						</select>
					</label>
					<input
						type="search"
						placeholder="Search label / email / external id"
						value={query}
						onChange={(e) => setQuery(e.target.value)}
					/>
					<span className="count muted">{filtered.length} of {data.principals.length}</span>
				</div>

				<Table
					colSpan={5}
					isEmpty={filtered.length === 0}
					empty="No principals match."
					head={
						<tr>
							<th>Type</th>
							<th>Label</th>
							<th>External id</th>
							<th>Status</th>
							<th>Created</th>
						</tr>
					}
				>
					{filtered.map((p) => (
						<tr key={p.id}>
							<td>{p.type}</td>
							<td>
								<Link to="principals/detail" params={{ id: p.id }}>{p.label}</Link>
								{p.email && <div className="muted small">{p.email}</div>}
							</td>
							<td>{p.externalId ?? <span className="muted">—</span>}</td>
							<td>
								<StatusBadge status={p.status} />
							</td>
							<td>{fmtDate(p.createdAt)}</td>
						</tr>
					))}
				</Table>
			</>
		)
	})

interface InviteFormProps {
	roles: RoleDto[]
	projects: ProjectDto[]
	onDone: () => void
}

function InviteForm({ roles, projects, onDone }: InviteFormProps) {
	const navigate = useNavigate()
	const [open, setOpen] = useState(false)
	const [email, setEmail] = useState('')
	const [withGrant, setWithGrant] = useState(false)
	const [roleKey, setRoleKey] = useState('')
	const [scope, setScope] = useState<ScopeValue>({ kind: 'unset' })
	const [expiry, setExpiry] = useState('')
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)

	async function submit(e: React.FormEvent) {
		e.preventDefault()
		setError(null)

		let projectId: string | null = null
		if (withGrant) {
			if (roleKey === '') {
				setError('Pick a role for the grant, or uncheck "also grant a role".')
				return
			}
			try {
				projectId = resolveScope(scope)
			} catch {
				setError('Pick a scope for the grant.')
				return
			}
		}

		setBusy(true)
		try {
			const invited = await api.post<PrincipalListItem>('/principals', { email } satisfies InviteRequest)
			if (withGrant) {
				const body: CreateGrantRequest = {
					principalId: invited.id,
					roleKey,
					projectId,
					expiresAt: parseDateTimeLocal(expiry),
				}
				await api.post('/grants', body)
			}
			setOpen(false)
			setEmail('')
			setWithGrant(false)
			setRoleKey('')
			setScope({ kind: 'unset' })
			setExpiry('')
			onDone()
			navigate('principals/detail', { params: { id: invited.id } })
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Invite failed.')
		} finally {
			setBusy(false)
		}
	}

	if (!open) {
		return (
			<div className="panel">
				<button type="button" className="primary" onClick={() => setOpen(true)}>Invite user</button>
				<p className="hint">
					Pre-create an invited user so you can grant a role before their first login. For team-wide pre-authorization, use group mappings instead.
				</p>
			</div>
		)
	}

	return (
		<form className="panel form" onSubmit={submit}>
			<h2>Invite user</h2>
			<label>
				Email
				<input
					type="email"
					required
					value={email}
					onChange={(e) => setEmail(e.target.value)}
					placeholder="person@example.com"
				/>
			</label>
			<label className="checkbox">
				<input type="checkbox" checked={withGrant} onChange={(e) => setWithGrant(e.target.checked)} />
				Also grant a role now
			</label>
			{withGrant && (
				<div className="nested">
					<label>
						Role
						<RolePicker roles={roles} value={roleKey} onChange={setRoleKey} />
					</label>
					<ScopePicker projects={projects} value={scope} onChange={setScope} idPrefix="invite-scope" />
					<label>
						Expires (optional)
						<input type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
					</label>
				</div>
			)}
			{error && <p className="error-text" role="alert">{error}</p>}
			<div className="form-actions">
				<button type="button" onClick={() => setOpen(false)} disabled={busy}>Cancel</button>
				<button type="submit" className="primary" disabled={busy}>
					{busy ? 'Inviting…' : 'Invite'}
				</button>
			</div>
		</form>
	)
}
