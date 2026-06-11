import { createPage } from '@buzola/router'
import type {
	AppDto,
	CreateGrantRequest,
	GrantDto,
	ListResponse,
	PermissionEntry,
	PrincipalDetail,
	ProjectDto,
	RoleDto,
	UpdatePrincipalRequest,
} from '@propustka/worker/admin'
import { useState } from 'react'
import { AppPicker, type AppValue, resolveApp } from '../../components/AppPicker'
import { Badge, StatusBadge } from '../../components/Badge'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { RolePicker } from '../../components/RolePicker'
import { resolveScope, ScopePicker, type ScopeValue } from '../../components/ScopePicker'
import { Table } from '../../components/Table'
import { api, ApiError } from '../../lib/api'
import { fmtDate, fmtExpiry, parseDateTimeLocal } from '../../lib/format'

export default createPage()
	.params({ id: 'string' })
	.loader(async ({ params }) => {
		const [principal, roles, projects, apps] = await Promise.all([
			api.get<PrincipalDetail>(`/principals/${params.id}`),
			api.get<ListResponse<RoleDto>>('/roles'),
			api.get<ListResponse<ProjectDto>>('/projects'),
			api.get<ListResponse<AppDto>>('/apps'),
		])
		return { principal, roles: roles.items, projects: projects.items, apps: apps.items }
	})
	.route('/principals/:id')
	.render(({ data, invalidate }) => {
		const { principal, roles, projects, apps } = data
		const projectName = (id: string | null): string => {
			if (id === null) return 'Global'
			const match = projects.find((p) => p.id === id)
			return match ? `${match.name} (${match.slug})` : id
		}

		return (
			<>
				<div className="page-head">
					<div className="page-head-row">
						<h1>{principal.label}</h1>
						<StatusBadge status={principal.status} />
					</div>
					<div className="subtitle muted">
						{principal.type}
						{principal.email && <>· {principal.email}</>}
						{principal.externalId && <>· {principal.externalId}</>}
						<>· created {fmtDate(principal.createdAt)}</>
					</div>
					<DisableToggle principal={principal} onDone={invalidate} />
				</div>

				<section>
					<h2>Effective permissions</h2>
					<p className="hint">Why this principal has each permission — resolved from grants, group mappings and bootstrap.</p>
					<Table
						colSpan={3}
						isEmpty={principal.permissions.length === 0}
						empty="No effective permissions."
						head={
							<tr>
								<th>Action</th>
								<th>Scope</th>
								<th>Source</th>
							</tr>
						}
					>
						{principal.permissions.map((perm, i) => (
							<tr key={`${perm.action}:${perm.projectId ?? 'global'}:${perm.source}:${i}`}>
								<td>
									<code>{perm.action}</code>
								</td>
								<td>{projectName(perm.projectId)}</td>
								<td>
									<SourceBadge source={perm.source} />
								</td>
							</tr>
						))}
					</Table>
				</section>

				<section>
					<h2>Grants</h2>
					<Table
						colSpan={7}
						isEmpty={principal.grants.length === 0}
						empty="No explicit grants. Add one below."
						head={
							<tr>
								<th>Role</th>
								<th>App</th>
								<th>Scope</th>
								<th>Expires</th>
								<th>Granted by</th>
								<th>Created</th>
								<th />
							</tr>
						}
					>
						{principal.grants.map((grant) => (
							<GrantRow
								key={grant.id}
								grant={grant}
								scopeLabel={projectName(grant.projectId)}
								onDone={invalidate}
							/>
						))}
					</Table>
				</section>

				<AddGrantForm
					principalId={principal.id}
					roles={roles}
					projects={projects}
					apps={apps}
					onDone={invalidate}
				/>
			</>
		)
	})

function SourceBadge({ source }: { source: PermissionEntry['source'] }) {
	if (source === 'bootstrap') return <Badge tone="warn" title="From IAM_BOOTSTRAP_ADMINS">bootstrap</Badge>
	if (source === 'grant') return <Badge tone="neutral">grant</Badge>
	return <Badge tone="muted" title="From an IdP group mapping">{source}</Badge>
}

function DisableToggle({ principal, onDone }: { principal: PrincipalDetail; onDone: () => void }) {
	const [confirming, setConfirming] = useState(false)
	const disabled = principal.status === 'disabled'

	async function toggle() {
		const body: UpdatePrincipalRequest = { disabled: !disabled }
		await api.patch(`/principals/${principal.id}`, body)
		onDone()
	}

	return (
		<>
			<button
				type="button"
				className={disabled ? 'primary' : 'danger'}
				onClick={() => setConfirming(true)}
			>
				{disabled ? 'Enable' : 'Disable'}
			</button>
			{confirming && (
				<ConfirmDialog
					title={disabled ? 'Enable principal' : 'Disable principal'}
					confirmLabel={disabled ? 'Enable' : 'Disable'}
					body={
						<p>
							{disabled ? 'Re-enable ' : 'Disable '}
							<strong>{principal.label}</strong>
							{disabled
								? '? Their permissions take effect again.'
								: '? They keep their grants but resolve to zero permissions until re-enabled.'}
						</p>
					}
					onConfirm={toggle}
					onClose={() => setConfirming(false)}
				/>
			)}
		</>
	)
}

function GrantRow({ grant, scopeLabel, onDone }: { grant: GrantDto; scopeLabel: string; onDone: () => void }) {
	const [confirming, setConfirming] = useState(false)

	async function revoke() {
		await api.del(`/grants/${grant.id}`)
		onDone()
	}

	return (
		<tr>
			<td>
				<code>{grant.roleKey}</code>
				{grant.dangling && (
					<Badge tone="bad" title="This role_key is no longer in the code role registry — it resolves to zero permissions.">
						dangling
					</Badge>
				)}
			</td>
			<td>{grant.app ? <code>{grant.app}</code> : <span className="muted">All apps</span>}</td>
			<td>{scopeLabel}</td>
			<td>{fmtExpiry(grant.expiresAt)}</td>
			<td>{grant.grantedBy ?? <span className="muted">—</span>}</td>
			<td>{fmtDate(grant.createdAt)}</td>
			<td className="row-actions">
				<button type="button" className="danger small" onClick={() => setConfirming(true)}>Revoke</button>
				{confirming && (
					<ConfirmDialog
						title="Revoke grant"
						confirmLabel="Revoke"
						body={
							<p>
								Revoke the <code>{grant.roleKey}</code> grant scoped to <strong>{scopeLabel}</strong>? This is immediate and audited.
							</p>
						}
						onConfirm={revoke}
						onClose={() => setConfirming(false)}
					/>
				)}
			</td>
		</tr>
	)
}

interface AddGrantFormProps {
	principalId: string
	roles: RoleDto[]
	projects: ProjectDto[]
	apps: AppDto[]
	onDone: () => void
}

function AddGrantForm({ principalId, roles, projects, apps, onDone }: AddGrantFormProps) {
	const [roleKey, setRoleKey] = useState('')
	const [scope, setScope] = useState<ScopeValue>({ kind: 'unset' })
	const [appValue, setAppValue] = useState<AppValue>({ kind: 'unset' })
	const [expiry, setExpiry] = useState('')
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)

	async function submit(e: React.FormEvent) {
		e.preventDefault()
		setError(null)
		if (roleKey === '') {
			setError('Pick a role.')
			return
		}
		let projectId: string | null
		try {
			projectId = resolveScope(scope)
		} catch {
			setError('Pick a scope.')
			return
		}
		let app: string | null
		try {
			app = resolveApp(appValue)
		} catch {
			setError('Pick an app.')
			return
		}
		setBusy(true)
		try {
			const body: CreateGrantRequest = { principalId, roleKey, projectId, app, expiresAt: parseDateTimeLocal(expiry) }
			await api.post('/grants', body)
			setRoleKey('')
			setScope({ kind: 'unset' })
			setAppValue({ kind: 'unset' })
			setExpiry('')
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Grant failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<form className="panel form" onSubmit={submit}>
			<h2>Add grant</h2>
			<label>
				Role
				<RolePicker roles={roles} value={roleKey} onChange={setRoleKey} />
			</label>
			<AppPicker apps={apps} value={appValue} onChange={setAppValue} idPrefix="grant-app" />
			<ScopePicker projects={projects} value={scope} onChange={setScope} idPrefix="grant-scope" />
			<label>
				Expires (optional)
				<input type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
			</label>
			{error && <p className="error-text" role="alert">{error}</p>}
			<div className="form-actions">
				<button type="submit" className="primary" disabled={busy}>{busy ? 'Granting…' : 'Add grant'}</button>
			</div>
		</form>
	)
}
