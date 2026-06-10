import type {
	CreateGroupMappingRequest,
	GroupMappingDto,
	ListResponse,
	ProjectDto,
	RoleDto,
} from '@propustka/worker/admin'
import { createPage } from '@buzola/router'
import { useState } from 'react'
import { Badge } from '../../components/Badge'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { RolePicker } from '../../components/RolePicker'
import { type ScopeValue, resolveScope, ScopePicker } from '../../components/ScopePicker'
import { Table } from '../../components/Table'
import { ApiError, api } from '../../lib/api'

export default createPage()
	.loader(async () => {
		const [mappings, roles, projects] = await Promise.all([
			api.get<ListResponse<GroupMappingDto>>('/group-mappings'),
			api.get<ListResponse<RoleDto>>('/roles'),
			api.get<ListResponse<ProjectDto>>('/projects'),
		])
		return { mappings: mappings.items, roles: roles.items, projects: projects.items }
	})
	.route('/group-mappings')
	.render(({ data, invalidate }) => {
		const projectName = (id: string | null): string => {
			if (id === null) return 'Global'
			const match = data.projects.find((p) => p.id === id)
			return match ? `${match.name} (${match.slug})` : id
		}

		return (
			<>
				<div className="page-head">
					<h1>Group mappings</h1>
					<p className="hint">
						Map an IdP group to a role. These are applied <strong>at login time, not live</strong>:
						removing a mapping takes effect on the next <code>authenticate()</code> within cache
						TTL, and removing team membership only after the user's Access session refreshes.
					</p>
				</div>

				<CreateMappingForm roles={data.roles} projects={data.projects} onDone={invalidate} />

				<Table
					colSpan={5}
					isEmpty={data.mappings.length === 0}
					empty="No group mappings yet."
					head={
						<tr>
							<th>Provider</th>
							<th>Group ref</th>
							<th>Role</th>
							<th>Scope</th>
							<th />
						</tr>
					}
				>
					{data.mappings.map((mapping) => (
						<MappingRow
							key={mapping.id}
							mapping={mapping}
							scopeLabel={projectName(mapping.projectId)}
							onDone={invalidate}
						/>
					))}
				</Table>
			</>
		)
	})

function CreateMappingForm({ roles, projects, onDone }: { roles: RoleDto[]; projects: ProjectDto[]; onDone: () => void }) {
	const [groupRef, setGroupRef] = useState('')
	const [roleKey, setRoleKey] = useState('')
	const [scope, setScope] = useState<ScopeValue>({ kind: 'unset' })
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
		setBusy(true)
		try {
			const body: CreateGroupMappingRequest = {
				provider: 'github',
				groupRef: groupRef.trim(),
				roleKey,
				projectId,
			}
			await api.post('/group-mappings', body)
			setGroupRef('')
			setRoleKey('')
			setScope({ kind: 'unset' })
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Create failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<form className="panel form" onSubmit={submit}>
			<h2>Create mapping</h2>
			<label>
				Provider
				<select value="github" disabled>
					<option value="github">github</option>
				</select>
			</label>
			<label>
				Group ref
				<input
					value={groupRef}
					onChange={(e) => setGroupRef(e.target.value)}
					required
					placeholder="acme-org/platform-team"
				/>
				<span className="hint">
					Use the <code>&lt;org&gt;/&lt;team&gt;</code> form, lowercased, so it matches the
					normalized identity data.
				</span>
			</label>
			<label>
				Role
				<RolePicker roles={roles} value={roleKey} onChange={setRoleKey} />
			</label>
			<ScopePicker projects={projects} value={scope} onChange={setScope} idPrefix="mapping-scope" />
			{error && <p className="error-text" role="alert">{error}</p>}
			<div className="form-actions">
				<button type="submit" className="primary" disabled={busy}>{busy ? 'Creating…' : 'Create mapping'}</button>
			</div>
		</form>
	)
}

function MappingRow({ mapping, scopeLabel, onDone }: { mapping: GroupMappingDto; scopeLabel: string; onDone: () => void }) {
	const [confirming, setConfirming] = useState(false)

	async function remove() {
		await api.del(`/group-mappings/${mapping.id}`)
		onDone()
	}

	return (
		<tr>
			<td>{mapping.provider}</td>
			<td><code>{mapping.groupRef}</code></td>
			<td>
				<code>{mapping.roleKey}</code>
				{mapping.dangling && (
					<Badge tone="bad" title="This role_key is no longer in the code role registry.">dangling</Badge>
				)}
			</td>
			<td>{scopeLabel}</td>
			<td className="row-actions">
				<button type="button" className="danger small" onClick={() => setConfirming(true)}>Delete</button>
				{confirming && (
					<ConfirmDialog
						title="Delete mapping"
						confirmLabel="Delete"
						body={
							<p>
								Delete the mapping <code>{mapping.groupRef}</code> → <code>{mapping.roleKey}</code>?
								Takes effect at the next login within cache TTL.
							</p>
						}
						onConfirm={remove}
						onClose={() => setConfirming(false)}
					/>
				)}
			</td>
		</tr>
	)
}
