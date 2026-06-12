import { createPage, useNavigate } from '@buzola/router'
import type { AppDto, AppSchemaDto, CreatePolicyRequest, ListResponse, PolicyDto, UpdatePolicyRequest } from '@propustka/worker/admin'
import { useState } from 'react'
import { ActionPicker } from '../../components/ActionPicker'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { Table } from '../../components/Table'
import { api, ApiError } from '../../lib/api'
import { fmtDate } from '../../lib/format'

/**
 * Custom policies (origin='custom' roles) for one app. The app is chosen via the `?app`
 * query param; without it, the page prompts to pick one. Policies are per-app — they can't
 * be cross-app — so this is a concrete app picker, not the all-apps one.
 */
export default createPage()
	.params({ app: '?string' })
	.loader(async ({ params }) => {
		const apps = await api.get<ListResponse<AppDto>>('/apps')
		const app = params.app && apps.items.some((a) => a.id === params.app) ? params.app : null
		if (app === null) {
			return { apps: apps.items, app: null, policies: [], schema: null }
		}
		const [policies, schema] = await Promise.all([
			api.get<ListResponse<PolicyDto>>(`/apps/${encodeURIComponent(app)}/policies`),
			api.get<AppSchemaDto>(`/apps/${encodeURIComponent(app)}/schema`),
		])
		return { apps: apps.items, app, policies: policies.items, schema }
	})
	.route('/policies')
	.render(({ data, invalidate }) => {
		const navigate = useNavigate()

		return (
			<>
				<div className="page-head">
					<h1>Policies</h1>
					<p className="hint">
						Admin-composed named permission sets (origin <code>custom</code>) for one app, built from its action catalog. Grantable like any role.
					</p>
				</div>

				<div className="toolbar">
					<label>
						App{' '}
						<select
							value={data.app ?? ''}
							onChange={(e) => navigate('policies', { params: { app: e.target.value || undefined }, replace: true })}
						>
							<option value="">Select an app…</option>
							{data.apps.map((a) => <option key={a.id} value={a.id}>{a.id}</option>)}
						</select>
					</label>
				</div>

				{data.app === null
					? <p className="hint">Pick an app to manage its custom policies.</p>
					: (
						<>
							<CreatePolicyForm app={data.app} actions={data.schema?.actions ?? []} onDone={invalidate} />

							<Table
								colSpan={4}
								isEmpty={data.policies.length === 0}
								empty="No custom policies for this app yet."
								head={
									<tr>
										<th>Key</th>
										<th>Name</th>
										<th>Permissions</th>
										<th />
									</tr>
								}
							>
								{data.policies.map((policy) => (
									<PolicyRow
										key={policy.key}
										app={data.app}
										policy={policy}
										actions={data.schema?.actions ?? []}
										onDone={invalidate}
									/>
								))}
							</Table>
						</>
					)}
			</>
		)
	})

function CreatePolicyForm(
	{ app, actions, onDone }: { app: string; actions: AppSchemaDto['actions']; onDone: () => void },
) {
	const [key, setKey] = useState('')
	const [name, setName] = useState('')
	const [description, setDescription] = useState('')
	const [permissions, setPermissions] = useState<string[]>([])
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)

	async function submit(e: React.FormEvent) {
		e.preventDefault()
		setError(null)
		if (permissions.length === 0) {
			setError('Pick at least one action.')
			return
		}
		setBusy(true)
		try {
			const body: CreatePolicyRequest = {
				key: key.trim(),
				name: name.trim(),
				...(description.trim() === '' ? {} : { description: description.trim() }),
				permissions,
			}
			await api.post(`/apps/${encodeURIComponent(app)}/policies`, body)
			setKey('')
			setName('')
			setDescription('')
			setPermissions([])
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Create failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<form className="panel form" onSubmit={submit}>
			<h2>Create policy</h2>
			<label>
				Key
				<input value={key} onChange={(e) => setKey(e.target.value)} required placeholder="report-publisher" />
			</label>
			<label>
				Name
				<input value={name} onChange={(e) => setName(e.target.value)} required placeholder="Report publisher" />
			</label>
			<label>
				Description (optional)
				<input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Can read and publish reports" />
			</label>
			<ActionPicker actions={actions} value={permissions} onChange={setPermissions} idPrefix="new-policy-action" />
			{error && <p className="error-text" role="alert">{error}</p>}
			<div className="form-actions">
				<button type="submit" className="primary" disabled={busy}>{busy ? 'Creating…' : 'Create policy'}</button>
			</div>
		</form>
	)
}

function PolicyRow(
	{ app, policy, actions, onDone }: { app: string; policy: PolicyDto; actions: AppSchemaDto['actions']; onDone: () => void },
) {
	const [editing, setEditing] = useState(false)
	const [confirming, setConfirming] = useState(false)
	const [name, setName] = useState(policy.name)
	const [description, setDescription] = useState(policy.description ?? '')
	const [permissions, setPermissions] = useState<string[]>(policy.permissions)
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)

	async function save(e: React.FormEvent) {
		e.preventDefault()
		setError(null)
		if (permissions.length === 0) {
			setError('Pick at least one action.')
			return
		}
		setBusy(true)
		try {
			const body: UpdatePolicyRequest = {
				name: name.trim(),
				...(description.trim() === '' ? {} : { description: description.trim() }),
				permissions,
			}
			await api.put(`/apps/${encodeURIComponent(app)}/policies/${encodeURIComponent(policy.key)}`, body)
			setEditing(false)
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Save failed.')
		} finally {
			setBusy(false)
		}
	}

	async function remove() {
		await api.del(`/apps/${encodeURIComponent(app)}/policies/${encodeURIComponent(policy.key)}`)
		onDone()
	}

	if (editing) {
		return (
			<tr>
				<td>
					<code>{policy.key}</code>
				</td>
				<td colSpan={3}>
					<form className="inline-edit-form" onSubmit={save}>
						<label>
							Name
							<input value={name} onChange={(e) => setName(e.target.value)} required />
						</label>
						<label>
							Description
							<input value={description} onChange={(e) => setDescription(e.target.value)} />
						</label>
						<ActionPicker actions={actions} value={permissions} onChange={setPermissions} idPrefix={`edit-${policy.key}-action`} />
						{error && <p className="error-text" role="alert">{error}</p>}
						<div className="form-actions">
							<button type="submit" className="small primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
							<button
								type="button"
								className="small"
								onClick={() => {
									setEditing(false)
									setName(policy.name)
									setDescription(policy.description ?? '')
									setPermissions(policy.permissions)
									setError(null)
								}}
								disabled={busy}
							>
								Cancel
							</button>
						</div>
					</form>
				</td>
			</tr>
		)
	}

	return (
		<tr>
			<td>
				<code>{policy.key}</code>
				<div className="muted small">{fmtDate(policy.createdAt)}</div>
			</td>
			<td>
				{policy.name}
				{policy.description && <div className="muted small">{policy.description}</div>}
			</td>
			<td>{policy.permissions.map((p) => <code key={p} className="perm-chip">{p}</code>)}</td>
			<td className="row-actions">
				<button type="button" className="small" onClick={() => setEditing(true)}>Edit</button>
				<button type="button" className="danger small" onClick={() => setConfirming(true)}>Delete</button>
				{confirming && (
					<ConfirmDialog
						title="Delete policy"
						confirmLabel="Delete"
						body={
							<p>
								Delete the custom policy <code>{policy.key}</code>? Existing grants referencing it will become dangling.
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
