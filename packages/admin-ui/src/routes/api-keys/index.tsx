import type {
	ApiKeyDto,
	GrantDto,
	ListResponse,
	ProjectDto,
	ProvisionApiKeyRequest,
	ProvisionApiKeyResponse,
	RoleDto,
	RotateApiKeyResponse,
} from '@propustka/worker/admin'
import { createPage } from '@buzola/router'
import { useState } from 'react'
import { StatusBadge } from '../../components/Badge'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { RolePicker } from '../../components/RolePicker'
import { type ScopeValue, resolveScope, ScopePicker } from '../../components/ScopePicker'
import { SecretModal } from '../../components/SecretModal'
import { Table } from '../../components/Table'
import { ApiError, api } from '../../lib/api'
import { fmtExpiry, parseDateTimeLocal } from '../../lib/format'

export default createPage()
	.loader(async () => {
		const [apiKeys, roles, projects] = await Promise.all([
			api.get<ListResponse<ApiKeyDto>>('/api-keys'),
			api.get<ListResponse<RoleDto>>('/roles'),
			api.get<ListResponse<ProjectDto>>('/projects'),
		])
		return { apiKeys: apiKeys.items, roles: roles.items, projects: projects.items }
	})
	.route('/api-keys')
	.render(({ data, invalidate }) => {
		const projectName = (id: string | null): string => {
			if (id === null) return 'Global'
			const match = data.projects.find((p) => p.id === id)
			return match ? `${match.name} (${match.slug})` : id
		}
		const grantSummary = (grants: GrantDto[]) => {
			if (grants.length === 0) return <span className="muted">no grants</span>
			return grants.map((g) => (
				<div key={g.id} className="grant-chip">
					<code>{g.roleKey}</code> <span className="muted">@ {projectName(g.projectId)}</span>
				</div>
			))
		}

		return (
			<>
				<div className="page-head">
					<h1>API keys</h1>
					<p className="hint">Service principals provisioned as Cloudflare Access service tokens. Secrets are never stored or shown after creation.</p>
				</div>

				<ProvisionForm roles={data.roles} projects={data.projects} onDone={invalidate} />

				<Table
					colSpan={5}
					isEmpty={data.apiKeys.length === 0}
					empty="No API keys provisioned yet."
					head={
						<tr>
							<th>Label</th>
							<th>Client id</th>
							<th>Status</th>
							<th>Role / scope · expiry</th>
							<th />
						</tr>
					}
				>
					{data.apiKeys.map((key) => (
						<tr key={key.principalId} className={key.clientId === null ? 'row-warn' : undefined}>
							<td>
								{key.label}
								{key.clientId === null && (
									<div className="warn-text small">
										Orphaned: no Access service token bound. Re-provisioning or manual reconciliation needed.
									</div>
								)}
							</td>
							<td>{key.clientId ? <code>{key.clientId}</code> : <span className="muted">—</span>}</td>
							<td><StatusBadge status={key.status} /></td>
							<td>
								{grantSummary(key.grants)}
								{key.grants.length > 0 && (
									<div className="muted small">
										expires: {key.grants.map((g) => fmtExpiry(g.expiresAt)).join(', ')}
									</div>
								)}
							</td>
							<td className="row-actions">
								<RotateButton apiKey={key} />
								<RevokeButton apiKey={key} onDone={invalidate} />
							</td>
						</tr>
					))}
				</Table>
			</>
		)
	})

function ProvisionForm({ roles, projects, onDone }: { roles: RoleDto[]; projects: ProjectDto[]; onDone: () => void }) {
	const [label, setLabel] = useState('')
	const [roleKey, setRoleKey] = useState('')
	const [scope, setScope] = useState<ScopeValue>({ kind: 'unset' })
	const [expiry, setExpiry] = useState('')
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)
	const [secret, setSecret] = useState<ProvisionApiKeyResponse | null>(null)

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
			const body: ProvisionApiKeyRequest = {
				label: label.trim(),
				type: 'service',
				roleKey,
				projectId,
				expiresAt: parseDateTimeLocal(expiry),
			}
			const result = await api.post<ProvisionApiKeyResponse>('/api-keys', body)
			setSecret(result)
			setLabel('')
			setRoleKey('')
			setScope({ kind: 'unset' })
			setExpiry('')
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Provisioning failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<>
			<form className="panel form" onSubmit={submit}>
				<h2>Provision API key</h2>
				<label>
					Label
					<input value={label} onChange={(e) => setLabel(e.target.value)} required placeholder="ci-deploy-bot" />
				</label>
				<label>
					Role
					<RolePicker roles={roles} value={roleKey} onChange={setRoleKey} />
				</label>
				<ScopePicker projects={projects} value={scope} onChange={setScope} idPrefix="apikey-scope" />
				<label>
					Expires (optional)
					<input type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
				</label>
				{error && <p className="error-text" role="alert">{error}</p>}
				<div className="form-actions">
					<button type="submit" className="primary" disabled={busy}>{busy ? 'Provisioning…' : 'Provision'}</button>
				</div>
			</form>
			{secret && (
				<SecretModal
					title="API key provisioned"
					fields={[
						{ label: 'Client ID', value: secret.clientId },
						{ label: 'Client secret', value: secret.clientSecret, multiline: true },
					]}
					note={
						secret.policyInclusion === 'manual'
							? (
								<p className="warn-text">
									<strong>Manual step required:</strong> this token was <em>not</em> added to the app's
									Service Auth policy automatically. Add the Client ID to the policy in the Cloudflare
									dashboard, or it won't be accepted.
								</p>
							)
							: undefined
					}
					onClose={() => setSecret(null)}
				/>
			)}
		</>
	)
}

function RotateButton({ apiKey }: { apiKey: ApiKeyDto }) {
	const [confirming, setConfirming] = useState(false)
	const [secret, setSecret] = useState<RotateApiKeyResponse | null>(null)

	async function rotate() {
		const result = await api.post<RotateApiKeyResponse>(`/api-keys/${apiKey.principalId}/rotate`)
		setSecret(result)
	}

	return (
		<>
			<button type="button" className="small" onClick={() => setConfirming(true)} disabled={apiKey.clientId === null}>
				Rotate
			</button>
			{confirming && (
				<ConfirmDialog
					title="Rotate secret"
					confirmLabel="Rotate"
					body={<p>Rotate the secret for <strong>{apiKey.label}</strong>? The old secret stops working immediately.</p>}
					onConfirm={rotate}
					onClose={() => setConfirming(false)}
				/>
			)}
			{secret && (
				<SecretModal
					title="Secret rotated"
					fields={[
						{ label: 'Client ID', value: secret.clientId },
						{ label: 'Client secret', value: secret.clientSecret, multiline: true },
					]}
					onClose={() => setSecret(null)}
				/>
			)}
		</>
	)
}

function RevokeButton({ apiKey, onDone }: { apiKey: ApiKeyDto; onDone: () => void }) {
	const [confirming, setConfirming] = useState(false)

	async function revoke() {
		await api.del(`/api-keys/${apiKey.principalId}`)
		onDone()
	}

	return (
		<>
			<button type="button" className="danger small" onClick={() => setConfirming(true)}>Revoke</button>
			{confirming && (
				<ConfirmDialog
					title="Revoke API key"
					confirmLabel="Revoke"
					body={
						<p>
							Revoke <strong>{apiKey.label}</strong>? This deletes the Access service token and its
							grants immediately — any caller using it stops working.
						</p>
					}
					onConfirm={revoke}
					onClose={() => setConfirming(false)}
				/>
			)}
		</>
	)
}
