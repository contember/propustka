import type {
	CapabilityListItem,
	IssueCapabilityRequest,
	IssuedCapabilityResponse,
	ListResponse,
	ProjectDto,
} from '@propustka/worker/admin'
import { createPage } from '@buzola/router'
import { useState } from 'react'
import { Badge } from '../../components/Badge'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { SecretModal } from '../../components/SecretModal'
import { Table } from '../../components/Table'
import { ApiError, api } from '../../lib/api'
import { fmtExpiry, parseDateTimeLocal } from '../../lib/format'

/** Known capability resource-type prefixes (app-owned shared namespace). */
const RESOURCE_HINTS = ['report:', 'invoice:', 'export:']

type CapStatus = 'active' | 'expired' | 'revoked' | 'exhausted'

function capStatus(cap: CapabilityListItem): CapStatus {
	if (cap.revokedAt !== null) return 'revoked'
	if (cap.expiresAt !== null && cap.expiresAt <= Date.now()) return 'expired'
	if (cap.maxUses !== null && cap.usedCount >= cap.maxUses) return 'exhausted'
	return 'active'
}

export default createPage()
	.loader(async () => {
		const [capabilities, projects] = await Promise.all([
			api.get<ListResponse<CapabilityListItem>>('/capabilities'),
			api.get<ListResponse<ProjectDto>>('/projects'),
		])
		return { capabilities: capabilities.items, projects: projects.items }
	})
	.route('/capabilities')
	.render(({ data, invalidate }) => (
		<>
			<div className="page-head">
				<h1>Capabilities</h1>
				<p className="hint">
					Scoped, short-lived tokens granting specific <code>(action, resource)</code> pairs.
					Resources are an app-owned shared namespace. Token plaintext is shown once at issue and never stored.
				</p>
			</div>

			<IssueForm projects={data.projects} onDone={invalidate} />

			<Table
				colSpan={6}
				isEmpty={data.capabilities.length === 0}
				empty="No capability tokens issued yet."
				head={
					<tr>
						<th>Label</th>
						<th>Grants</th>
						<th>Expires</th>
						<th>Uses</th>
						<th>Status</th>
						<th />
					</tr>
				}
			>
				{data.capabilities.map((cap) => (
					<CapabilityRow key={cap.id} cap={cap} onDone={invalidate} />
				))}
			</Table>
		</>
	))

function CapabilityRow({ cap, onDone }: { cap: CapabilityListItem; onDone: () => void }) {
	const [confirming, setConfirming] = useState(false)
	const status = capStatus(cap)
	const tone = status === 'active' ? 'good' : status === 'revoked' ? 'bad' : 'muted'

	async function revoke() {
		await api.del(`/capabilities/${cap.id}`)
		onDone()
	}

	return (
		<tr>
			<td>{cap.label ?? <span className="muted">—</span>}</td>
			<td>
				{cap.grants.map((g, i) => (
					<div key={`${g.action}:${g.resource}:${i}`} className="grant-chip">
						<code>{g.action}</code> <span className="muted">on</span> <code>{g.resource}</code>
					</div>
				))}
			</td>
			<td>{fmtExpiry(cap.expiresAt)}</td>
			<td>{cap.usedCount}{cap.maxUses !== null ? ` / ${cap.maxUses}` : ''}</td>
			<td><Badge tone={tone}>{status}</Badge></td>
			<td className="row-actions">
				{status !== 'revoked' && (
					<button type="button" className="danger small" onClick={() => setConfirming(true)}>Revoke</button>
				)}
				{confirming && (
					<ConfirmDialog
						title="Revoke capability"
						confirmLabel="Revoke"
						body={<p>Revoke the capability token <strong>{cap.label ?? cap.id}</strong>? Effective immediately.</p>}
						onConfirm={revoke}
						onClose={() => setConfirming(false)}
					/>
				)}
			</td>
		</tr>
	)
}

interface GrantRow {
	action: string
	resource: string
	projectId: string
}

function IssueForm({ projects, onDone }: { projects: ProjectDto[]; onDone: () => void }) {
	const [rows, setRows] = useState<GrantRow[]>([{ action: '', resource: '', projectId: '' }])
	const [label, setLabel] = useState('')
	const [expiry, setExpiry] = useState('')
	const [maxUses, setMaxUses] = useState('')
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)
	const [token, setToken] = useState<IssuedCapabilityResponse | null>(null)

	function updateRow(index: number, patch: Partial<GrantRow>) {
		setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ...patch } : row)))
	}
	function addRow() {
		setRows((prev) => [...prev, { action: '', resource: '', projectId: '' }])
	}
	function removeRow(index: number) {
		setRows((prev) => (prev.length === 1 ? prev : prev.filter((_, i) => i !== index)))
	}

	async function submit(e: React.FormEvent) {
		e.preventDefault()
		setError(null)

		const grants = rows
			.map((row) => ({ action: row.action.trim(), resource: row.resource.trim(), projectId: row.projectId }))
			.filter((row) => row.action !== '' || row.resource !== '')
		if (grants.length === 0) {
			setError('Add at least one (action, resource) grant.')
			return
		}
		if (grants.some((g) => g.action === '' || g.resource === '')) {
			setError('Each grant needs both an action and a resource.')
			return
		}

		const maxUsesNum = maxUses.trim() === '' ? undefined : Number(maxUses)
		if (maxUsesNum !== undefined && (!Number.isInteger(maxUsesNum) || maxUsesNum < 1)) {
			setError('Max uses must be a positive whole number.')
			return
		}

		const expiresAt = parseDateTimeLocal(expiry)

		const body: IssueCapabilityRequest = {
			grants: grants.map((g) => ({
				action: g.action,
				resource: g.resource,
				projectId: g.projectId === '' ? null : g.projectId,
			})),
			...(label.trim() === '' ? {} : { label: label.trim() }),
			...(expiresAt === null ? {} : { expiresAt }),
			...(maxUsesNum === undefined ? {} : { maxUses: maxUsesNum }),
		}

		setBusy(true)
		try {
			const result = await api.post<IssuedCapabilityResponse>('/capabilities', body)
			setToken(result)
			setRows([{ action: '', resource: '', projectId: '' }])
			setLabel('')
			setExpiry('')
			setMaxUses('')
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Issue failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<>
			<form className="panel form" onSubmit={submit}>
				<h2>Issue capability</h2>
				<div className="grant-rows">
					<div className="grant-rows-head">
						<span>Action</span>
						<span>Resource</span>
						<span>Project (delegation check)</span>
						<span />
					</div>
					{rows.map((row, i) => (
						<div className="grant-row" key={i}>
							<input
								aria-label="Action"
								value={row.action}
								onChange={(e) => updateRow(i, { action: e.target.value })}
								placeholder="report.read"
							/>
							<input
								aria-label="Resource"
								value={row.resource}
								onChange={(e) => updateRow(i, { resource: e.target.value })}
								placeholder="report:q3-2025"
								list="resource-hints"
							/>
							<select
								aria-label="Project"
								value={row.projectId}
								onChange={(e) => updateRow(i, { projectId: e.target.value })}
							>
								<option value="">Global</option>
								{projects.map((p) => (
									<option key={p.id} value={p.id}>{p.name} ({p.slug})</option>
								))}
							</select>
							<button type="button" className="small" onClick={() => removeRow(i)} disabled={rows.length === 1}>
								Remove
							</button>
						</div>
					))}
					<datalist id="resource-hints">
						{RESOURCE_HINTS.map((hint) => <option key={hint} value={hint} />)}
					</datalist>
					<button type="button" className="small" onClick={addRow}>+ Add grant</button>
					<p className="hint">Known resource-type prefixes: {RESOURCE_HINTS.map((h) => <code key={h}>{h}</code>)}</p>
				</div>
				<label>
					Label (optional)
					<input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Q3 report share" />
				</label>
				<label>
					Expires (optional)
					<input type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
				</label>
				<label>
					Max uses (optional)
					<input type="number" min={1} step={1} value={maxUses} onChange={(e) => setMaxUses(e.target.value)} placeholder="unlimited" />
				</label>
				{error && <p className="error-text" role="alert">{error}</p>}
				<div className="form-actions">
					<button type="submit" className="primary" disabled={busy}>{busy ? 'Issuing…' : 'Issue capability'}</button>
				</div>
			</form>
			{token && (
				<SecretModal
					title="Capability issued"
					fields={[{ label: 'Token', value: token.token, multiline: true }]}
					note={<p className="hint">Hand this token to the holder over a trusted channel. It is the only secret — anyone with it can redeem the granted actions.</p>}
					onClose={() => setToken(null)}
				/>
			)}
		</>
	)
}
