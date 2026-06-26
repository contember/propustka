import { createPage } from '@buzola/router'
import type { IssuedShareLinkResponse, IssueShareLinkRequest, ListResponse, ShareLinkListItem } from '@propustka/worker/admin'
import { useState } from 'react'
import { Badge } from '../../components/Badge'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { SecretModal } from '../../components/SecretModal'
import { Table } from '../../components/Table'
import { api, ApiError } from '../../lib/api'
import { fmtExpiry, parseDateTimeLocal } from '../../lib/format'

type LinkStatus = 'active' | 'expired' | 'revoked'

function linkStatus(link: ShareLinkListItem): LinkStatus {
	if (link.revokedAt !== null) return 'revoked'
	// expiresAt is epoch-seconds (backend `unixepoch()`), so compare in seconds.
	if (link.expiresAt !== null && link.expiresAt <= Date.now() / 1000) return 'expired'
	return 'active'
}

export default createPage()
	.loader(async () => {
		const shareLinks = await api.get<ListResponse<ShareLinkListItem>>('/share-links')
		return { shareLinks: shareLinks.items }
	})
	.route('/share-links')
	.render(({ data, invalidate }) => (
		<>
			<div className="page-head">
				<h1>Share links</h1>
				<p className="hint">
					Anonymous, revocable <code>px_</code> credentials granting specific <code>(action, scope)</code> permissions — matched by <code>permits()</code>
					{' '}
					at use time, like any other token. Carry the link in a URL path or header; the plaintext is shown once at issue and never stored.
				</p>
			</div>

			<IssueForm onDone={invalidate} />

			<Table
				colSpan={5}
				isEmpty={data.shareLinks.length === 0}
				empty="No share links issued yet."
				head={
					<tr>
						<th>Label</th>
						<th>Grants</th>
						<th>Expires</th>
						<th>Status</th>
						<th />
					</tr>
				}
			>
				{data.shareLinks.map((link) => <ShareLinkRow key={link.id} link={link} onDone={invalidate} />)}
			</Table>
		</>
	))

function ShareLinkRow({ link, onDone }: { link: ShareLinkListItem; onDone: () => void }) {
	const [confirming, setConfirming] = useState(false)
	const status = linkStatus(link)
	const tone = status === 'active' ? 'good' : status === 'revoked' ? 'bad' : 'muted'

	async function revoke() {
		await api.del(`/share-links/${link.id}`)
		onDone()
	}

	return (
		<tr>
			<td>{link.label ?? <span className="muted">—</span>}</td>
			<td>
				{link.grants.map((g, i) => (
					<div key={`${g.action}:${g.scope?.type ?? ''}:${g.scope?.value ?? ''}:${i}`} className="grant-chip">
						<code>{g.action}</code>
						{g.scope
							? (
								<>
									{' '}
									<span className="muted">on</span> <code>{g.scope.type}={g.scope.value}</code>
								</>
							)
							: (
								<>
									{' '}
									<span className="muted">(global)</span>
								</>
							)}
					</div>
				))}
			</td>
			<td>{fmtExpiry(link.expiresAt)}</td>
			<td>
				<Badge tone={tone}>{status}</Badge>
			</td>
			<td className="row-actions">
				{status !== 'revoked' && <button type="button" className="danger small" onClick={() => setConfirming(true)}>Revoke</button>}
				{confirming && (
					<ConfirmDialog
						title="Revoke share link"
						confirmLabel="Revoke"
						body={
							<p>
								Revoke the share link <strong>{link.label ?? link.id}</strong>? Effective immediately.
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

interface GrantRow {
	action: string
	/** Scope dimension; both-or-neither with `scopeValue` (both empty = global). */
	scopeType: string
	scopeValue: string
}

const EMPTY_ROW: GrantRow = { action: '', scopeType: '', scopeValue: '' }

function IssueForm({ onDone }: { onDone: () => void }) {
	const [rows, setRows] = useState<GrantRow[]>([{ ...EMPTY_ROW }])
	const [label, setLabel] = useState('')
	const [expiry, setExpiry] = useState('')
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)
	const [token, setToken] = useState<IssuedShareLinkResponse | null>(null)

	function updateRow(index: number, patch: Partial<GrantRow>) {
		setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ...patch } : row)))
	}
	function addRow() {
		setRows((prev) => [...prev, { ...EMPTY_ROW }])
	}
	function removeRow(index: number) {
		setRows((prev) => (prev.length === 1 ? prev : prev.filter((_, i) => i !== index)))
	}

	async function submit(e: React.FormEvent) {
		e.preventDefault()
		setError(null)

		const grants = rows
			.map((row) => ({
				action: row.action.trim(),
				scopeType: row.scopeType.trim(),
				scopeValue: row.scopeValue.trim(),
			}))
			.filter((row) => row.action !== '' || row.scopeType !== '' || row.scopeValue !== '')
		if (grants.length === 0) {
			setError('Add at least one grant.')
			return
		}
		if (grants.some((g) => g.action === '')) {
			setError('Each grant needs an action.')
			return
		}
		if (grants.some((g) => (g.scopeType === '') !== (g.scopeValue === ''))) {
			setError('A scope needs both a dimension and a value, or leave both empty for a global grant.')
			return
		}

		const expiresAt = parseDateTimeLocal(expiry)

		const body: IssueShareLinkRequest = {
			grants: grants.map((g) => ({
				action: g.action,
				scope: g.scopeType === '' ? null : { type: g.scopeType, value: g.scopeValue },
			})),
			...(label.trim() === '' ? {} : { label: label.trim() }),
			...(expiresAt === null ? {} : { expiresAt }),
		}

		setBusy(true)
		try {
			const result = await api.post<IssuedShareLinkResponse>('/share-links', body)
			setToken(result)
			setRows([{ ...EMPTY_ROW }])
			setLabel('')
			setExpiry('')
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Issue failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<>
			<form className="panel form wide" onSubmit={submit}>
				<h2>Issue share link</h2>
				<div className="grant-rows">
					<div className="grant-rows-head">
						<span>Action</span>
						<span>Scope dimension (optional)</span>
						<span>Scope value</span>
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
								aria-label="Scope dimension"
								value={row.scopeType}
								onChange={(e) => updateRow(i, { scopeType: e.target.value })}
								placeholder="tenant"
							/>
							<input
								aria-label="Scope value"
								value={row.scopeValue}
								onChange={(e) => updateRow(i, { scopeValue: e.target.value })}
								placeholder="acme"
							/>
							<button type="button" className="small" onClick={() => removeRow(i)} disabled={rows.length === 1}>
								Remove
							</button>
						</div>
					))}
					<button type="button" className="small" onClick={addRow}>+ Add grant</button>
					<p className="hint">
						The grant is matched by <code>permits()</code>{' '}
						at use time (action + scope). The issuer can only delegate what it itself holds; leave both scope fields empty for a global grant.
					</p>
				</div>
				<label>
					Label (optional)
					<input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Q3 report share" />
				</label>
				<label>
					Expires (optional)
					<input type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
				</label>
				{error && <p className="error-text" role="alert">{error}</p>}
				<div className="form-actions">
					<button type="submit" className="primary" disabled={busy}>{busy ? 'Issuing…' : 'Issue share link'}</button>
				</div>
			</form>
			{token && (
				<SecretModal
					title="Share link issued"
					fields={[{ label: 'Token', value: token.token, multiline: true }]}
					note={
						<p className="hint">
							Hand this token to the holder over a trusted channel. It is the only secret — anyone with it can perform the granted actions.
						</p>
					}
					onClose={() => setToken(null)}
				/>
			)}
		</>
	)
}
