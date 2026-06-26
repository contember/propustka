import { createPage, useNavigate } from '@buzola/router'
import type { AuthLogDto, CursorList } from '@propustka/worker/admin'
import { useState } from 'react'
import { Badge } from '../../components/Badge'
import { Table } from '../../components/Table'
import { api } from '../../lib/api'
import { fmtDate, qs } from '../../lib/format'

const LIMIT = 50

export default createPage()
	.params({
		principalId: '?string',
		requestId: '?string',
		decision: '?string',
		before: '?string',
	})
	.loader(async ({ params }) => {
		const query = qs({
			principalId: params.principalId,
			requestId: params.requestId,
			decision: params.decision,
			before: params.before,
			limit: LIMIT,
		})
		const page = await api.get<CursorList<AuthLogDto>>(`/auth-log${query}`)
		return { page }
	})
	.route('/audit/auth-log')
	.render(({ params, data }) => {
		const navigate = useNavigate()
		const rows = data.page.items

		function applyFilters(next: { principalId?: string; requestId?: string; decision?: string }) {
			navigate('audit/auth-log', {
				params: { ...next, before: undefined },
				replace: true,
			})
		}
		function nextPage() {
			if (data.page.nextCursor === null) return
			navigate('audit/auth-log', {
				params: {
					principalId: params.principalId,
					requestId: params.requestId,
					decision: params.decision,
					before: data.page.nextCursor,
				},
			})
		}

		return (
			<>
				<div className="page-head">
					<h1>Audit — auth log</h1>
					<p className="hint">
						Outcomes of <code>mintToken()</code> / <code>mintFromKey()</code> and the OIDC login. This is where you debug "login looks broken" — e.g.{' '}
						<code>invalid_token</code>, <code>unknown_principal</code>, or <code>disabled</code>.
					</p>
				</div>

				<AuthLogFilters params={params} onApply={applyFilters} />

				<Table
					colSpan={6}
					isEmpty={rows.length === 0}
					empty="No auth-log rows match."
					head={
						<tr>
							<th>When</th>
							<th>App</th>
							<th>Kind</th>
							<th>Principal / credential</th>
							<th>Decision</th>
							<th>Reason</th>
						</tr>
					}
				>
					{rows.map((row) => (
						<tr key={row.id}>
							<td>{fmtDate(row.createdAt)}</td>
							<td>{row.app}</td>
							<td>{row.kind}</td>
							<td>
								{row.credentialId
									? (
										<span title={row.credentialId}>
											credential <code className="small">{row.credentialId}</code>
										</span>
									)
									: row.principalId
									? <code className="small">{row.principalId}</code>
									: <span className="muted">—</span>}
							</td>
							<td>
								<Badge tone={row.decision === 'allow' ? 'good' : 'bad'}>{row.decision}</Badge>
							</td>
							<td>{row.reason ? <code className="small">{row.reason}</code> : <span className="muted">—</span>}</td>
						</tr>
					))}
				</Table>

				<div className="pager">
					{params.before && <button type="button" onClick={() => applyFilters(params)}>First page</button>}
					<span className="pull" />
					<button type="button" onClick={nextPage} disabled={data.page.nextCursor === null}>
						Next page
					</button>
				</div>
			</>
		)
	})

interface AuthFilterParams {
	principalId?: string
	requestId?: string
	decision?: string
}

function AuthLogFilters({ params, onApply }: { params: AuthFilterParams; onApply: (next: AuthFilterParams) => void }) {
	const [principalId, setPrincipalId] = useState(params.principalId ?? '')
	const [requestId, setRequestId] = useState(params.requestId ?? '')
	const [decision, setDecision] = useState(params.decision ?? '')

	function submit(e: React.FormEvent) {
		e.preventDefault()
		onApply({ principalId, requestId, decision: decision === '' ? undefined : decision })
	}
	function clear() {
		setPrincipalId('')
		setRequestId('')
		setDecision('')
		onApply({})
	}

	return (
		<form className="panel filters" onSubmit={submit}>
			<label>
				Principal id<input value={principalId} onChange={(e) => setPrincipalId(e.target.value)} />
			</label>
			<label>
				Request id<input value={requestId} onChange={(e) => setRequestId(e.target.value)} />
			</label>
			<label>
				Decision
				<select value={decision} onChange={(e) => setDecision(e.target.value)}>
					<option value="">Any</option>
					<option value="allow">allow</option>
					<option value="deny">deny</option>
				</select>
			</label>
			<div className="filter-actions">
				<button type="submit" className="primary small">Filter</button>
				<button type="button" className="small" onClick={clear}>Clear</button>
			</div>
		</form>
	)
}
