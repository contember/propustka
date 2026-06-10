import { createPage, Link, useNavigate } from '@buzola/router'
import type { AuditEventDto, CursorList } from '@propustka/worker/admin'
import { useState } from 'react'
import { JsonView } from '../../components/JsonView'
import { Table } from '../../components/Table'
import { api } from '../../lib/api'
import { fmtDate, qs } from '../../lib/format'

const LIMIT = 50

interface FilterParams {
	resourceType?: string
	resourceId?: string
	principalId?: string
	action?: string
	requestId?: string
}

export default createPage()
	.params({
		resourceType: '?string',
		resourceId: '?string',
		principalId: '?string',
		action: '?string',
		requestId: '?string',
		before: '?string',
	})
	.loader(async ({ params }) => {
		const query = qs({
			resourceType: params.resourceType,
			resourceId: params.resourceId,
			principalId: params.principalId,
			action: params.action,
			requestId: params.requestId,
			before: params.before,
			limit: LIMIT,
		})
		const page = await api.get<CursorList<AuditEventDto>>(`/audit${query}`)
		return { page }
	})
	.route('/audit')
	.render(({ params, data }) => {
		const navigate = useNavigate()
		const events = data.page.items
		const current: FilterParams = {
			resourceType: params.resourceType,
			resourceId: params.resourceId,
			principalId: params.principalId,
			action: params.action,
			requestId: params.requestId,
		}

		function applyFilters(next: FilterParams) {
			// Reset the cursor whenever filters change.
			navigate('audit', { params: { ...next, before: undefined }, replace: true })
		}

		function nextPage() {
			if (data.page.nextCursor === null) return
			navigate('audit', { params: { ...current, before: data.page.nextCursor } })
		}

		return (
			<>
				<div className="page-head">
					<h1>Audit — domain events</h1>
					<p className="hint">Write operations recorded by the IAM Worker. Read-only.</p>
				</div>

				<AuditFilters params={current} onApply={applyFilters} />

				<Table
					colSpan={6}
					isEmpty={events.length === 0}
					empty="No audit events match."
					head={
						<tr>
							<th>When</th>
							<th>Actor</th>
							<th>App</th>
							<th>Action</th>
							<th>Resource</th>
							<th>Request</th>
						</tr>
					}
				>
					{events.map((event) => <AuditRow key={event.id} event={event} />)}
				</Table>

				<div className="pager">
					{params.before && <button type="button" onClick={() => applyFilters(current)}>First page</button>}
					<span className="pull" />
					<button type="button" onClick={nextPage} disabled={data.page.nextCursor === null}>
						Next page
					</button>
				</div>
			</>
		)
	})

function AuditFilters({ params, onApply }: { params: FilterParams; onApply: (next: FilterParams) => void }) {
	const [resourceType, setResourceType] = useState(params.resourceType ?? '')
	const [resourceId, setResourceId] = useState(params.resourceId ?? '')
	const [principalId, setPrincipalId] = useState(params.principalId ?? '')
	const [action, setAction] = useState(params.action ?? '')
	const [requestId, setRequestId] = useState(params.requestId ?? '')

	function submit(e: React.FormEvent) {
		e.preventDefault()
		onApply({ resourceType, resourceId, principalId, action, requestId })
	}
	function clear() {
		setResourceType('')
		setResourceId('')
		setPrincipalId('')
		setAction('')
		setRequestId('')
		onApply({})
	}

	return (
		<form className="panel filters" onSubmit={submit}>
			<label>
				Resource type<input value={resourceType} onChange={(e) => setResourceType(e.target.value)} />
			</label>
			<label>
				Resource id<input value={resourceId} onChange={(e) => setResourceId(e.target.value)} />
			</label>
			<label>
				Principal id<input value={principalId} onChange={(e) => setPrincipalId(e.target.value)} />
			</label>
			<label>
				Action<input value={action} onChange={(e) => setAction(e.target.value)} />
			</label>
			<label>
				Request id<input value={requestId} onChange={(e) => setRequestId(e.target.value)} />
			</label>
			<div className="filter-actions">
				<button type="submit" className="primary small">Filter</button>
				<button type="button" className="small" onClick={clear}>Clear</button>
			</div>
		</form>
	)
}

function AuditRow({ event }: { event: AuditEventDto }) {
	const [open, setOpen] = useState(false)
	const hasDetail = event.diff !== null && event.diff !== undefined
		|| event.metadata !== null && event.metadata !== undefined

	return (
		<>
			<tr>
				<td>{fmtDate(event.createdAt)}</td>
				<td>
					{event.capabilityTokenId
						? (
							<span title={event.capabilityTokenId}>
								capability <code className="small">{event.capabilityTokenId}</code>
							</span>
						)
						: event.principalLabel}
				</td>
				<td>{event.app}</td>
				<td>
					<code>{event.action}</code>
				</td>
				<td>
					<code>{event.resourceType}</code>
					{event.resourceId && <span className="muted">{' '}#{event.resourceId}</span>}
				</td>
				<td>
					<Link
						to="audit"
						params={{ requestId: event.requestId }}
						title="Filter to this request"
					>
						<code className="small">{event.requestId.slice(0, 8)}</code>
					</Link>
					{hasDetail && (
						<button type="button" className="link-btn small" onClick={() => setOpen((v) => !v)}>
							{open ? 'hide' : 'detail'}
						</button>
					)}
				</td>
			</tr>
			{open && hasDetail && (
				<tr className="detail-row">
					<td colSpan={6}>
						<div className="detail-grid">
							<div>
								<h4>diff</h4>
								<JsonView value={event.diff} />
							</div>
							<div>
								<h4>metadata</h4>
								<JsonView value={event.metadata} />
							</div>
						</div>
					</td>
				</tr>
			)}
		</>
	)
}
