import { createPage } from '@buzola/router'
import type { CreateProjectRequest, ListResponse, ProjectDto, UpdateProjectRequest } from '@propustka/worker/admin'
import { useState } from 'react'
import { Table } from '../../components/Table'
import { api, ApiError } from '../../lib/api'
import { fmtDate } from '../../lib/format'

export default createPage()
	.loader(async () => {
		const projects = await api.get<ListResponse<ProjectDto>>('/projects')
		return { projects: projects.items }
	})
	.route('/projects')
	.render(({ data, invalidate }) => (
		<>
			<div className="page-head">
				<h1>Projects</h1>
				<p className="hint">
					Projects scope grants and mappings. Admin-managed; no delete in v1 (projects are referenced by grants and mappings).
				</p>
			</div>

			<CreateProjectForm onDone={invalidate} />

			<Table
				colSpan={4}
				isEmpty={data.projects.length === 0}
				empty="No projects yet."
				head={
					<tr>
						<th>Slug</th>
						<th>Name</th>
						<th>Created</th>
						<th />
					</tr>
				}
			>
				{data.projects.map((project) => <ProjectRow key={project.id} project={project} onDone={invalidate} />)}
			</Table>
		</>
	))

function CreateProjectForm({ onDone }: { onDone: () => void }) {
	const [slug, setSlug] = useState('')
	const [name, setName] = useState('')
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)

	async function submit(e: React.FormEvent) {
		e.preventDefault()
		setError(null)
		setBusy(true)
		try {
			const body: CreateProjectRequest = { slug: slug.trim(), name: name.trim() }
			await api.post('/projects', body)
			setSlug('')
			setName('')
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Create failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<form className="panel form inline" onSubmit={submit}>
			<h2>Create project</h2>
			<label>
				Slug
				<input value={slug} onChange={(e) => setSlug(e.target.value)} required placeholder="acme" />
			</label>
			<label>
				Name
				<input value={name} onChange={(e) => setName(e.target.value)} required placeholder="Acme Corp" />
			</label>
			{error && <p className="error-text" role="alert">{error}</p>}
			<button type="submit" className="primary" disabled={busy}>{busy ? 'Creating…' : 'Create'}</button>
		</form>
	)
}

function ProjectRow({ project, onDone }: { project: ProjectDto; onDone: () => void }) {
	const [editing, setEditing] = useState(false)
	const [name, setName] = useState(project.name)
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)

	async function save(e: React.FormEvent) {
		e.preventDefault()
		setError(null)
		setBusy(true)
		try {
			const body: UpdateProjectRequest = { name: name.trim() }
			await api.patch(`/projects/${project.id}`, body)
			setEditing(false)
			onDone()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Rename failed.')
		} finally {
			setBusy(false)
		}
	}

	return (
		<tr>
			<td>
				<code>{project.slug}</code>
			</td>
			<td>
				{editing
					? (
						<form className="inline-edit" onSubmit={save}>
							<input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
							<button type="submit" className="small primary" disabled={busy}>Save</button>
							<button
								type="button"
								className="small"
								onClick={() => {
									setEditing(false)
									setName(project.name)
								}}
								disabled={busy}
							>
								Cancel
							</button>
							{error && <span className="error-text small">{error}</span>}
						</form>
					)
					: project.name}
			</td>
			<td>{fmtDate(project.createdAt)}</td>
			<td className="row-actions">
				{!editing && <button type="button" className="small" onClick={() => setEditing(true)}>Rename</button>}
			</td>
		</tr>
	)
}
