/** Read-only pretty-printed JSON. Renders nothing for null/undefined. */
export function JsonView({ value }: { value: unknown }) {
	if (value === null || value === undefined) return <span className="muted">—</span>
	let text: string
	try {
		text = JSON.stringify(value, null, 2)
	} catch {
		text = String(value)
	}
	if (text === undefined) return <span className="muted">—</span>
	return <pre className="json-view">{text}</pre>
}
