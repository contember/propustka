import { useState } from 'react'

interface CopyFieldProps {
	label: string
	value: string
	/** When true, render in a monospace block (for long secrets/tokens). */
	multiline?: boolean
}

/**
 * A read-only field with a copy-to-clipboard button. The value is rendered as plain
 * copyable text only — never as a navigable link — so a token can't leak via Referer.
 */
export function CopyField({ label, value, multiline }: CopyFieldProps) {
	const [copied, setCopied] = useState(false)

	async function copy() {
		try {
			await navigator.clipboard.writeText(value)
			setCopied(true)
			setTimeout(() => setCopied(false), 1500)
		} catch {
			// Clipboard may be unavailable (insecure context); the value is still selectable.
		}
	}

	return (
		<div className="copy-field">
			<label>{label}</label>
			<div className="copy-row">
				{multiline
					? <code className="copy-value block">{value}</code>
					: <code className="copy-value">{value}</code>}
				<button type="button" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
			</div>
		</div>
	)
}
