import type { ReactNode } from 'react'
import { useState } from 'react'
import { ApiError } from '../lib/api'
import { Modal } from './Modal'

interface ConfirmDialogProps {
	title: string
	/** Names the target of the destructive action. */
	body: ReactNode
	confirmLabel?: string
	onConfirm: () => Promise<void>
	onClose: () => void
}

/** A small confirm dialog for revoke / disable / destructive actions. */
export function ConfirmDialog({ title, body, confirmLabel = 'Confirm', onConfirm, onClose }: ConfirmDialogProps) {
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState<string | null>(null)

	async function confirm() {
		setBusy(true)
		setError(null)
		try {
			await onConfirm()
			onClose()
		} catch (cause) {
			setError(cause instanceof ApiError ? cause.message : 'Action failed.')
			setBusy(false)
		}
	}

	return (
		<Modal title={title} onClose={busy ? undefined : onClose}>
			<div className="confirm-body">{body}</div>
			{error && <p className="error-text" role="alert">{error}</p>}
			<div className="modal-actions">
				<button type="button" onClick={onClose} disabled={busy}>Cancel</button>
				<button type="button" className="danger" onClick={confirm} disabled={busy}>
					{busy ? 'Working…' : confirmLabel}
				</button>
			</div>
		</Modal>
	)
}
