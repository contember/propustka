import type { ReactNode } from 'react'
import { CopyField } from './CopyField'
import { Modal } from './Modal'

interface SecretField {
	label: string
	value: string
	multiline?: boolean
}

interface SecretModalProps {
	title: string
	fields: SecretField[]
	/** Extra caveat copy (e.g. the manual Service-Auth-policy note). */
	note?: ReactNode
	onClose: () => void
}

/**
 * Blocking, once-shown secret/token display. The secret is never persisted, never put in
 * a URL or link — only rendered as copyable text. The user must explicitly acknowledge it
 * before the modal closes.
 */
export function SecretModal({ title, fields, note, onClose }: SecretModalProps) {
	return (
		<Modal title={title} blocking>
			<p className="warn-text">
				<strong>Copy this now.</strong> It will not be shown again and cannot be retrieved later.
			</p>
			{fields.map((field) => (
				<CopyField
					key={field.label}
					label={field.label}
					value={field.value}
					multiline={field.multiline}
				/>
			))}
			{note && <div className="modal-note">{note}</div>}
			<div className="modal-actions">
				<button type="button" className="primary" onClick={onClose}>
					I've copied it
				</button>
			</div>
		</Modal>
	)
}
