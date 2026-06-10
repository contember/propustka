import type { ReactNode } from 'react'
import { useEffect } from 'react'

interface ModalProps {
	title: string
	children: ReactNode
	/** Called when the user dismisses via the backdrop, Escape, or the close button. */
	onClose?: () => void
	/** When true the modal can only be closed by an explicit action inside it. */
	blocking?: boolean
}

/** A minimal centered modal with a backdrop. */
export function Modal({ title, children, onClose, blocking }: ModalProps) {
	useEffect(() => {
		if (blocking || !onClose) return
		function onKey(e: KeyboardEvent) {
			if (e.key === 'Escape') onClose?.()
		}
		window.addEventListener('keydown', onKey)
		return () => window.removeEventListener('keydown', onKey)
	}, [blocking, onClose])

	return (
		<div
			className="modal-backdrop"
			onClick={blocking ? undefined : onClose}
			role="presentation"
		>
			<div
				className="modal"
				role="dialog"
				aria-modal="true"
				aria-label={title}
				onClick={(e) => e.stopPropagation()}
			>
				<div className="modal-head">
					<h2>{title}</h2>
					{!blocking && onClose && (
						<button type="button" className="icon-btn" aria-label="Close" onClick={onClose}>×</button>
					)}
				</div>
				<div className="modal-body">{children}</div>
			</div>
		</div>
	)
}
