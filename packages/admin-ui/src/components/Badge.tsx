import type { ReactNode } from 'react'

type Tone = 'neutral' | 'good' | 'warn' | 'bad' | 'muted'

interface BadgeProps {
	tone?: Tone
	children: ReactNode
	title?: string
}

/** A small inline status pill. */
export function Badge({ tone = 'neutral', children, title }: BadgeProps) {
	return <span className={`badge badge-${tone}`} title={title}>{children}</span>
}

/** Map a principal/api-key status string to a toned badge. */
export function StatusBadge({ status }: { status: 'invited' | 'active' | 'disabled' }) {
	const tone: Tone = status === 'active' ? 'good' : status === 'invited' ? 'warn' : 'muted'
	return <Badge tone={tone}>{status}</Badge>
}
