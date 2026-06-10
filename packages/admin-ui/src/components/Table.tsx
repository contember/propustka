import type { ReactNode } from 'react'

interface TableProps {
	head: ReactNode
	children: ReactNode
	/** Message to show in place of the body when there are no rows. */
	empty?: ReactNode
	isEmpty?: boolean
	colSpan?: number
}

/** A tiny semantic table wrapper with a built-in empty state. */
export function Table({ head, children, empty, isEmpty, colSpan = 1 }: TableProps) {
	return (
		<div className="table-wrap">
			<table>
				<thead>{head}</thead>
				<tbody>
					{isEmpty
						? (
							<tr>
								<td className="empty" colSpan={colSpan}>{empty ?? 'Nothing here yet.'}</td>
							</tr>
						)
						: children}
				</tbody>
			</table>
		</div>
	)
}
