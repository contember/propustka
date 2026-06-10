import type { MeDto } from '@propustka/worker/admin'
import { useEffect, useState } from 'react'
import { ApiError, api } from './api'

export type MeState =
	| { status: 'loading' }
	| { status: 'ok'; me: MeDto }
	| { status: 'forbidden' }
	| { status: 'error'; message: string }

/**
 * Fetch the current admin (`GET /admin/me`) once for the app shell. A 403 means the
 * caller is authenticated by Access but is not an IAM admin — the nav-level gate. This is
 * UX only; the server re-checks every `/admin/*` call. (401 / Access bounces are handled
 * inside `api()` via a hard reload.)
 */
export function useMe(): MeState {
	const [state, setState] = useState<MeState>({ status: 'loading' })

	useEffect(() => {
		let cancelled = false
		api.get<MeDto>('/me')
			.then((me) => {
				if (!cancelled) setState({ status: 'ok', me })
			})
			.catch((cause: unknown) => {
				if (cancelled) return
				if (cause instanceof ApiError && cause.status === 403) {
					setState({ status: 'forbidden' })
				} else {
					setState({
						status: 'error',
						message: cause instanceof ApiError ? cause.message : 'Failed to load.',
					})
				}
			})
		return () => {
			cancelled = true
		}
	}, [])

	return state
}
