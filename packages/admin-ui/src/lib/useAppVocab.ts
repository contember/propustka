import type { AppActionDef, AppSchemaDto, AppScopeDef, ListResponse, RoleDto } from '@propustka/worker/admin'
import { useEffect, useState } from 'react'
import { api, ApiError } from './api'

/**
 * The per-app authz vocabulary a grant / mapping form needs once an app is chosen:
 *  - `roles`   — built-in (cross-app) + the app's app/custom roles (`GET /roles?app=…`).
 *  - `scopes`  — the app's scope dimensions (`GET /apps/:app/schema`).
 *  - `actions` — the app's action catalog (`GET /apps/:app/schema`).
 *
 * When `app` is null (cross-app), only built-in roles load and there are no scopes /
 * actions (a cross-app grant can't reference an app's scope dimensions or action catalog).
 */
export interface AppVocab {
	roles: RoleDto[]
	scopes: AppScopeDef[]
	actions: AppActionDef[]
}

export type AppVocabState =
	| { status: 'loading' }
	| { status: 'ok'; vocab: AppVocab }
	| { status: 'error'; message: string }

const EMPTY: AppVocab = { roles: [], scopes: [], actions: [] }

/**
 * Load the vocabulary for `app`. `app` is `undefined` while the admin hasn't chosen yet
 * (no fetch, no roles), `null` for an explicit cross-app choice (built-in roles only), or
 * an app id. Re-fetches whenever `app` changes.
 */
export function useAppVocab(app: string | null | undefined): AppVocabState {
	const [state, setState] = useState<AppVocabState>(
		app === undefined ? { status: 'ok', vocab: EMPTY } : { status: 'loading' },
	)

	useEffect(() => {
		let cancelled = false
		if (app === undefined) {
			setState({ status: 'ok', vocab: EMPTY })
			return
		}
		setState({ status: 'loading' })

		const rolesPath = app === null ? '/roles' : `/roles?app=${encodeURIComponent(app)}`
		const rolesP = api.get<ListResponse<RoleDto>>(rolesPath)
		const schemaP = app === null
			? Promise.resolve<AppSchemaDto | null>(null)
			: api.get<AppSchemaDto>(`/apps/${encodeURIComponent(app)}/schema`)

		Promise.all([rolesP, schemaP])
			.then(([roles, schema]) => {
				if (cancelled) return
				setState({
					status: 'ok',
					vocab: { roles: roles.items, scopes: schema?.scopes ?? [], actions: schema?.actions ?? [] },
				})
			})
			.catch((cause: unknown) => {
				if (cancelled) return
				setState({ status: 'error', message: cause instanceof ApiError ? cause.message : 'Failed to load app vocabulary.' })
			})

		return () => {
			cancelled = true
		}
	}, [app])

	return state
}
