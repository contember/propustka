import { ApiError } from '../lib/api'

interface RouteErrorProps {
	error: Error
}

/** Title + body for a route error, mapped by type — never echoing a raw server message. */
function describe(error: Error): { title: string; body: string } {
	if (error instanceof ApiError) {
		if (error.status === 403) {
			return {
				title: "You don't have permission to view this",
				body: 'Your account is missing the permission this page requires. Ask an IAM admin if you think this is wrong.',
			}
		}
		if (error.status === 404) {
			return {
				title: 'Not found',
				body: "The thing you're looking for doesn't exist, or was removed.",
			}
		}
		if (error.status === 0) {
			return {
				title: 'Network error',
				body: "Couldn't reach the server. Check your connection and try again.",
			}
		}
	}
	return {
		title: 'Something went wrong',
		body: 'This page failed to load. Try again, and if it keeps happening, contact an IAM admin.',
	}
}

/**
 * Styled fallback for loader/render failures, wired as the layout `<Outlet errorFallback>`.
 * Maps the error by type/status — it never renders the raw `error.message`, which can carry
 * an internal server string. A short status hint is shown for `ApiError`s for support.
 */
export function RouteError({ error }: RouteErrorProps) {
	const { title, body } = describe(error)
	const status = error instanceof ApiError && error.status !== 0 ? error.status : null

	return (
		<div className="gate-screen">
			<h1>{title}</h1>
			<p>{body}</p>
			{status !== null && <p className="muted small">Status {status}</p>}
			<button type="button" onClick={() => location.reload()}>Retry</button>
		</div>
	)
}
