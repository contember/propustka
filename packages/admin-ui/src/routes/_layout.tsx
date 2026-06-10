import { Link, Outlet, useRoute } from '@buzola/router'
import { useMe } from '../lib/useMe'

interface NavItem {
	to:
		| 'principals'
		| 'projects'
		| 'group-mappings'
		| 'api-keys'
		| 'capabilities'
		| 'audit'
		| 'roles'
	label: string
	/** Path prefix used to mark the item active. */
	match: string
}

const NAV: NavItem[] = [
	{ to: 'principals', label: 'Principals', match: '/principals' },
	{ to: 'projects', label: 'Projects', match: '/projects' },
	{ to: 'group-mappings', label: 'Group mappings', match: '/group-mappings' },
	{ to: 'api-keys', label: 'API keys', match: '/api-keys' },
	{ to: 'capabilities', label: 'Capabilities', match: '/capabilities' },
	{ to: 'audit', label: 'Audit', match: '/audit' },
	{ to: 'roles', label: 'Roles', match: '/roles' },
]

export default function RootLayout() {
	const me = useMe()
	const { pathname } = useRoute()

	if (me.status === 'forbidden') {
		return (
			<div className="gate-screen">
				<h1>Not an IAM admin</h1>
				<p>
					Your session is valid, but your account does not hold the <code>iam.admin</code>{' '}
					permission, so the admin tool is unavailable. Ask an existing IAM admin to grant
					you the <code>admin</code> role.
				</p>
			</div>
		)
	}

	if (me.status === 'error') {
		return (
			<div className="gate-screen">
				<h1>Couldn't load the admin tool</h1>
				<p className="error-text">{me.message}</p>
				<button type="button" onClick={() => location.reload()}>Retry</button>
			</div>
		)
	}

	const isAuditSection = pathname.startsWith('/audit')

	return (
		<div className="app-shell">
			<aside className="sidebar">
				<div className="brand">propustka</div>
				<nav>
					{NAV.map((item) => {
						const active = item.match === '/audit'
							? isAuditSection
							: pathname === item.match || pathname.startsWith(`${item.match}/`)
						return (
							<Link key={item.to} to={item.to} className={active ? 'active' : ''}>
								{item.label}
							</Link>
						)
					})}
				</nav>
				{isAuditSection && (
					<nav className="subnav">
						<Link to="audit" className={pathname === '/audit' ? 'active' : ''}>
							Domain events
						</Link>
						<Link to="audit/auth-log" className={pathname === '/audit/auth-log' ? 'active' : ''}>
							Auth log
						</Link>
					</nav>
				)}
				<div className="me">
					{me.status === 'loading'
						? <span className="muted">loading…</span>
						: (
							<>
								<span className="me-label">{me.me.label}</span>
								<span className="me-type muted">{me.me.type}</span>
								{me.me.groupsUnavailable && (
									<span className="me-warn" title="IdP group resolution was unavailable this request — group-based permissions may be missing.">
										groups unavailable
									</span>
								)}
							</>
						)}
				</div>
			</aside>
			<main className="content">
				<Outlet fallback={<div className="loading">Loading…</div>} />
			</main>
		</div>
	)
}
