import { Link, Outlet, useRoute } from '@buzola/router'
import { RouteError } from '../components/RouteError'
import { useMe } from '../lib/useMe'

type Page =
	| 'principals'
	| 'group-mappings'
	| 'api-keys'
	| 'share-links'
	| 'audit'
	| 'audit/auth-log'
	| 'policies'
	| 'roles'
	| 'schema'

interface NavChild {
	to: Page
	label: string
	/** Exact path that marks this child active. */
	path: string
}

interface NavItem {
	to: Page
	label: string
	/** Path prefix used to mark the item (and its section) active. */
	match: string
	children?: NavChild[]
}

const NAV: NavItem[] = [
	{ to: 'principals', label: 'Principals', match: '/principals' },
	{ to: 'group-mappings', label: 'Group mappings', match: '/group-mappings' },
	{ to: 'api-keys', label: 'API keys', match: '/api-keys' },
	{ to: 'share-links', label: 'Share links', match: '/share-links' },
	{
		to: 'audit',
		label: 'Audit',
		match: '/audit',
		children: [
			{ to: 'audit', label: 'Domain events', path: '/audit' },
			{ to: 'audit/auth-log', label: 'Auth log', path: '/audit/auth-log' },
		],
	},
	{ to: 'policies', label: 'Policies', match: '/policies' },
	{ to: 'roles', label: 'Roles', match: '/roles' },
	{ to: 'schema', label: 'Schema', match: '/schema' },
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
					permission, so the admin tool is unavailable. Ask an existing IAM admin to grant you the <code>admin</code> role.
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

	return (
		<div className="app-shell">
			<aside className="sidebar">
				<div className="brand">
					<span className="brand-name">propustka</span>
					<span className="brand-sub">IAM admin</span>
				</div>
				<nav>
					{NAV.map((item) => {
						const sectionActive = pathname === item.match
							|| pathname.startsWith(`${item.match}/`)
						const hasChildren = item.children && item.children.length > 0
						return (
							<div key={item.to} className="nav-group">
								<Link
									to={item.to}
									className={`nav-item${sectionActive ? (hasChildren ? ' section-active' : ' active') : ''}`}
									aria-current={sectionActive && !hasChildren ? 'page' : undefined}
								>
									{item.label}
								</Link>
								{hasChildren && sectionActive && (
									<div className="subnav">
										{item.children?.map((child) => {
											const childActive = pathname === child.path
											return (
												<Link
													key={child.path}
													to={child.to}
													className={`nav-subitem${childActive ? ' active' : ''}`}
													aria-current={childActive ? 'page' : undefined}
												>
													{child.label}
												</Link>
											)
										})}
									</div>
								)}
							</div>
						)
					})}
				</nav>
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
				<Outlet
					fallback={<div className="loading">Loading…</div>}
					errorFallback={(error) => <RouteError error={error} />}
				/>
			</main>
		</div>
	)
}
