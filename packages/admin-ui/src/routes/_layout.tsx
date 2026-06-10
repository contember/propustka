import { Link, Outlet } from '@buzola/router'

export default function RootLayout() {
	return (
		<>
			<header className="app-header">
				<Link to="index" className="brand">propustka</Link>
			</header>
			<main>
				<Outlet />
			</main>
		</>
	)
}
