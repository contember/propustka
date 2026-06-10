import { createPage, Link } from '@buzola/router'

export default createPage()
	.render(() => (
		<div className="gate-screen">
			<h1>Not found</h1>
			<p>That page doesn't exist.</p>
			<Link to="principals">Go to principals</Link>
		</div>
	))
