import { createPage } from '@buzola/router'

export default createPage()
	.loader(async ({ redirect }) => redirect('principals'))
	.route('/')
	.render(() => null)
