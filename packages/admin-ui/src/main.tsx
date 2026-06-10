import { BuzolaProvider } from '@buzola/router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { pageRegistry, routes } from './buzola.gen'

const root = document.getElementById('root')
if (!root) throw new Error('#root not found')

createRoot(root).render(
	<StrictMode>
		<BuzolaProvider routes={routes} pageRegistry={pageRegistry} />
	</StrictMode>,
)
