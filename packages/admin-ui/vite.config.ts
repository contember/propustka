import { buzolaPlugin } from '@buzola/vite-plugin'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
	plugins: [
		buzolaPlugin(),
		react(),
	],
	server: {
		port: 18192,
		proxy: {
			'/admin': 'http://localhost:18191',
		},
	},
})
