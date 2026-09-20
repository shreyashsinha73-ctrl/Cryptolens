import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
<<<<<<< HEAD
    proxy: {
      '/api': 'http://127.0.0.1:8000',
=======
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
>>>>>>> 09ed384854c6a471d409aeed5b20daf4a821a5d1
    },
  },
})
