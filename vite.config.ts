import path from "path"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// ⚠️ Se for um *project page* (https://username.github.io/<repo>):
const repoName = '<repo>'       // <-- muda para o teu nome de repo
const isProjectPage = true

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: isProjectPage ? `/${repoName}/` : '/', // para GH Pages
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
