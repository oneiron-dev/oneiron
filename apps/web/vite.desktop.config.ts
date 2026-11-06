import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import { defineConfig } from 'vite'
import viteReact from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Separate config is intentional: this Start version opens its prerender
// preview by configFile, without forwarding Vite's mode. A mode-only branch
// in the web config would accidentally load Nitro during desktop prerender.
export default defineConfig({
  server: { host: '127.0.0.1', port: 1420, strictPort: true },
  build: { outDir: 'dist-desktop' },
  resolve: { tsconfigPaths: true },
  plugins: [
    tailwindcss(),
    tanstackStart({
      srcDirectory: 'src',
      // Tauri's route fallback is index.html. Render only the shared shell;
      // the same file routes and fixture content render on the client.
      spa: { enabled: true, prerender: { outputPath: '/index' } },
      prerender: { autoStaticPathsDiscovery: false },
    }),
    viteReact(),
  ],
})
