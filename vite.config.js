import react from '@vitejs/plugin-react'
import path from 'path'
import { defineConfig } from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  // Prevent Vite from clearing console (useful for debugging)
  clearScreen: false,

  // Development server configuration
  server: {
    port: 1420,
    strictPort: true,

    // CRITICAL: Use 'localhost' not '0.0.0.0' for security
    // This prevents external network access during development
    host: 'localhost',

    // Configure WebSocket for hot module replacement
    hmr: {
      protocol: 'ws',
      host: 'localhost',
      port: 1421
    },

    // Add CORS headers for Tauri
    cors: true,

    // Headers for better compatibility
    headers: {
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy': 'same-origin'
    }
  },

  // Environment variable prefixes
  envPrefix: ['VITE_', 'TAURI_'],

  // Build configuration
  build: {
    // Tauri supports ES2022
    target: ['es2022', 'chrome100', 'safari13'],

    // Enable source maps for debugging
    sourcemap: true,

    // Output directory
    outDir: 'dist',

    // Asset handling
    assetsDir: 'assets',

    // Rollup options for better compatibility
    rollupOptions: {
      input: {
        main: path.resolve(__dirname, 'index.html'),
      },
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'ui-vendor': ['lucide-react', 'zustand']
        }
      }
    }
  },

  // Resolve aliases for cleaner imports
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@commands': path.resolve(__dirname, './src-tauri/src/commands'),
      '@analysis': path.resolve(__dirname, './src-tauri/src/analysis'),
      '@core': path.resolve(__dirname, './src-tauri/src/core'),
      '@scanning': path.resolve(__dirname, './src-tauri/src/scanning'),
      '@utils': path.resolve(__dirname, './src-tauri/src/utils')
    }
  },

  // Optimize dependencies
  optimizeDeps: {
    include: ['react', 'react-dom', 'zustand', '@tauri-apps/api']
  }
})