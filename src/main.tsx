import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

// Mock Tauri APIs for browser development
if (!window.__TAURI__) {
  (window as any).__TAURI__ = {
    convertFileSrc: (src: string) => src
  };
  (window as any).__TAURI_IPC__ = async () => Promise.resolve([]);
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)