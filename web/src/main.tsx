import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

function verifyRequiredEnv() {
  const missing: string[] = []
  if (!import.meta.env.VITE_ENCRYPTION_KEY) {
    missing.push('VITE_ENCRYPTION_KEY')
  }
  if (!import.meta.env.VITE_ADMIN_KEY) {
    missing.push('VITE_ADMIN_KEY')
  }
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variable(s): ${missing.join(
        ', ',
      )}. Configure them in web/.env.local as documented in web/README.md.`,
    )
  }
}

verifyRequiredEnv()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
