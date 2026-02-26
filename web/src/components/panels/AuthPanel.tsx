import { useState } from 'react'

import { apiRequest } from '../../lib/api'
import { useAuthStore } from '../../store/auth'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import { JsonView } from '../ui/JsonView'

export function AuthPanel() {
  const clientId = useAuthStore((state) => state.clientId)
  const setClientId = useAuthStore((state) => state.setClientId)
  const clientSecret = useAuthStore((state) => state.clientSecret)
  const setClientSecret = useAuthStore((state) => state.setClientSecret)
  const accessToken = useAuthStore((state) => state.accessToken)
  const refreshToken = useAuthStore((state) => state.refreshToken)
  const expiresIn = useAuthStore((state) => state.expiresIn)
  const clearTokens = useAuthStore((state) => state.clearTokens)

  const [result, setResult] = useState('')
  const [error, setError] = useState('')

  async function authenticate() {
    setError('')
    try {
      const payload = await apiRequest<Record<string, unknown>>({
        method: 'POST',
        path: '/auth/token',
        body: { client_id: clientId, client_secret: clientSecret },
        encrypt: true,
      })
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'authenticate failed')
    }
  }

  async function refresh() {
    setError('')
    try {
      const payload = await apiRequest<Record<string, unknown>>({
        method: 'POST',
        path: '/auth/token/refresh',
        body: { refresh_token: refreshToken },
        encrypt: true,
      })
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'refresh failed')
    }
  }

  async function revoke() {
    setError('')
    try {
      const payload = await apiRequest<Record<string, unknown>>({
        method: 'POST',
        path: '/auth/token/revoke',
        body: { token: refreshToken },
        auth: true,
        encrypt: true,
      })
      setResult(JSON.stringify(payload, null, 2))
      clearTokens()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'revoke failed')
    }
  }

  return (
    <section className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/70 p-4">
      <h3 className="text-sm font-semibold text-slate-100">Auth</h3>

      <div className="grid gap-3 md:grid-cols-2">
        <Input value={clientId} onChange={(event) => setClientId(event.target.value)} placeholder="client_id" />
        <Input type="password" value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} placeholder="client_secret" />
      </div>

      <div className="flex flex-wrap gap-2">
        <Button onClick={authenticate}>Authenticate</Button>
        <Button variant="secondary" onClick={refresh} disabled={!refreshToken}>Refresh Token</Button>
        <Button variant="danger" onClick={revoke} disabled={!accessToken}>Revoke Current Token</Button>
      </div>

      <p className="text-xs text-slate-400">
        Status: {accessToken ? 'authenticated' : 'no token'} | Expires in: {expiresIn || 0}s
      </p>

      {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      <JsonView content={result} />
    </section>
  )
}
