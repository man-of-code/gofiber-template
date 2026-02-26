import { useState } from 'react'

import { apiRequest } from '../../lib/api'
import { useAuthStore } from '../../store/auth'
import { Button } from '../ui/Button'
import { Input, Textarea } from '../ui/Input'
import { JsonView } from '../ui/JsonView'

interface RegisterResponse {
  id: number
  name: string
  client_id: string
  client_secret: string
}

interface Client {
  id: number
  name: string
  client_id: string
  allowed_ips: string[]
  status: string
  created_at: number
  updated_at: number
}

export function AdminPanel() {
  const adminKey = useAuthStore((state) => state.adminKey)
  const setAdminKey = useAuthStore((state) => state.setAdminKey)
  const setClientId = useAuthStore((state) => state.setClientId)
  const setClientSecret = useAuthStore((state) => state.setClientSecret)

  const [name, setName] = useState((import.meta.env.VITE_DEFAULT_CLIENT_NAME as string | undefined) ?? '')
  const [allowedIps, setAllowedIps] = useState((import.meta.env.VITE_DEFAULT_ALLOWED_IPS as string | undefined) ?? '')
  const [revokeId, setRevokeId] = useState('')
  const [clients, setClients] = useState<Client[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [editName, setEditName] = useState('')
  const [editStatus, setEditStatus] = useState('active')
  const [editAllowedIps, setEditAllowedIps] = useState('')
  const [loadingClients, setLoadingClients] = useState(false)
  const [result, setResult] = useState('')
  const [error, setError] = useState('')
  const [registeredClientId, setRegisteredClientId] = useState('')
  const [registeredClientSecret, setRegisteredClientSecret] = useState('')

  async function registerClient() {
    setError('')
    const ips = allowedIps
      .split('\n')
      .map((value) => value.trim())
      .filter(Boolean)

    try {
      const payload = await apiRequest<RegisterResponse>({
        method: 'POST',
        path: '/admin/clients',
        body: { name, allowed_ips: ips },
        admin: true,
        encrypt: true,
      })
      setClientId(payload.client_id)
      setClientSecret(payload.client_secret)
      setRegisteredClientId(payload.client_id)
      setRegisteredClientSecret(payload.client_secret)
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'register failed')
    }
  }

  async function revokeAll() {
    setError('')
    try {
      const payload = await apiRequest<Record<string, unknown>>({
        method: 'POST',
        path: `/admin/clients/${revokeId}/revoke-all`,
        body: {},
        admin: true,
        encrypt: true,
      })
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'revoke failed')
    }
  }

  async function loadClients() {
    setError('')
    setLoadingClients(true)
    try {
      const payload = await apiRequest<Client[]>({
        method: 'GET',
        path: '/admin/clients',
        admin: true,
        encrypt: false,
      })
      setClients(payload)
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'load clients failed')
    } finally {
      setLoadingClients(false)
    }
  }

  function selectClient(client: Client) {
    setSelectedId(client.id)
    setEditName(client.name)
    setEditStatus(client.status)
    setEditAllowedIps(client.allowed_ips.join('\n'))
    setRevokeId(String(client.id))
  }

  async function updateClient() {
    if (!selectedId) return
    setError('')
    const ips = editAllowedIps
      .split('\n')
      .map((value) => value.trim())
      .filter(Boolean)
    try {
      const payload = await apiRequest<Client>({
        method: 'PUT',
        path: `/admin/clients/${selectedId}`,
        body: { name: editName, allowed_ips: ips, status: editStatus },
        admin: true,
        encrypt: true,
      })
      setClients((prev) => prev.map((c) => (c.id === payload.id ? payload : c)))
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'update failed')
    }
  }

  async function deleteClient() {
    if (!selectedId) return
    setError('')
    try {
      await apiRequest<Record<string, unknown>>({
        method: 'DELETE',
        path: `/admin/clients/${selectedId}`,
        admin: true,
        encrypt: false,
      })
      setClients((prev) => prev.filter((c) => c.id !== selectedId))
      setSelectedId(null)
      setEditName('')
      setEditAllowedIps('')
      setResult('deleted')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'delete failed')
    }
  }

  async function revokeSelected() {
    if (!selectedId) return
    setError('')
    try {
      const payload = await apiRequest<Record<string, unknown>>({
        method: 'POST',
        path: `/admin/clients/${selectedId}/revoke-all`,
        body: {},
        admin: true,
        encrypt: true,
      })
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'revoke failed')
    }
  }

  return (
    <section className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/70 p-4">
      <h3 className="text-sm font-semibold text-slate-100">Admin</h3>

      <label className="space-y-1 text-xs text-slate-300">
        Admin Key
        <Input type="password" value={adminKey} onChange={(event) => setAdminKey(event.target.value)} placeholder="X-Admin-Key" />
      </label>

      <div className="grid gap-3 md:grid-cols-2">
        <label className="space-y-1 text-xs text-slate-300">
          Client Name
          <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="acme-client" />
        </label>
        <div className="md:row-span-2">
          <label className="space-y-1 text-xs text-slate-300">
            Allowed IPs (CIDR per line)
            <Textarea value={allowedIps} onChange={(event) => setAllowedIps(event.target.value)} placeholder="10.0.0.0/8" />
          </label>
        </div>
        <div>
          <Button className="w-full" onClick={registerClient}>Register Client</Button>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-[1fr_auto]">
        <Input value={revokeId} onChange={(event) => setRevokeId(event.target.value)} placeholder="Client DB ID" />
        <Button variant="danger" onClick={revokeAll}>Revoke All Tokens</Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" onClick={loadClients}>{loadingClients ? 'Loading…' : 'Load Clients'}</Button>
        <span className="text-xs text-slate-400">Requires valid admin key.</span>
      </div>

      {clients.length > 0 ? (
        <div className="overflow-auto rounded-lg border border-slate-800">
          <table className="w-full min-w-[640px] text-left text-xs">
            <thead className="bg-slate-800/70 text-slate-300">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Client ID</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Allowed IPs</th>
                <th className="px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => (
                <tr key={client.id} className="border-t border-slate-800 hover:bg-slate-800/40">
                  <td className="px-3 py-2">{client.id}</td>
                  <td className="px-3 py-2">{client.name}</td>
                  <td className="px-3 py-2 font-mono text-[11px]">{client.client_id}</td>
                  <td className="px-3 py-2">
                    <span className="rounded bg-slate-800 px-2 py-1 text-[11px] uppercase tracking-wide">{client.status}</span>
                  </td>
                  <td className="px-3 py-2 whitespace-pre-line text-[11px] text-slate-300">{client.allowed_ips.join('\n') || 'any'}</td>
                  <td className="px-3 py-2">
                    <Button variant="secondary" className="text-xs" onClick={() => selectClient(client)}>Edit</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {selectedId ? (
        <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-slate-200">Edit Client #{selectedId}</h4>
            <Button variant="danger" className="text-xs" onClick={deleteClient}>Delete</Button>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="space-y-1 text-xs text-slate-300">
              Name
              <Input value={editName} onChange={(event) => setEditName(event.target.value)} placeholder="client name" />
            </label>
            <label className="space-y-1 text-xs text-slate-300">
              Status
              <select
                className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={editStatus}
                onChange={(event) => setEditStatus(event.target.value)}
              >
                <option value="active">active</option>
                <option value="suspended">suspended</option>
                <option value="revoked">revoked</option>
              </select>
            </label>
          </div>
          <label className="space-y-1 text-xs text-slate-300">
            Allowed IPs (CIDR per line)
            <Textarea value={editAllowedIps} onChange={(event) => setEditAllowedIps(event.target.value)} placeholder="10.0.0.0/8" />
          </label>
          <div className="flex gap-2">
            <Button onClick={updateClient}>Save Changes</Button>
            <Button variant="secondary" onClick={revokeSelected}>Revoke All Tokens</Button>
          </div>
        </div>
      ) : null}

      {registeredClientId ? (
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-1 text-xs text-slate-300">
            <p>Client ID</p>
            <div className="flex gap-2">
              <Input readOnly value={registeredClientId} />
              <Button
                variant="secondary"
                className="min-h-11 px-3"
                onClick={async () => {
                  await navigator.clipboard.writeText(registeredClientId)
                }}
              >
                Copy
              </Button>
            </div>
          </div>
          <div className="space-y-1 text-xs text-slate-300">
            <p>Client Secret</p>
            <div className="flex gap-2">
              <Input readOnly type="password" value={registeredClientSecret} />
              <Button
                variant="secondary"
                className="min-h-11 px-3"
                onClick={async () => {
                  await navigator.clipboard.writeText(registeredClientSecret)
                }}
              >
                Copy
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      <JsonView content={result} />
    </section>
  )
}
