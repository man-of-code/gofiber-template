import { useState } from 'react'

import { apiRequest } from '../../lib/api'
import { useAuthStore } from '../../store/auth'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import { JsonView } from '../ui/JsonView'

export function ItemsPanel() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)

  const [page, setPage] = useState('1')
  const [limit, setLimit] = useState('20')
  const [id, setId] = useState('')
  const [name, setName] = useState('')
  const [result, setResult] = useState('')
  const [error, setError] = useState('')

  if (!isAuthenticated) {
    return (
      <section className="rounded-lg border border-slate-700 bg-slate-900/70 p-4">
        <p className="text-sm text-slate-300">Authenticate in the Auth tab to use item endpoints.</p>
      </section>
    )
  }

  async function run(action: () => Promise<Record<string, unknown> | Array<unknown>>) {
    setError('')
    try {
      const payload = await action()
      setResult(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'request failed')
    }
  }

  return (
    <section className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/70 p-4">
      <h3 className="text-sm font-semibold text-slate-100">Items</h3>

      <div className="grid gap-2 md:grid-cols-[120px_120px_auto]">
        <Input value={page} onChange={(event) => setPage(event.target.value)} placeholder="page" />
        <Input value={limit} onChange={(event) => setLimit(event.target.value)} placeholder="limit" />
        <Button
          onClick={() =>
            run(() =>
              apiRequest<Record<string, unknown>>({
                method: 'GET',
                path: `/api/items?page=${Number.parseInt(page, 10) || 1}&limit=${Number.parseInt(limit, 10) || 20}`,
                auth: true,
                encrypt: false,
              }),
            )
          }
        >
          Fetch Items
        </Button>
      </div>

      <div className="grid gap-2 md:grid-cols-[1fr_auto]">
        <Input value={id} onChange={(event) => setId(event.target.value)} placeholder="item id" />
        <Button
          onClick={() =>
            run(() =>
              apiRequest<Record<string, unknown>>({
                method: 'GET',
                path: `/api/items/${id}`,
                auth: true,
                encrypt: false,
              }),
            )
          }
        >
          Get Item
        </Button>
      </div>

      <div className="grid gap-2 md:grid-cols-[1fr_auto]">
        <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="item name" />
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={() =>
              run(() =>
                apiRequest<Record<string, unknown>>({
                  method: 'POST',
                  path: '/api/items',
                  body: { name },
                  auth: true,
                  encrypt: true,
                }),
              )
            }
          >
            Create
          </Button>
          <Button
            variant="secondary"
            onClick={() =>
              run(() =>
                apiRequest<Record<string, unknown>>({
                  method: 'PUT',
                  path: `/api/items/${id}`,
                  body: { name },
                  auth: true,
                  encrypt: true,
                }),
              )
            }
          >
            Update
          </Button>
          <Button
            variant="danger"
            onClick={() =>
              run(() =>
                apiRequest<Record<string, unknown>>({
                  method: 'DELETE',
                  path: `/api/items/${id}`,
                  auth: true,
                  encrypt: false,
                }),
              )
            }
          >
            Delete
          </Button>
        </div>
      </div>

      {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      <JsonView content={result} />
    </section>
  )
}
