import { useState } from 'react'

import { apiRequest } from '../../lib/api'
import { Button } from '../ui/Button'
import { JsonView } from '../ui/JsonView'

export function HealthPanel() {
  const [response, setResponse] = useState('')
  const [error, setError] = useState('')

  return (
    <section className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/70 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-100">Health Check</h3>
        <Button
          onClick={async () => {
            setError('')
            try {
              const result = await apiRequest<Record<string, unknown>>({ method: 'GET', path: '/health', encrypt: false })
              setResponse(JSON.stringify(result, null, 2))
            } catch (err) {
              setError(err instanceof Error ? err.message : 'request failed')
            }
          }}
        >
          Check Health
        </Button>
      </div>
      {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      <JsonView content={response} />
    </section>
  )
}
