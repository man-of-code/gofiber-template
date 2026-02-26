import type { HttpMethod } from '../../lib/types'

export function MethodBadge({ method }: { method: HttpMethod }) {
  const color =
    method === 'GET'
      ? 'border-emerald-400/40 text-emerald-300 bg-emerald-500/10'
      : method === 'POST'
        ? 'border-blue-400/40 text-blue-300 bg-blue-500/10'
        : method === 'PUT'
          ? 'border-amber-400/40 text-amber-300 bg-amber-500/10'
          : 'border-rose-400/40 text-rose-300 bg-rose-500/10'

  return <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${color}`}>{method}</span>
}

export function StatusBadge({ status }: { status: number }) {
  const color =
    status >= 500
      ? 'border-rose-400/40 text-rose-300 bg-rose-500/10'
      : status >= 400
        ? 'border-amber-400/40 text-amber-300 bg-amber-500/10'
        : status >= 200
          ? 'border-emerald-400/40 text-emerald-300 bg-emerald-500/10'
          : 'border-slate-600 text-slate-300 bg-slate-700/50'

  return <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${color}`}>{status || '-'}</span>
}
