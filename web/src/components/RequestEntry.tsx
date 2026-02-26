import type { NetworkEntry } from '../lib/types'
import { MethodBadge, StatusBadge } from './ui/Badge'

function formatAge(timestamp: number): string {
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ago`
}

export function RequestEntry({
  entry,
  expanded,
  onClick,
}: {
  entry: NetworkEntry
  expanded: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full rounded-lg border p-3 text-left transition focus:outline-none focus:ring-2 focus:ring-blue-500 ${
        expanded ? 'border-blue-500/60 bg-slate-800' : 'border-slate-700 bg-slate-900/70 hover:bg-slate-800'
      }`}
    >
      <div className="flex items-center gap-2">
        <MethodBadge method={entry.method} />
        <p className="min-w-0 flex-1 truncate text-sm text-slate-100">{entry.path}</p>
      </div>
      <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
        <StatusBadge status={entry.status} />
        <span>{entry.durationMs}ms</span>
        <span>{formatAge(entry.timestamp)}</span>
        {entry.encrypted ? <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[10px] text-slate-200">Encrypted</span> : null}
      </div>
    </button>
  )
}
