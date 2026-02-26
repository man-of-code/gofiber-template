import { Trash2 } from 'lucide-react'

import { useNetworkLogStore } from '../store/network-log'
import { RequestDialog } from './RequestDetail'
import { RequestEntry } from './RequestEntry'
import { Button } from './ui/Button'

export function Sidebar() {
  const entries = useNetworkLogStore((state) => state.entries)
  const selectedId = useNetworkLogStore((state) => state.selectedId)
  const setSelectedId = useNetworkLogStore((state) => state.setSelectedId)
  const clearEntries = useNetworkLogStore((state) => state.clearEntries)
  const selectedEntry = entries.find((entry) => entry.id === selectedId) ?? null

  return (
    <aside className="flex h-full w-full flex-col border-l border-slate-700 bg-slate-900/90 md:w-96">
      <div className="flex items-center justify-between border-b border-slate-700 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Network Inspector</h2>
          <p className="text-xs text-slate-400">{entries.length} request(s)</p>
        </div>
        <Button variant="secondary" className="min-h-0 px-2 py-1" onClick={clearEntries}>
          <Trash2 size={14} />
        </Button>
      </div>

      <div className="flex-1 space-y-2 overflow-auto p-3">
        {entries.map((entry) => (
          <RequestEntry
            key={entry.id}
            entry={entry}
            expanded={selectedId === entry.id}
            onClick={() => setSelectedId(entry.id)}
          />
        ))}
        {entries.length === 0 ? (
          <p className="rounded-lg border border-slate-700 bg-slate-900 p-4 text-sm text-slate-400">No requests yet.</p>
        ) : null}
      </div>
      {selectedEntry ? <RequestDialog entry={selectedEntry} onClose={() => setSelectedId(null)} /> : null}
    </aside>
  )
}
