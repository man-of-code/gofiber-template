import type { Tab } from '../../store/ui'

const tabs: Array<{ id: Tab; label: string }> = [
  { id: 'health', label: 'Health' },
  { id: 'admin', label: 'Admin' },
  { id: 'auth', label: 'Auth' },
  { id: 'items', label: 'Items' },
]

export function TabBar({ activeTab, onChange }: { activeTab: Tab; onChange: (tab: Tab) => void }) {
  return (
    <div className="flex flex-wrap gap-2 rounded-lg border border-slate-700 bg-slate-900/80 p-2">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`min-h-11 rounded-md px-4 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-blue-500 ${
            activeTab === tab.id ? 'bg-blue-500/25 text-blue-100' : 'text-slate-300 hover:bg-slate-800'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}
