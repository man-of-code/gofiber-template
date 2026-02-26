import { Shield } from 'lucide-react'

import { useUiStore } from '../store/ui'
import { Sidebar } from './Sidebar'
import { AdminPanel } from './panels/AdminPanel'
import { AuthPanel } from './panels/AuthPanel'
import { HealthPanel } from './panels/HealthPanel'
import { ItemsPanel } from './panels/ItemsPanel'
import { TabBar } from './ui/TabBar'

export function Layout() {
  const activeTab = useUiStore((state) => state.activeTab)
  const setActiveTab = useUiStore((state) => state.setActiveTab)
  const encryptPayloads = useUiStore((state) => state.encryptPayloads)
  const setEncryptPayloads = useUiStore((state) => state.setEncryptPayloads)

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100 md:h-screen md:flex-row">
      <main className="flex-1 overflow-auto p-4 md:p-6">
        <div className="mb-4 rounded-lg border border-slate-700 bg-slate-900/70 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h1 className="flex items-center gap-2 text-lg font-semibold">
              <Shield size={18} />
              GoFiber API Test Client
            </h1>
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-slate-700 bg-slate-900"
                checked={encryptPayloads}
                onChange={(event) => setEncryptPayloads(event.target.checked)}
              />
              Encrypt payloads by default
            </label>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            PoC only: exposing VITE_ENCRYPTION_KEY in browser code is not production-safe.
          </p>
        </div>

        <div className="space-y-4">
          <TabBar activeTab={activeTab} onChange={setActiveTab} />
          {activeTab === 'health' ? <HealthPanel /> : null}
          {activeTab === 'admin' ? <AdminPanel /> : null}
          {activeTab === 'auth' ? <AuthPanel /> : null}
          {activeTab === 'items' ? <ItemsPanel /> : null}
        </div>
      </main>

      <Sidebar />
    </div>
  )
}
