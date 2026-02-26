import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'

type Tab = 'health' | 'admin' | 'auth' | 'items'

interface UiState {
  activeTab: Tab
  encryptPayloads: boolean
  setActiveTab: (tab: Tab) => void
  setEncryptPayloads: (value: boolean) => void
}

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      activeTab: 'health',
      encryptPayloads: true,
      setActiveTab: (activeTab) => set({ activeTab }),
      setEncryptPayloads: (encryptPayloads) => set({ encryptPayloads }),
    }),
    {
      name: 'react-api-test-client-ui',
      storage: createJSONStorage(() => sessionStorage),
    },
  ),
)

export type { Tab }
