import { create } from 'zustand'

import type { NetworkEntry } from '../lib/types'

const MAX_ENTRIES = 200

interface NetworkLogState {
  entries: NetworkEntry[]
  selectedId: string | null
  addEntry: (entry: NetworkEntry) => void
  updateEntry: (id: string, patch: Partial<NetworkEntry>) => void
  clearEntries: () => void
  setSelectedId: (id: string | null) => void
}

export const useNetworkLogStore = create<NetworkLogState>((set) => ({
  entries: [],
  selectedId: null,
  addEntry: (entry) =>
    set((state) => {
      const entries = [entry, ...state.entries].slice(0, MAX_ENTRIES)
      return {
        entries,
        selectedId: state.selectedId ?? entry.id,
      }
    }),
  updateEntry: (id, patch) =>
    set((state) => ({
      entries: state.entries.map((entry) => (entry.id === id ? { ...entry, ...patch } : entry)),
    })),
  clearEntries: () =>
    set({
      entries: [],
      selectedId: null,
    }),
  setSelectedId: (id) => set({ selectedId: id }),
}))
