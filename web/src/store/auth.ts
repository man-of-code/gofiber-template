import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'

interface AuthState {
  adminKey: string
  clientId: string
  clientSecret: string
  accessToken: string
  refreshToken: string
  expiresIn: number
  setAdminKey: (value: string) => void
  setClientId: (value: string) => void
  setClientSecret: (value: string) => void
  setTokenPair: (value: { accessToken: string; refreshToken: string; expiresIn: number }) => void
  clearTokens: () => void
  isAuthenticated: boolean
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      adminKey: (import.meta.env.VITE_ADMIN_KEY as string | undefined) ?? '',
      clientId: '',
      clientSecret: '',
      accessToken: '',
      refreshToken: '',
      expiresIn: 0,
      setAdminKey: (value) => set({ adminKey: value }),
      setClientId: (value) => set({ clientId: value }),
      setClientSecret: (value) => set({ clientSecret: value }),
      setTokenPair: (value) =>
        set({
          accessToken: value.accessToken,
          refreshToken: value.refreshToken,
          expiresIn: value.expiresIn,
          isAuthenticated: Boolean(value.accessToken),
        }),
      clearTokens: () =>
        set({
          accessToken: '',
          refreshToken: '',
          expiresIn: 0,
          isAuthenticated: false,
        }),
      isAuthenticated: false,
    }),
    {
      name: 'react-api-test-client-auth',
      storage: createJSONStorage(() => sessionStorage),
    },
  ),
)
