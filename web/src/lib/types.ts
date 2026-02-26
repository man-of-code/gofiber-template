export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'

export interface NetworkEntry {
  id: string
  timestamp: number
  method: HttpMethod
  path: string
  status: number
  durationMs: number
  encrypted: boolean
  requestHeaders: Record<string, string>
  responseHeaders: Record<string, string>
  rawRequestBody: string
  displayRequestBody: string
  rawResponseBody: string
  displayResponseBody: string
  decryptionError?: string
}

export interface RequestOptions {
  method: HttpMethod
  path: string
  body?: unknown
  encrypt?: boolean
  auth?: boolean
  admin?: boolean
}

export interface ApiErrorPayload {
  message?: string
  error?: string
  details?: unknown
}
