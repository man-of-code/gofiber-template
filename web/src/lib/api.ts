import { decryptPayload, encryptPayload, headersToRecord, safePretty } from './crypto'
import type { ApiErrorPayload, NetworkEntry, RequestOptions } from './types'
import { useAuthStore } from '../store/auth'
import { useNetworkLogStore } from '../store/network-log'
import { useUiStore } from '../store/ui'

function toErrorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== 'object') {
    return fallback
  }
  const typed = payload as ApiErrorPayload
  return typed.message ?? typed.error ?? fallback
}

function parseTokenResponse(payload: unknown): { accessToken: string; refreshToken: string; expiresIn: number } | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }
  const data = payload as Record<string, unknown>
  const accessToken = typeof data.access_token === 'string' ? data.access_token : ''
  const refreshToken = typeof data.refresh_token === 'string' ? data.refresh_token : ''
  const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 0
  if (!accessToken || !refreshToken) {
    return null
  }
  return { accessToken, refreshToken, expiresIn }
}

async function parseResponseBody(
  rawResponseBody: string,
  encrypted: boolean,
): Promise<{ display: string; value: unknown; error?: string }> {
  if (!rawResponseBody) {
    return { display: '', value: null }
  }

  if (!encrypted) {
    try {
      const parsed = JSON.parse(rawResponseBody)
      return { display: safePretty(parsed), value: parsed }
    } catch {
      return { display: rawResponseBody, value: rawResponseBody }
    }
  }

  try {
    const decrypted = await decryptPayload(rawResponseBody)
    return { display: safePretty(decrypted), value: decrypted }
  } catch (error) {
    return {
      display: rawResponseBody,
      value: rawResponseBody,
      error: error instanceof Error ? error.message : 'failed to decrypt response',
    }
  }
}

export async function apiRequest<TResponse>(options: RequestOptions): Promise<TResponse> {
  const authState = useAuthStore.getState()
  const networkStore = useNetworkLogStore.getState()
  const uiState = useUiStore.getState()

  const hasBody = options.body !== undefined
  const encrypted = options.encrypt ?? uiState.encryptPayloads
  const shouldEncrypt = encrypted && hasBody

  const requestHeaders: Record<string, string> = {
    Accept: 'application/json',
  }

  if (options.auth && authState.accessToken) {
    requestHeaders.Authorization = `Bearer ${authState.accessToken}`
  }
  if (options.admin && authState.adminKey) {
    requestHeaders['X-Admin-Key'] = authState.adminKey
  }

  let bodyText = ''
  let displayRequestBody = ''

  if (hasBody) {
    displayRequestBody = safePretty(options.body)
    if (shouldEncrypt) {
      bodyText = await encryptPayload(options.body)
      requestHeaders['X-Encrypted-Payload'] = 'true'
      requestHeaders['Content-Type'] = 'application/octet-stream'
    } else {
      bodyText = JSON.stringify(options.body)
      requestHeaders['Content-Type'] = 'application/json'
    }
  }

  const entryId = crypto.randomUUID()
  const startedAt = performance.now()

  const pendingEntry: NetworkEntry = {
    id: entryId,
    timestamp: Date.now(),
    method: options.method,
    path: options.path,
    status: 0,
    durationMs: 0,
    encrypted: shouldEncrypt,
    requestHeaders,
    responseHeaders: {},
    rawRequestBody: bodyText,
    displayRequestBody,
    rawResponseBody: '',
    displayResponseBody: '',
  }

  networkStore.addEntry(pendingEntry)

  try {
    const response = await fetch(options.path, {
      method: options.method,
      headers: requestHeaders,
      body: hasBody ? bodyText : undefined,
    })

    const rawResponseBody = await response.text()
    const contentType = response.headers.get('content-type') ?? ''
    const encryptedResponse = shouldEncrypt || contentType.toLowerCase().startsWith('application/octet-stream')
    const responseHeaders = headersToRecord(response.headers)
    const durationMs = Math.round(performance.now() - startedAt)
    const bodyResult = await parseResponseBody(rawResponseBody, encryptedResponse)

    networkStore.updateEntry(entryId, {
      status: response.status,
      durationMs,
      responseHeaders,
      rawResponseBody,
      displayResponseBody: bodyResult.display,
      decryptionError: bodyResult.error,
      encrypted: encryptedResponse,
    })

    if (!response.ok) {
      throw new Error(toErrorMessage(bodyResult.value, `request failed: ${response.status}`))
    }

    const tokenPayload = parseTokenResponse(bodyResult.value)
    if (tokenPayload) {
      useAuthStore.getState().setTokenPair(tokenPayload)
    }

    return bodyResult.value as TResponse
  } catch (error) {
    const durationMs = Math.round(performance.now() - startedAt)
    networkStore.updateEntry(entryId, {
      durationMs,
      decryptionError: error instanceof Error ? error.message : 'request failed',
    })
    throw error
  }
}
