const NONCE_SIZE = 12
const SALT = new TextEncoder().encode('hanushield-v1')
const INFO = new TextEncoder().encode('payload-transport')

let cachedKey: CryptoKey | null = null

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase()
  if (normalized.length === 0 || normalized.length % 2 !== 0 || !/^[0-9a-f]+$/.test(normalized)) {
    throw new Error('invalid hex payload')
  }
  const bytes = new Uint8Array(normalized.length / 2)
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function derivePayloadKey(masterHex: string): Promise<CryptoKey> {
  const masterBytes = hexToBytes(masterHex)
  if (masterBytes.length !== 32) {
    throw new Error('VITE_ENCRYPTION_KEY must be 64 hex chars (32 bytes)')
  }
  const hkdfKey = await crypto.subtle.importKey('raw', masterBytes.buffer as ArrayBuffer, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: SALT,
      info: INFO,
    },
    hkdfKey,
    256,
  )

  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

export async function getPayloadKey(): Promise<CryptoKey> {
  if (cachedKey) {
    return cachedKey
  }

  const masterHex = import.meta.env.VITE_ENCRYPTION_KEY as string | undefined
  if (!masterHex) {
    throw new Error('VITE_ENCRYPTION_KEY is required for encrypted requests')
  }

  cachedKey = await derivePayloadKey(masterHex)
  return cachedKey
}

export async function encryptPayload(value: unknown): Promise<string> {
  const key = await getPayloadKey()
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  const plaintext = new TextEncoder().encode(JSON.stringify(value ?? {}))

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    plaintext,
  )

  const encryptedBytes = new Uint8Array(encrypted)
  const merged = new Uint8Array(nonce.length + encryptedBytes.length)
  merged.set(nonce, 0)
  merged.set(encryptedBytes, nonce.length)

  return bytesToHex(merged)
}

export async function decryptPayload(rawHex: string): Promise<unknown> {
  const key = await getPayloadKey()
  const payload = hexToBytes(rawHex)
  if (payload.length <= NONCE_SIZE) {
    throw new Error('encrypted payload is too short')
  }

  const nonce = payload.slice(0, NONCE_SIZE)
  const ciphertext = payload.slice(NONCE_SIZE)

  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    ciphertext,
  )

  const decoded = new TextDecoder().decode(plaintext)
  return decoded.length === 0 ? null : JSON.parse(decoded)
}

export function safePretty(value: unknown): string {
  if (value === undefined) {
    return ''
  }
  if (typeof value === 'string') {
    return value
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export function headersToRecord(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {}
  headers.forEach((value, key) => {
    result[key] = value
  })
  return result
}
