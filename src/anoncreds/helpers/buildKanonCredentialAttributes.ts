import { KANON_CRED_ID_ATTRIBUTE } from '../utils/credIdHash'

/**
 * Standard AnonCreds credential attribute entry.
 */
export interface KanonCredentialAttribute {
  name: string
  value: string
}

export interface BuildKanonCredentialAttributesResult {
  /**
   * The (possibly augmented) attribute list. If the caller did not include a
   * `kanonCredId` entry one is prepended with a freshly-generated UUID. The
   * original array is not mutated.
   */
  attributes: KanonCredentialAttribute[]
  /**
   * The credId value that ends up on the credential, regardless of whether it
   * was supplied by the caller or generated here. Issuers want this so they can
   * record (credDefId, credId) in their off-chain ledger for later revocation.
   */
  credId: string
}

/**
 * Generates a v4 UUID using the platform-provided `crypto.randomUUID`. Available
 * on Node 19+, modern browsers, and React Native (Hermes). We deliberately avoid
 * adding the `uuid` npm dependency to keep the package footprint minimal.
 */
function randomUuid(): string {
  // biome-ignore lint/suspicious/noExplicitAny: globalThis.crypto typing varies across runtimes
  const c: any = (globalThis as any).crypto
  if (!c || typeof c.randomUUID !== 'function') {
    throw new Error(
      'buildKanonCredentialAttributes: globalThis.crypto.randomUUID() is unavailable in this runtime. Use Node >= 19, a modern browser, or polyfill globalThis.crypto.'
    )
  }
  return c.randomUUID()
}

/**
 * Ensures the AnonCreds attribute list carries a `kanonCredId` entry. If the
 * caller already included one its value is reused; otherwise a UUID is
 * generated and prepended. Returns the final attribute list plus the credId
 * for callers that need it for off-chain bookkeeping (revocation indexing,
 * receipts, etc.).
 */
export function buildKanonCredentialAttributes(
  attrs: KanonCredentialAttribute[]
): BuildKanonCredentialAttributesResult {
  if (!Array.isArray(attrs)) {
    throw new Error('buildKanonCredentialAttributes: attrs must be an array')
  }

  const existing = attrs.find((a) => a.name === KANON_CRED_ID_ATTRIBUTE)
  if (existing) {
    if (typeof existing.value !== 'string' || existing.value.length === 0) {
      throw new Error(
        `buildKanonCredentialAttributes: existing '${KANON_CRED_ID_ATTRIBUTE}' attribute must have a non-empty string value`
      )
    }
    return { attributes: [...attrs], credId: existing.value }
  }

  const credId = randomUuid()
  return {
    attributes: [{ name: KANON_CRED_ID_ATTRIBUTE, value: credId }, ...attrs],
    credId,
  }
}
