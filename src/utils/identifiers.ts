/**
 * did:kanon identifier parsing for the kanon registries.
 *
 * kanon binds the DID identifier to its subject, so there are exactly two
 * shapes (no free-form network segment like the legacy method had):
 *
 *   * org-scoped  : `did:kanon:org:0x<64 hex>`  (the bytes32 orgId)
 *   * user-scoped : `did:kanon:user:0x<64 hex>`  (bound to controller+salt)
 *
 * AnonCreds resource IDs are DID URLs under the issuer DID, e.g.
 * `did:kanon:org:0x<64 hex>/anoncreds/v0/SCHEMA/<name>/<version>`.
 *
 * Parsing is delegated to the SDK's `parseKanonDid` so the on-chain convention
 * stays authoritative; this module adapts the result into a Credo `ParsedDid`.
 */
import type { ParsedDid } from '@credo-ts/core'

import {
  orgDid,
  parseKanonDid as sdkParseKanonDid,
  userDid,
  type ParsedKanonDid as SdkParsedKanonDid,
} from '@ajna-inc/kanon-sdk/anoncreds'

export { orgDid, userDid }

const ORG_ID = String.raw`(?<orgId>0x[0-9a-fA-F]{64})`
const USER_HEX = String.raw`(?<userHex>0x[0-9a-fA-F]{64})`
const SUBJECT = String.raw`(?:org:${ORG_ID}|user:${USER_HEX})`
const PATH = String.raw`(?<path>/[^#?]*)?`
const QUERY = String.raw`(?<query>\?[^#]*)?`
const FRAGMENT = String.raw`(?<fragment>#.*)?`

/** Matches a bare did:kanon DID (no path/query/fragment). */
export const kanonDidRegex = new RegExp(`^did:kanon:${SUBJECT}$`)

/** Matches a did:kanon DID URL (with optional path/query/fragment). */
export const kanonDidUrlRegex = new RegExp(`^did:kanon:${SUBJECT}${PATH}${QUERY}${FRAGMENT}$`)

/**
 * Matches anything starting with `did:kanon:` — used as the resolver's
 * `supportedMethods` guard and the AnonCreds registry's `supportedIdentifier`
 * (schema / credDef IDs are DID URLs under the issuer DID).
 */
export const kanonPrefixRegex = /^did:kanon:.+$/

export type ParsedKanonDid = ParsedDid & {
  scope: SdkParsedKanonDid['scope']
  /** bytes32 orgId as a 0x<64 hex> string (org-scoped DIDs only). */
  orgId?: string
  userHex?: string
}

/** Return the decomposed did:kanon URI, or null if it does not match. */
export function parsekanonDid(didUrl: string): ParsedKanonDid | null {
  if (!didUrl) return null
  const parsed = sdkParseKanonDid(didUrl)
  if (!parsed) return null
  return {
    did: parsed.did,
    method: 'kanon',
    id: parsed.scope === 'org' ? (parsed.orgId ?? '') : (parsed.userHex ?? ''),
    didUrl,
    scope: parsed.scope,
    orgId: parsed.orgId,
    userHex: parsed.userHex,
    path: parsed.path,
  }
}
