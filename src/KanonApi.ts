import { AgentContext, injectable } from '@credo-ts/core'

import { resourceIdToBytes32 } from '@ajna-inc/kanon-sdk/anoncreds'

import { kanonCredIdHash } from './anoncreds/utils/credIdHash'
import { KanonClientService } from './ledger'
import { KanonZkApi, KanonZkService } from './zk'

/**
 * Normalize a credDefId to its on-chain bytes32 form.
 *
 * The AnonCreds module emits credDefIds in the DID-URL form
 *   `did:kanon:org:0x.../anoncreds/v0/CLAIM_DEF/<schemaTag>/<tag>`
 * — but the on-chain registries are keyed by the bytes32 hash of that URL.
 * Every method on this API previously required callers to convert by hand
 * via `resourceIdToBytes32`, which produced the worst kind of surprise when
 * a caller passed the URL form and ethers' ABI encoder threw a cryptic
 * "Invalid byte-string" error halfway through a contract call. We accept
 * either form here and forward the bytes32 to the SDK.
 */
function toBytes32CredDefId(credDefId: string): string {
  // Already bytes32: 0x + 64 hex chars. Accept and return as-is.
  if (/^0x[0-9a-fA-F]{64}$/.test(credDefId)) return credDefId
  return resourceIdToBytes32(credDefId)
}

/**
 * High-level facade over {@link KanonClientService}'s AnonCredsStatusRegistry
 * methods. Each operation takes a `credDefId` — either the on-chain bytes32
 * form OR the DID-URL form emitted by the AnonCreds module; we normalize on
 * the way in — and a `credId` (the human-readable id placed in the
 * `kanonCredId` attribute, hashed on the caller's behalf).
 */
@injectable()
export class KanonApi {
  private agentContext: AgentContext

  public constructor(agentContext: AgentContext) {
    this.agentContext = agentContext
  }

  private get ledger(): KanonClientService {
    return this.agentContext.dependencyManager.resolve(KanonClientService)
  }

  /** Mode B (Groth16 non-revocation) revoke + introspection surface. */
  public get zk(): KanonZkApi {
    return this.agentContext.dependencyManager.resolve(KanonZkApi)
  }

  /**
   * Writes an issuance record to `AnonCredsStatusRegistry`. Idempotent on the
   * contract side; safe to call after `KanonIssuanceTracker` has already done it.
   */
  public async issueCredentialOnChain(credDefId: string, credId: string) {
    return this.ledger.issueCredentialStatus(toBytes32CredDefId(credDefId), kanonCredIdHash(credId))
  }

  /**
   * Marks the (credDefId, credIdHash) pair as revoked on-chain. **Mode A only**
   * — writes to AnonCredsStatusRegistry. Skips the write (no-op) when the
   * credDef did not opt into TIER_ONE_TIME; in that case use `zk.revoke`.
   */
  public async revokeCredentialOnChain(credDefId: string, credId: string) {
    return this.ledger.revokeCredentialStatus(toBytes32CredDefId(credDefId), kanonCredIdHash(credId))
  }

  /**
   * Canonical revoke entry point. Reads the credDef's on-chain `policyMask`
   * and writes to every tier it opted into:
   *   - `TIER_ONE_TIME` → AnonCredsStatusRegistry.revokeCredential
   *   - `TIER_ZK_SNARK` → MerkleStateRegistry.batchUpdate (rotates the root)
   *
   * Callers shouldn't reach for `revokeCredentialOnChain` (Mode A only) or
   * the internal `KanonZkService.revoke` directly — this method routes
   * correctly without the caller having to track the mask.
   */
  public async revokeCredential(credDefId: string, credId: string): Promise<void> {
    const client = this.ledger.client
    const credDefIdBytes32 = toBytes32CredDefId(credDefId)
    const mask = await client.getCredDefPolicy(credDefIdBytes32)
    const TIER_ONE_TIME = 0b01
    const TIER_ZK_SNARK = 0b10
    if ((mask & TIER_ONE_TIME) !== 0 && this.ledger.hasAnonCredsStatusRegistry()) {
      await this.ledger.revokeCredentialStatus(credDefIdBytes32, kanonCredIdHash(credId))
    }
    if ((mask & TIER_ZK_SNARK) !== 0) {
      const zkService = this.agentContext.dependencyManager.resolve(KanonZkService)
      // KanonZkService internally handles both forms when it queries on chain,
      // but pass through the original here so the cache keys match across
      // the rest of the plugin (which uses the DID-URL form as record id).
      await zkService.revoke(this.agentContext, credDefId, [credId])
    }
  }

  /**
   * Reads the revocation flag from the on-chain status registry.
   */
  public async isCredentialRevokedOnChain(credDefId: string, credId: string): Promise<boolean> {
    return this.ledger.isCredentialRevokedOnStatus(toBytes32CredDefId(credDefId), kanonCredIdHash(credId))
  }

  /**
   * Reads the full status enum (issued / revoked / unknown depending on contract).
   */
  public async getCredentialStatus(credDefId: string, credId: string): Promise<number> {
    return this.ledger.getCredentialStatus(toBytes32CredDefId(credDefId), kanonCredIdHash(credId))
  }
}
