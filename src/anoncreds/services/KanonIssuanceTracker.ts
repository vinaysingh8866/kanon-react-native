import type { AgentContext } from '@credo-ts/core'
import type { CredentialStateChangedEvent } from '@credo-ts/core'

import { CredentialEventTypes, EventEmitter, injectable } from '@credo-ts/core'
import type { Subscription } from 'rxjs'

import { KanonClientService } from '../../ledger'
import { KanonZkService } from '../../zk'
import { KANON_CRED_ID_ATTRIBUTE, kanonCredIdHash } from '../utils/credIdHash'

// Mirrors the SDK's TIER_* constants. Defined locally to avoid a runtime SDK
// import when only the bit-mask values are needed.
const TIER_ONE_TIME = 0b01
const TIER_ZK_SNARK = 0b10

/**
 * Subscribes to Credo's credential lifecycle events and writes an `issueCredential`
 * call to `AnonCredsStatusRegistry` once a credential is finalized on the issuer side.
 *
 * Reads the credential's `kanonCredId` attribute and the credential definition id
 * from the AnonCreds metadata on the record, hashes the credId via `kanonCredIdHash`,
 * and submits the tx. Logs and swallows failures so issuance never blocks on the
 * on-chain write; operators can retry via a separate reconciliation job.
 */
@injectable()
export class KanonIssuanceTracker {
  private subscriptions = new Map<string, Subscription>()
  // policyMask is immutable for the lifetime of a credDef on chain, so cache
  // it once per credDef. Refreshing requires plugin restart, which is fine —
  // the mask cannot be changed after registration.
  private policyMaskCache = new Map<string, number>()

  public constructor(
    private readonly ledgerService: KanonClientService,
    private readonly zkService: KanonZkService
  ) {}

  /**
   * Wire the listener to the given agent context. Safe to call multiple times for
   * the same context — the listener will only be attached once per contextId.
   */
  public attach(agentContext: AgentContext): void {
    // The tracker handles BOTH modes: Mode A writes to AnonCredsStatusRegistry,
    // Mode B writes to MerkleStateRegistry. The address book always exposes a
    // MerkleStateRegistry, but the AnonCreds status registry is optional in
    // older deployments. Only refuse to attach when neither surface is wired —
    // a deployment with only the MerkleStateRegistry is valid for Mode B-only
    // cred-defs.
    const hasStatus = this.ledgerService.hasAnonCredsStatusRegistry()
    if (!hasStatus) {
      agentContext.config.logger.warn(
        'KanonIssuanceTracker: AnonCredsStatusRegistry not configured. Mode A writes will be skipped; Mode B writes still attempted when the credDef opts in to TIER_ZK_SNARK.'
      )
    }
    if (this.subscriptions.has(agentContext.contextCorrelationId)) return

    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)
    const observable = eventEmitter.observable<CredentialStateChangedEvent>(
      CredentialEventTypes.CredentialStateChanged
    )

    const sub = observable.subscribe(async (event) => {
      try {
        await this.handleCredentialStateChanged(agentContext, event.payload)
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        agentContext.config.logger.error(
          `KanonIssuanceTracker: error handling CredentialStateChanged: ${message}`
        )
      }
    })

    this.subscriptions.set(agentContext.contextCorrelationId, sub)
  }

  public detach(agentContext: AgentContext): void {
    const sub = this.subscriptions.get(agentContext.contextCorrelationId)
    if (sub) {
      sub.unsubscribe()
      this.subscriptions.delete(agentContext.contextCorrelationId)
    }
  }

  private async handleCredentialStateChanged(
    agentContext: AgentContext,
    payload: CredentialStateChangedEvent['payload']
  ): Promise<void> {
    // The payload carries `credentialExchangeRecord` in current Credo versions; the
    // permissive `any` cast lets us read fields that vary across Credo versions.
    // biome-ignore lint/suspicious/noExplicitAny: credential record shape varies
    const record = (payload as any).credentialExchangeRecord ?? (payload as any).credentialRecord
    // Only react when the issuer side has finalized: state="done" and role="issuer".
    if (record?.state !== 'done' || record?.role !== 'issuer') return

    const credDefId = extractCredDefId(record)
    const credId = extractKanonCredId(record)
    if (!credDefId || !credId) {
      agentContext.config.logger.debug(
        `KanonIssuanceTracker: skipping — record missing credDefId or ${KANON_CRED_ID_ATTRIBUTE}`,
        { credentialRecordId: record?.id }
      )
      return
    }

    const credIdHash = kanonCredIdHash(credId)
    const policyMask = await this.getPolicyMask(agentContext, credDefId)

    // ── Mode A: AnonCredsStatusRegistry.issueCredential ──
    // Only writes when the credDef opted in to TIER_ONE_TIME AND the status
    // registry is configured for this agent. Skipping the write when the
    // credDef is ZK-only avoids the linkable on-chain trace that Mode B is
    // designed to avoid.
    if ((policyMask & TIER_ONE_TIME) !== 0) {
      if (!this.ledgerService.hasAnonCredsStatusRegistry()) {
        agentContext.config.logger.warn(
          `KanonIssuanceTracker: credDef ${credDefId} requires Mode A but AnonCredsStatusRegistry is not configured; skipping Mode A write`
        )
      } else {
        agentContext.config.logger.info(
          `KanonIssuanceTracker: Mode A issue ${credDefId} ${credIdHash}`
        )
        await this.ledgerService.issueCredentialStatus(credDefId, credIdHash)
      }
    } else {
      agentContext.config.logger.debug(
        `KanonIssuanceTracker: credDef ${credDefId} does not include TIER_ONE_TIME — skipping Mode A status write`
      )
    }

    // ── Mode B: MerkleStateRegistry.batchUpdate (publish leaf) ──
    if ((policyMask & TIER_ZK_SNARK) !== 0) {
      try {
        agentContext.config.logger.info(
          `KanonIssuanceTracker: Mode B publish leaf for ${credDefId}`
        )
        await this.zkService.addIssued(agentContext, credDefId, [credId])
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        agentContext.config.logger.error(
          `KanonIssuanceTracker: Mode B publish failed for ${credDefId}: ${message}`
        )
      }
    }
  }

  /**
   * Read + cache the on-chain `policyMask` for a credDef. The mask cannot
   * change after registration, so the per-credDef cache is safe for the
   * lifetime of the process.
   */
  private async getPolicyMask(agentContext: AgentContext, credDefId: string): Promise<number> {
    const cached = this.policyMaskCache.get(credDefId)
    if (cached !== undefined) return cached
    try {
      const mask = await this.ledgerService.client.getCredDefPolicy(credDefId)
      this.policyMaskCache.set(credDefId, mask)
      return mask
    } catch (err) {
      // Backward compat: if the credDef predates `policyMask` or the call
      // reverts, fall back to TIER_ONE_TIME so legacy Mode A behaviour is
      // preserved instead of silently dropping the status-registry write.
      const message = err instanceof Error ? err.message : String(err)
      agentContext.config.logger.warn(
        `KanonIssuanceTracker: getCredDefPolicy(${credDefId}) failed (${message}); defaulting to TIER_ONE_TIME`
      )
      this.policyMaskCache.set(credDefId, TIER_ONE_TIME)
      return TIER_ONE_TIME
    }
  }
}

/**
 * Returns the AnonCreds credential definition id from a Credo credential record.
 * Looks in several known metadata slots that Credo uses across versions.
 */
// biome-ignore lint/suspicious/noExplicitAny: record shape varies
function extractCredDefId(record: any): string | undefined {
  const meta = record?.metadata
  if (!meta) return undefined
  const candidates = [
    meta.get?.('_anoncreds/credential')?.credentialDefinitionId,
    meta.get?.('_anonCreds/credential')?.credentialDefinitionId,
    meta.get?.('_internal/anoncreds')?.credentialDefinitionId,
    meta.get?.('credentialDefinitionId'),
    record.credentialDefinitionId,
  ]
  return candidates.find((v) => typeof v === 'string' && v.length > 0)
}

/**
 * Returns the value of the `kanonCredId` attribute from the credential record's
 * credentialAttributes list.
 */
// biome-ignore lint/suspicious/noExplicitAny: record shape varies
function extractKanonCredId(record: any): string | undefined {
  // biome-ignore lint/suspicious/noExplicitAny: attribute shape varies
  const attrs: any[] = Array.isArray(record?.credentialAttributes) ? record.credentialAttributes : []
  const attr = attrs.find((a) => a?.name === KANON_CRED_ID_ATTRIBUTE)
  return typeof attr?.value === 'string' ? attr.value : undefined
}
