import type { AgentContext } from '@credo-ts/core'
import type { IssuerSyncCheckpoint } from '@ajna-inc/kanon-sdk'

import { IssuerService, issuer as sdkIssuer } from '@ajna-inc/kanon-sdk'
import { injectable } from '@credo-ts/core'
// Credo 0.5 does not re-export GenericRecordsApi from the package root (it
// was added to the public surface in 0.6). Import it from the module path so
// the class can be used both as the DI resolution token and for typing.
import { GenericRecordsApi } from '@credo-ts/core/build/modules/generic-records/GenericRecordsApi'

import { KanonClientService } from '../ledger'

/**
 * Internal record type for the per-credDef sync checkpoint. The plugin stores
 * one record per credDef; the record id encodes the credDef so lookups are
 * deterministic without a separate index.
 */
const CHECKPOINT_RECORD_TYPE = 'kanon-zk-sync'
const checkpointRecordId = (credDefId: string): string => `kanon-zk-sync:${credDefId.toLowerCase()}`

/** Circuit-fixed attribute count. Mirrors `nAttr` in `non_revocation.circom`. */
export const KANON_ZK_CIRCUIT_ATTRS = 16

/**
 * Pad / truncate a felt array to the circuit's 16-felt attribute width.
 * Throws when the caller has more attributes than the circuit supports — that
 * is a schema-design problem the caller has to fix, not a silent truncation.
 */
export function padAttrsToCircuit(attrs: bigint[]): bigint[] {
  if (attrs.length > KANON_ZK_CIRCUIT_ATTRS) {
    throw new Error(
      `kanon-zk: schema has ${attrs.length} attributes but the circuit only supports ${KANON_ZK_CIRCUIT_ATTRS}. Reduce the schema or recompile with a higher nAttr.`
    )
  }
  const out = attrs.slice()
  while (out.length < KANON_ZK_CIRCUIT_ATTRS) out.push(0n)
  return out
}

/**
 * Restart-survivable Mode B (Groth16 non-revocation) facade for the credo
 * plugin. Maintains a lazy-initialised `IssuerService` per credDef.
 *
 * Cold start:
 *
 *   1. Caller asks for `getOrInit(credDefId)`.
 *   2. The service looks up a persisted checkpoint in `GenericRecordsApi`.
 *   3. If present, `loadCheckpoint` rehydrates the local active leaf set + the
 *      keccak↔poseidon companion map without touching chain.
 *   4. `reconstructFromChain(lastSyncedBlock)` then folds in any events that
 *      arrived since the snapshot.
 *   5. The updated checkpoint is persisted.
 *
 * Subsequent calls reuse the cached `IssuerService` in-process. Plugin reload
 * (agent shutdown) is survived by the persisted checkpoint.
 */
@injectable()
export class KanonZkService {
  private readonly cache = new Map<string, IssuerService>()

  public constructor(private readonly clientService: KanonClientService) {}

  /**
   * Get the issuer service for `credDefId`. Idempotent — subsequent calls
   * return the cached instance. The caller must ensure `clientService.init()`
   * has completed before invoking this.
   */
  public async getOrInit(agentContext: AgentContext, credDefId: string): Promise<IssuerService> {
    const key = credDefId.toLowerCase()
    const cached = this.cache.get(key)
    if (cached) return cached

    const records = agentContext.dependencyManager.resolve(GenericRecordsApi)

    // IssuerService requires an IssuerKeyPair but the revoke path does not use
    // it (keys only matter for SDK-side issuance which the credo plugin does
    // not perform — issuance goes through Credo's AnonCreds flow). A fresh
    // throwaway keypair keeps the constructor happy without cost.
    const dummyKeys = sdkIssuer.generateIssuerKeyPair()
    const service = new IssuerService(
      this.clientService.contracts,
      this.clientService.getSigner(),
      credDefId,
      dummyKeys
    )

    // 1. Hydrate from a persisted checkpoint if present.
    const existing = await records.findById(checkpointRecordId(credDefId)).catch(() => null)
    let lastSynced = 0
    if (existing) {
      try {
        const cp = existing.content as unknown as IssuerSyncCheckpoint
        service.loadCheckpoint(cp)
        lastSynced = cp.lastSyncedBlock
      } catch {
        // Stale / corrupt checkpoint — fall through and rescan from genesis.
        lastSynced = 0
      }
    }

    // 2. Incremental scan from the checkpoint forward.
    await service.reconstructFromChain(lastSynced)

    // 3. Persist the refreshed checkpoint.
    await this.persistCheckpoint(agentContext, credDefId, service.getCheckpoint())

    this.cache.set(key, service)
    return service
  }

  /**
   * Revoke `credIds` for `credDefId`. Lazy-initialises the issuer service if
   * needed, derives keccak leaves via the SDK, publishes `batchUpdate` to
   * MerkleStateRegistry, and re-persists the checkpoint so the local state
   * survives the next restart.
   */
  public async revoke(
    agentContext: AgentContext,
    credDefId: string,
    credIds: string[]
  ): Promise<void> {
    if (credIds.length === 0) return
    const service = await this.getOrInit(agentContext, credDefId)
    await service.revokeByCredId(credIds)
    await this.persistCheckpoint(agentContext, credDefId, service.getCheckpoint())
  }

  /**
   * Add issued credentials to the on-chain Merkle roots.
   *
   * For each `{credId, attributes}` we compute:
   *
   *   - Mode A leaf:  `deriveLeaf(keccak256(utf8(credId)))` — the OZ-keccak
   *                   tree leaf used by the nullifier path. Always computed
   *                   so revocation works even on Mode B-only credDefs (the
   *                   contract just won't accept Mode A consume on them).
   *   - Mode B leaf:  `Poseidon(LEAF_TAG, credDefId, credId, Poseidon(attrs))`
   *                   — the tagged leaf the `non_revocation.circom` circuit
   *                   recomputes from its inputs. Same value the issuer's
   *                   BabyJubjub signature was computed over inside
   *                   `KanonZkApi.prepareModeBCredential`.
   *
   * Both roots are recomputed over the FULL active set after folding the
   * new leaves in:
   *
   *   - Keccak root  → OZ-StandardMerkleTree.root (matches the on-chain
   *                    `MerkleStateRegistry.deriveLeaf` ordering).
   *   - Poseidon root → depth-26 tagged-Poseidon tree (matches
   *                    `non_revocation.circom`'s `MerkleInclusion`).
   *
   * No placeholders — mirrors the v6 plugin's `KanonZkService.addIssued`
   * byte-for-byte so a holder using either plugin generates the same
   * SNARK inputs.
   *
   * Backwards compat: a plain `string[]` of credIds is still accepted and
   * gets wrapped as `{credId, attributes: []}` so Mode-A-only callers
   * keep working. Those callers will get a leaf computed over a
   * zero-padded attribute vector — fine for Mode A revocation; not
   * meaningful for Mode B SNARK verification (and Mode B credDefs should
   * pass the real attributes anyway).
   */
  public async addIssued(
    agentContext: AgentContext,
    credDefId: string,
    credentials: Array<{ credId: string; attributes: bigint[] }> | string[]
  ): Promise<void> {
    if (credentials.length === 0) return
    const service = await this.getOrInit(agentContext, credDefId)
    const sdk = await import('@ajna-inc/kanon-sdk')

    // Normalise both call shapes to `{credId, attributes}`.
    const normalized: Array<{ credId: string; attributes: bigint[] }> =
      credentials.map((entry) =>
        typeof entry === 'string' ? { credId: entry, attributes: [] } : entry
      )

    // Reduce credDefId to the BN254 felt the on-chain registry binds against.
    const credDefFelt = BigInt(credDefId) % sdk.BN254_SCALAR_FIELD

    await sdk.zk.initPoseidon()

    const addedKeccak: string[] = []
    const addedPoseidon: string[] = []
    for (const { credId, attributes } of normalized) {
      // Mode A leaf: keccak path. `kanonCredIdHash` matches the SDK +
      // Python convention; `deriveLeaf` then does the OZ-standard
      // double-keccak.
      const credIdHash = sdk.kanonCredIdHash(credId)
      const keccakLeaf = sdk.deriveLeaf(credIdHash)

      // Mode B leaf: tagged Poseidon. The credId felt mirrors the
      // verifier side — same hash-then-reduce as the prep step.
      const credIdFelt = BigInt(credIdHash) % sdk.BN254_SCALAR_FIELD
      const padded: bigint[] = attributes.slice()
      while (padded.length < 16) padded.push(0n)
      const poseidonLeaf = await sdk.computeZkLeaf(credDefFelt, credIdFelt, padded)
      const poseidonLeafHex = '0x' + poseidonLeaf.toString(16).padStart(64, '0')

      addedKeccak.push(keccakLeaf)
      addedPoseidon.push(poseidonLeafHex)
    }

    // Fold the new leaves into local state.
    const cp = service.getCheckpoint()
    cp.active.keccak.push(...addedKeccak)
    cp.active.poseidon.push(...addedPoseidon)
    service.loadCheckpoint(cp)

    // Real depth-26 Poseidon-Merkle root over the WHOLE active set.
    const allKeccak = cp.active.keccak
    const keccakTree = new sdk.core.StandardMerkleTree(
      allKeccak.length > 0 ? allKeccak : ['0x' + '00'.repeat(32)]
    )
    const newKeccakRoot = keccakTree.root

    const allPoseidonBig = cp.active.poseidon.map((h) => BigInt(h))
    const poseidonTree = new sdk.zk.PoseidonTree(26, allPoseidonBig)
    const newPoseidonRoot =
      '0x' + poseidonTree.root.toString(16).padStart(64, '0')

    await this.clientService.contracts.merkleStateRegistry
      .connect(this.clientService.getSigner())
      .batchUpdate(
        credDefId,
        addedKeccak,
        addedPoseidon,
        [],
        [],
        newKeccakRoot,
        newPoseidonRoot
      )

    await this.persistCheckpoint(agentContext, credDefId, service.getCheckpoint())
  }

  /** Snapshot the current active-leaf set for a credDef (mostly for tests). */
  public async getCheckpoint(
    agentContext: AgentContext,
    credDefId: string
  ): Promise<IssuerSyncCheckpoint> {
    const service = await this.getOrInit(agentContext, credDefId)
    return service.getCheckpoint()
  }

  /** Drop the in-process cache for a credDef. Forces re-init on next call. */
  public invalidate(credDefId: string): void {
    this.cache.delete(credDefId.toLowerCase())
  }

  private async persistCheckpoint(
    agentContext: AgentContext,
    credDefId: string,
    checkpoint: IssuerSyncCheckpoint
  ): Promise<void> {
    const records = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const id = checkpointRecordId(credDefId)
    const existing = await records.findById(id).catch(() => null)
    if (existing) {
      existing.content = checkpoint as unknown as Record<string, unknown>
      await records.update(existing)
    } else {
      await records.save({
        id,
        content: checkpoint as unknown as Record<string, unknown>,
        tags: { type: CHECKPOINT_RECORD_TYPE, credDefId: credDefId.toLowerCase() },
      })
    }
  }
}
