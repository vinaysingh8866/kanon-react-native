import type { AgentContext } from '@credo-ts/core'

import { injectable } from '@credo-ts/core'
// 0.5 doesn't re-export GenericRecordsApi from the root — see the comment
// in KanonZkIssuerKeyService for context.
import { GenericRecordsApi } from '@credo-ts/core/build/modules/generic-records/GenericRecordsApi'
import { ethers } from 'ethers'

import { KanonClientService } from '../ledger'

/**
 * Merkle path discovery for Mode B presentations.
 *
 * The holder needs `(pathElements, pathIndices, root)` for the credential's
 * Poseidon leaf so the SNARK can prove non-revocation. The tree is rebuilt by
 * replaying every `CredentialAdded` / `CredentialRevoked` event the issuer
 * has published under `credDefId`, then constructing the tagged `PoseidonTree`
 * the circuit verifies against.
 *
 * Persistence: the replayed active-leaf list is cached per credDef in
 * `GenericRecordsApi` so subsequent presentations don't re-scan the chain
 * from genesis — only `(lastSyncedBlock, currentBlock]` is replayed. The
 * cache survives agent restarts and is keyed by `kanon-zk-path-cache:<credDefId>`.
 *
 * Concurrency: a per-credDef in-process lock prevents two concurrent
 * `findPath` calls from racing on the same cache record. The lock is
 * advisory; if your agent runs multiple instances with shared storage you
 * should fence at the storage layer instead.
 */
@injectable()
export class KanonZkPathService {
  /**
   * Per-credDef serialization queue. Each `findPath` call chains onto the
   * previous one for the same credDef so two concurrent presentations don't
   * race on the GenericRecords-backed cache record. The previous "acquire /
   * release" lock had a window between `await existing` and `locks.set` that
   * let two callers both proceed — this single-flight chain closes it.
   */
  private readonly queues = new Map<string, Promise<unknown>>()

  public constructor(private readonly clientService: KanonClientService) {}

  /**
   * Resolve the Merkle inclusion proof for `poseidonLeaf` under `credDefId`.
   *
   * Returns `null` if the leaf isn't in the current active set (e.g. it was
   * revoked, or it was never published — most often a sign the holder fired
   * a presentation before the issuance batch landed on chain).
   *
   * `wantRoot` shouldn't usually be supplied; it's there for tests that need
   * to pin against a specific historical root.
   */
  public async findPath(
    agentContext: AgentContext,
    credDefId: string,
    poseidonLeaf: bigint,
    wantRoot?: bigint
  ): Promise<{
    pathElements: bigint[]
    pathIndices: number[]
    root: bigint
    leafIndex: number
  } | null> {
    return this.withLock(credDefId, async () => {
      const active = await this.replayActive(agentContext, credDefId)
      const leafIndex = active.findIndex((v) => v === poseidonLeaf)
      if (leafIndex < 0) return null

      const sdk = await import('@ajna-inc/kanon-sdk')
      await sdk.zk.initPoseidon()
      // 26 = the compiled circuit depth. Mirrors `non_revocation.circom`'s
      // `MerkleInclusion(26)` so the path the prover supplies has the same
      // length the circuit consumes.
      const tree = new sdk.zk.PoseidonTree(26, active)
      const root = tree.root
      if (wantRoot !== undefined && root !== wantRoot) {
        // Caller pinned a root and we didn't reproduce it — the local cache
        // is stale relative to whatever they expected.
        return null
      }
      const { pathElements, pathIndices } = tree.proof(leafIndex)
      return { pathElements, pathIndices, root, leafIndex }
    })
  }

  /**
   * Run `fn` exclusively for `credDefId`. Concurrent calls for the same
   * credDef execute one-at-a-time in FIFO order; calls for different credDefs
   * are independent. Failures are isolated — a thrown `fn` doesn't poison the
   * queue for the next caller.
   */
  private withLock<T>(credDefId: string, fn: () => Promise<T>): Promise<T> {
    const key = credDefId.toLowerCase()
    const last = this.queues.get(key) ?? Promise.resolve()
    // Recover from previous failure with `.catch(() => {})` so the queue
    // keeps moving. The returned promise still rejects with the original
    // error so the caller sees it.
    const next = last.catch(() => undefined).then(fn)
    this.queues.set(key, next.catch(() => undefined))
    return next
  }

  /** Drop the cached active set for a credDef so the next call re-scans from genesis. */
  public async invalidate(agentContext: AgentContext, credDefId: string): Promise<void> {
    const records = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const existing = await records.findById(this.cacheRecordId(credDefId)).catch(() => null)
    if (existing) await records.delete(existing)
  }

  // ─── internals ────────────────────────────────────────────────────────

  private async replayActive(
    agentContext: AgentContext,
    credDefId: string
  ): Promise<bigint[]> {
    const records = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const recordId = this.cacheRecordId(credDefId)
    const cached = await records.findById(recordId).catch(() => null)

    let lastSyncedBlock = 0
    const active: bigint[] = []
    if (cached) {
      const content = cached.content as { lastSyncedBlock?: number; poseidon?: string[] }
      lastSyncedBlock = content.lastSyncedBlock ?? 0
      const seeds = content.poseidon ?? []
      for (const hex of seeds) active.push(BigInt(hex))
    }

    const registry = this.clientService.contracts.merkleStateRegistry
    const provider = this.clientService.getSigner().provider
    if (!provider) {
      throw new Error('KanonZkPathService: no provider on signer — agent must have an RPC URL configured')
    }
    const currentBlock = await provider.getBlockNumber()
    if (currentBlock < lastSyncedBlock) return active // local clock-skew safety

    // Replay both event topics under the credDef. We can't rely on getEvents
    // helpers in the SDK at this level — go direct via ethers so we don't
    // pull in additional indirection.
    const addedTopic = (registry as unknown as ethers.BaseContract).filters?.CredentialAdded?.(credDefId)
    const revokedTopic = (registry as unknown as ethers.BaseContract).filters?.CredentialRevoked?.(credDefId)

    const FROM = lastSyncedBlock + 1
    const TO = currentBlock

    const fromBlockSafe = FROM > TO ? TO : FROM

    // Pull `blockNumber`, `transactionIndex` and `logIndex` per event so
    // adds + revokes that land in the same `batchUpdate` tx replay in
    // chain order. `queryFilter` returns events per-filter, so concat'ing
    // without these tie-breakers would lose within-block ordering — fine
    // when only one event type fires per block, broken on the common case
    // where `batchUpdate` adds AND revokes in the same tx.
    type EventQuery = (
      filter: ethers.DeferredTopicFilter,
      fromBlock: number,
      toBlock: number
    ) => Promise<
      Array<{
        args: { keccak: string; poseidon: string }
        blockNumber: number
        transactionIndex: number
        logIndex: number
      }>
    >
    const queryFilter = (registry as unknown as { queryFilter: EventQuery }).queryFilter

    const addedEvents = addedTopic
      ? await queryFilter.call(registry, addedTopic, fromBlockSafe, TO)
      : []
    const revokedEvents = revokedTopic
      ? await queryFilter.call(registry, revokedTopic, fromBlockSafe, TO)
      : []

    interface ReplayEvent {
      kind: 'add' | 'remove'
      poseidon: bigint
      block: number
      txIndex: number
      logIndex: number
    }
    const combined: ReplayEvent[] = []
    for (const e of addedEvents) {
      combined.push({
        kind: 'add',
        poseidon: BigInt(e.args.poseidon),
        block: e.blockNumber,
        txIndex: e.transactionIndex,
        logIndex: e.logIndex,
      })
    }
    for (const e of revokedEvents) {
      combined.push({
        kind: 'remove',
        poseidon: BigInt(e.args.poseidon),
        block: e.blockNumber,
        txIndex: e.transactionIndex,
        logIndex: e.logIndex,
      })
    }
    combined.sort((a, b) => {
      if (a.block !== b.block) return a.block - b.block
      if (a.txIndex !== b.txIndex) return a.txIndex - b.txIndex
      return a.logIndex - b.logIndex
    })

    for (const e of combined) {
      if (e.kind === 'add') {
        active.push(e.poseidon)
      } else {
        const idx = active.findIndex((v) => v === e.poseidon)
        if (idx >= 0) active.splice(idx, 1)
      }
    }

    const newRecord = {
      lastSyncedBlock: TO,
      poseidon: active.map((v) => '0x' + v.toString(16).padStart(64, '0')),
    }
    if (cached) {
      cached.content = newRecord as unknown as Record<string, unknown>
      await records.update(cached)
    } else {
      await records.save({
        id: recordId,
        content: newRecord as unknown as Record<string, unknown>,
        tags: { type: 'kanon-zk-path-cache', credDefId: credDefId.toLowerCase() },
      })
    }
    return active
  }

  private cacheRecordId(credDefId: string): string {
    return `kanon-zk-path-cache:${credDefId.toLowerCase()}`
  }
}
