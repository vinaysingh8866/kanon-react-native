import type { AgentContext } from '@credo-ts/core'
import type { KanonZkIssuerKey } from '@ajna-inc/kanon-sdk'

import { injectable } from '@credo-ts/core'
// `GenericRecordsApi` isn't re-exported from credo-ts 0.5's root entry —
// only from the deep module path. credo-ts 0.6 lifted it to the root, which
// is why the v6 plugin imports it directly from '@credo-ts/core'.
import { GenericRecordsApi } from '@credo-ts/core/build/modules/generic-records/GenericRecordsApi'
import {
  generateZkIssuerKey,
  restoreZkIssuerKey,
} from '@ajna-inc/kanon-sdk'

/**
 * Tier-2 BabyJubjub issuer key lifecycle (off-chain only).
 *
 * Mode B requires the issuer's BabyJubjub public key to be published on chain
 * via `CredentialDefinitionRegistry.registerCredentialDefinition(..., ax, ay)`
 * — registration and key publication happen atomically in one transaction. So
 * this service does NOT touch chain: it just generates + persists the keypair
 * so the registration caller can read `(ax, ay)` to pass through and so the
 * issuance side can later read the private key to sign credential leaves.
 *
 * Persistence: `GenericRecordsApi`, one record per credDef, keyed by
 * `kanon-zk-issuer-key:<lowercased credDefId>`. The wallet encrypts records at
 * rest, so the on-disk form is safe; the in-memory exposure surface is the
 * hex string between load + use.
 *
 * Hardening choices in this implementation:
 *
 *   - We cache ONLY the public key (`Ax`, `Ay`). Public coords are safe to
 *     keep — they're literally published on chain. The PRIVATE key is loaded
 *     from the wallet on every signing operation and discarded immediately
 *     after.
 *
 *   - `withPrivateKey(fn)` lets callers compute with the privkey in a tight
 *     scope. The privkey buffer is best-effort overwritten before returning,
 *     mitigating heap-dump exposure (JS doesn't guarantee zeroing — GC may
 *     have copied it — but this still removes the strong reference).
 *
 *   - `provision()` is serialized per credDef via a single-flight lock. Two
 *     concurrent calls for the same credDef can't both generate fresh keys
 *     and race on the GenericRecords write — the second caller blocks on the
 *     first and observes the persisted result.
 *
 * Idempotent: `provision` returns the existing key if already persisted.
 * Rotating is unsupported — it would silently break every previously-issued
 * Mode B proof.
 */
@injectable()
export class KanonZkIssuerKeyService {
  /**
   * In-process cache for the PUBLIC key only. The public coords are safe to
   * cache — they're on chain anyway. We deliberately do NOT cache the
   * private key; it's loaded from the wallet on every use and the hex
   * string is dropped as soon as the closure that uses it returns.
   */
  private readonly publicKeyCache = new Map<string, { Ax: bigint; Ay: bigint }>()

  /**
   * Per-credDef single-flight queue so two concurrent `provision()` calls
   * for the same credDef can't both generate fresh keys and race on the
   * GenericRecords write. Same pattern as `KanonZkPathService.withLock`.
   */
  private readonly provisionQueues = new Map<string, Promise<unknown>>()

  /**
   * Generate a fresh BJJ keypair for `credDefId` if one isn't persisted yet,
   * and return it. Pass `(key.publicKey.Ax, key.publicKey.Ay)` to
   * `registerCredentialDefinition` in the same flow.
   *
   * Concurrent calls for the same credDef serialize — only ONE generates a
   * fresh key; the rest observe the persisted record.
   */
  public async provision(
    agentContext: AgentContext,
    credDefId: string
  ): Promise<KanonZkIssuerKey> {
    return this.withProvisionLock(credDefId, async () => {
      const records = agentContext.dependencyManager.resolve(GenericRecordsApi)
      const existing = await records.findById(this.recordId(credDefId)).catch(() => null)
      if (existing) {
        const restored = await this.restore(existing.content)
        this.publicKeyCache.set(credDefId.toLowerCase(), restored.publicKey)
        return restored
      }

      const fresh = await generateZkIssuerKey()
      await records.save({
        id: this.recordId(credDefId),
        content: {
          privateKeyHex: fresh.privateKeyHex,
          ax: fresh.publicKey.Ax.toString(),
          ay: fresh.publicKey.Ay.toString(),
        },
        tags: { type: 'kanon-zk-issuer-key', credDefId: credDefId.toLowerCase() },
      })
      this.publicKeyCache.set(credDefId.toLowerCase(), fresh.publicKey)
      return fresh
    })
  }

  /**
   * Public-key-only accessor. Hits the in-process cache when warm; otherwise
   * reads from the wallet but discards the privkey hex on return. Used by
   * Mode B presentation flow (which needs `(Ax, Ay)` as a public input).
   */
  public async loadPublicKey(
    agentContext: AgentContext,
    credDefId: string
  ): Promise<{ Ax: bigint; Ay: bigint }> {
    const cacheKey = credDefId.toLowerCase()
    const cached = this.publicKeyCache.get(cacheKey)
    if (cached) return cached
    const records = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const existing = await records.findById(this.recordId(credDefId)).catch(() => null)
    if (!existing) {
      throw new Error(
        `KanonZkIssuerKeyService: no issuer key persisted for ${credDefId} — call provision() during credDef registration`
      )
    }
    const content = existing.content as Record<string, unknown>
    // Prefer the stored ax/ay strings (avoid touching the privkey) when
    // present. Fall back to deriving from privkey if the record was written
    // by an older version of the service.
    const ax =
      typeof content.ax === 'string' ? BigInt(content.ax) : undefined
    const ay =
      typeof content.ay === 'string' ? BigInt(content.ay) : undefined
    if (ax !== undefined && ay !== undefined) {
      const pub = { Ax: ax, Ay: ay }
      this.publicKeyCache.set(cacheKey, pub)
      return pub
    }
    const restored = await this.restore(existing.content)
    this.publicKeyCache.set(cacheKey, restored.publicKey)
    return restored.publicKey
  }

  /**
   * Run `fn` with the issuer's BabyJubjub private key for `credDefId`.
   *
   * The privkey is loaded from the wallet, passed to `fn`, and the local
   * reference dropped on return. Callers MUST do their signing inside `fn`
   * and not stash the hex string elsewhere — the entire point is to keep
   * the strong reference scoped tightly.
   *
   * We make a best-effort attempt to overwrite the hex string buffer before
   * returning. JavaScript doesn't guarantee deletion (the GC may have copied
   * the string elsewhere) but removing the obvious reference reduces the
   * window for a heap-dump attacker.
   */
  public async withPrivateKey<T>(
    agentContext: AgentContext,
    credDefId: string,
    fn: (key: KanonZkIssuerKey) => Promise<T>
  ): Promise<T> {
    const records = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const existing = await records.findById(this.recordId(credDefId)).catch(() => null)
    if (!existing) {
      throw new Error(
        `KanonZkIssuerKeyService: no issuer key persisted for ${credDefId} — call provision() during credDef registration`
      )
    }
    const content = existing.content as Record<string, unknown>
    const privateKeyHex = content.privateKeyHex
    if (typeof privateKeyHex !== 'string') {
      throw new Error('KanonZkIssuerKeyService: corrupt key record (no privateKeyHex)')
    }
    const restored = await restoreZkIssuerKey(privateKeyHex)
    try {
      return await fn(restored)
    } finally {
      // Best-effort zeroize: strings are immutable in JS so we can't actually
      // overwrite the existing hex chars, but blanking the property removes
      // the strong reference held by `restored`. The GC will collect when no
      // other reference is held — typically right after this finally block.
      try {
        ;(restored as { privateKeyHex?: string }).privateKeyHex = ''
      } catch {
        /* not strict-mode-locked, ignored */
      }
    }
  }

  /**
   * Legacy method retained for transition. Now equivalent to
   * `loadPublicKey` for the public coords + best-effort drop of the privkey
   * reference immediately. Prefer `loadPublicKey` (read-only fast path) or
   * `withPrivateKey(fn)` (scoped signing) directly.
   *
   * @deprecated use `loadPublicKey` or `withPrivateKey` instead.
   */
  public async load(
    agentContext: AgentContext,
    credDefId: string
  ): Promise<KanonZkIssuerKey> {
    const records = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const existing = await records.findById(this.recordId(credDefId)).catch(() => null)
    if (!existing) {
      throw new Error(
        `KanonZkIssuerKeyService: no issuer key persisted for ${credDefId} — call provision() during credDef registration`
      )
    }
    const restored = await this.restore(existing.content)
    this.publicKeyCache.set(credDefId.toLowerCase(), restored.publicKey)
    return restored
  }

  // ─── internals ────────────────────────────────────────────────────────

  private async restore(content: unknown): Promise<KanonZkIssuerKey> {
    const record = content as Record<string, unknown>
    const privateKeyHex = record.privateKeyHex
    if (typeof privateKeyHex !== 'string') {
      throw new Error('KanonZkIssuerKeyService: corrupt key record (no privateKeyHex)')
    }
    return restoreZkIssuerKey(privateKeyHex)
  }

  /**
   * Per-credDef single-flight queue. Each `provision` call chains onto the
   * previous one for the same credDef. Failure in one doesn't poison the
   * queue for the next caller — `.catch(() => undefined)` keeps it moving.
   */
  private withProvisionLock<T>(credDefId: string, fn: () => Promise<T>): Promise<T> {
    const key = credDefId.toLowerCase()
    const last = this.provisionQueues.get(key) ?? Promise.resolve()
    const next = last.catch(() => undefined).then(fn)
    this.provisionQueues.set(key, next.catch(() => undefined))
    return next
  }

  private recordId(credDefId: string): string {
    return `kanon-zk-issuer-key:${credDefId.toLowerCase()}`
  }
}
