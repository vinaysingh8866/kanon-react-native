import type { AgentContext } from '@credo-ts/core'

import { injectable } from '@credo-ts/core'

import { KanonClientService } from '../ledger'

import { KanonZkService } from './KanonZkService'

/**
 * Read-only Mode B introspection surface. Mounted on
 * `agent.modules.kanon.api.zk`.
 *
 * **Why no `revoke` here.** Mode B revoke is reached through the
 * canonical, mask-aware `KanonApi.revokeCredential(credDefId, credId)`,
 * which reads each credDef's on-chain `policyMask` and dispatches to Mode A
 * and/or Mode B without the caller having to know which tier was chosen at
 * registration. A dedicated `zk.revoke` would either duplicate that
 * routing or silently bypass it for Mode-A-only credDefs — both worse than
 * the single entry point. This API is therefore *introspection only*.
 */
@injectable()
export class KanonZkApi {
  public constructor(
    private readonly zkService: KanonZkService,
    private readonly clientService: KanonClientService,
    private readonly agentContext: AgentContext
  ) {}

  /**
   * Read-only snapshot of the active leaf set for a credDef. Useful for
   * dashboards / debug. Triggers a lazy reconstruct on first call after
   * restart (one chain scan per credDef per process).
   */
  public async getActiveLeaves(credDefId: string): Promise<{ keccak: string[]; poseidon: string[] }> {
    const cp = await this.zkService.getCheckpoint(this.agentContext, credDefId)
    return cp.active
  }

  /** True iff the credDef opted in to `TIER_ZK_SNARK` at registration. */
  public async supportsZk(credDefId: string): Promise<boolean> {
    return this.clientService.client.credDefSupportsZk(credDefId)
  }

  /**
   * Force-refresh the local state by dropping the in-process cache and
   * re-running `reconstructFromChain`. Use after an out-of-band write
   * (e.g. another agent published a `batchUpdate`) when you need this
   * agent's view to catch up before the next event tick.
   */
  public async resync(credDefId: string): Promise<void> {
    this.zkService.invalidate(credDefId)
    await this.zkService.getOrInit(this.agentContext, credDefId)
  }
}
