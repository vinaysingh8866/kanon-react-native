import type { AnonCredsHolderService, AnonCredsVerifierService } from '@credo-ts/anoncreds'
import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'

import { AnonCredsHolderServiceSymbol, AnonCredsVerifierServiceSymbol } from '@credo-ts/anoncreds'

import { KanonApi } from './KanonApi'
import {
  KanonIssuanceTracker,
  KanonWrappedAnonCredsHolderService,
  KanonWrappedAnonCredsVerifierService,
  OriginalAnonCredsHolderServiceSymbol,
  OriginalAnonCredsVerifierServiceSymbol,
} from './anoncreds'
import { KanonDidRegistrar, KanonDidResolver } from './dids'
import { KanonModuleConfig, type KanonModuleConfigOptions } from './KanonModuleConfig'
import { KanonClientService } from './ledger'
import {
  KanonZkApi,
  KanonZkIssuerKeyService,
  KanonZkPathService,
  KanonZkService,
} from './zk'

export class KanonModule implements Module {
  public readonly config: KanonModuleConfig
  public readonly api = KanonApi

  public constructor(configOptions: KanonModuleConfigOptions) {
    this.config = new KanonModuleConfig(configOptions)
  }

  public register(dependencyManager: DependencyManager) {
    // Register config
    dependencyManager.registerInstance(KanonModuleConfig, this.config)

    // Core singletons
    dependencyManager.registerSingleton(KanonClientService)
    dependencyManager.registerSingleton(KanonIssuanceTracker)
    dependencyManager.registerSingleton(KanonDidRegistrar)
    dependencyManager.registerSingleton(KanonDidResolver)
    // Mode B (Groth16 non-revocation) — restart-survivable issuer state +
    // public revoke API. Holds an IssuerService per credDef in-process, with
    // a GenericRecords-backed checkpoint so cold start resumes from the last
    // synced block instead of replaying the chain from genesis.
    dependencyManager.registerSingleton(KanonZkIssuerKeyService)
    dependencyManager.registerSingleton(KanonZkPathService)
    dependencyManager.registerSingleton(KanonZkService)
    dependencyManager.registerSingleton(KanonZkApi)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    const dm = agentContext.dependencyManager

    // Wrap the AnonCreds verifier + holder services HERE (in `initialize`),
    // not in `register`. The two symbols we override
    // (`AnonCredsHolderServiceSymbol`, `AnonCredsVerifierServiceSymbol`)
    // are bound by `AnonCredsModule.register`, and Credo's
    // `DependencyManager` runs every module's `register` before any
    // module's `initialize`. Doing the wrapping in `register` would
    // require KanonModule to be listed AFTER `AnonCredsModule` in the
    // user's `modules` map AND for Credo to honour that insertion order
    // when iterating — fragile across Credo versions. Wrapping at
    // `initialize` time avoids the ordering constraint entirely.
    if (this.config.anonCredsStatusRegistryAddress || this.config.addressBook) {
      const originalVerifier = dm.resolve<AnonCredsVerifierService>(AnonCredsVerifierServiceSymbol)
      dm.registerInstance(OriginalAnonCredsVerifierServiceSymbol, originalVerifier)
      dm.registerSingleton(AnonCredsVerifierServiceSymbol, KanonWrappedAnonCredsVerifierService)
    }

    // Mode B holder wrapper — at presentation time, this intercepts
    // `createProof`, computes the Groth16 SNARK over the non-revocation
    // circuit, and injects it as a `kanonZkProof` self-attested attribute
    // on the credo presentation response. Mode A credentials are left
    // untouched.
    const originalHolder = dm.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)
    dm.registerInstance(OriginalAnonCredsHolderServiceSymbol, originalHolder)
    dm.registerSingleton(AnonCredsHolderServiceSymbol, KanonWrappedAnonCredsHolderService)

    // Eagerly resolve so the client service picks up its config, and resolve the
    // registries from the address book (no-op for explicit deployments).
    const clientService = dm.resolve(KanonClientService)
    await clientService.init()

    // The tracker handles Mode A AND Mode B issuance routing based on each
    // credDef's on-chain policyMask. Attach unconditionally so Mode-B-only
    // deployments (no AnonCredsStatusRegistry) still publish leaves; the
    // tracker logs + skips Mode A when the status registry is missing.
    const tracker = dm.resolve(KanonIssuanceTracker)
    tracker.attach(agentContext)
  }
}
