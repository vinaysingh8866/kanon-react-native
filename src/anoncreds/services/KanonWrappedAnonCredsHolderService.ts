import type {
  AnonCredsHolderService,
  CreateCredentialRequestOptions,
  CreateCredentialRequestReturn,
  CreateLinkSecretOptions,
  CreateLinkSecretReturn,
  CreateProofOptions,
  CreateW3cPresentationOptions,
  GetCredentialOptions,
  GetCredentialsForProofRequestOptions,
  GetCredentialsForProofRequestReturn,
  GetCredentialsOptions,
  LegacyToW3cCredentialOptions,
  StoreCredentialOptions,
  W3cToLegacyCredentialOptions,
} from '@credo-ts/anoncreds'
import type { AnonCredsCredentialInfo, AnonCredsProof } from '@credo-ts/anoncreds'
import type {
  AgentContext,
  W3cJsonLdVerifiableCredential,
  W3cJsonLdVerifiablePresentation,
} from '@credo-ts/core'

import {
  attrValueToFelt,
  BN254_SCALAR_FIELD,
  encodeAttributesCanonical,
  encodeKanonZkProofAttr,
  KANON_CRED_ID_ATTRIBUTE,
  KANON_ZK_PROOF_ATTRIBUTE,
  KANON_ZK_SIG_ATTRIBUTE,
  decodeZkSignature,
  kanonCredIdHash,
  computeZkLeaf,
} from '@ajna-inc/kanon-sdk'
import { ethers } from 'ethers'
import { inject, injectable } from '@credo-ts/core'

import { KanonClientService } from '../../ledger'
import { padAttrsToCircuit } from '../../zk/KanonZkService'
import { KanonZkPathService } from '../../zk/KanonZkPathService'

/**
 * DI token used by `KanonModule` to register the original
 * `AnonCredsRsHolderService` so the wrapper can inject it without depending
 * on a deep build path.
 */
export const OriginalAnonCredsHolderServiceSymbol = Symbol('OriginalAnonCredsHolderService')

/**
 * Bit mask of `TIER_ZK_SNARK`. Inlined to avoid a runtime SDK import for a
 * single-use constant.
 */
const TIER_ZK_SNARK = 0b10

/**
 * Wraps the AnonCredsRsHolderService so Mode B presentations are entirely
 * transparent to the application:
 *
 *   - Before `createProof` runs, the wrapper inspects the selected
 *     credentials. For each credentialDefinitionId that opts into
 *     `TIER_ZK_SNARK` on chain, it generates the Groth16 non-revocation proof
 *     and injects it as a self-attested attribute named
 *     `kanon_<credDefId>_zkProof`.
 *
 *   - The presentation that goes over the wire is a plain AnonCreds
 *     presentation. The self-attested attribute rides as a normal
 *     `requested_proof.self_attested_attrs` entry — anything that speaks
 *     AnonCreds can deserialize it, and the corresponding
 *     `KanonWrappedAnonCredsVerifierService` will verify it on chain.
 *
 *   - For Mode-A-only and non-Kanon credentials the wrapper is a no-op; the
 *     inner service handles them unchanged.
 *
 *   - Other methods on `AnonCredsHolderService` (createCredentialRequest,
 *     storeCredential, getCredentials, …) delegate to inner without
 *     modification.
 *
 * No DIDComm message extension, no proof-format URI change, no client-side
 * coordination: the holder just calls `agent.modules.proofs.acceptRequest(…)`
 * and the wrapper does the rest.
 */
@injectable()
export class KanonWrappedAnonCredsHolderService implements AnonCredsHolderService {
  /** Per-credDef on-chain policyMask cache; immutable after registration. */
  private readonly policyCache = new Map<string, number>()

  public constructor(
    @inject(OriginalAnonCredsHolderServiceSymbol) private readonly inner: AnonCredsHolderService,
    private readonly clientService: KanonClientService,
    private readonly pathService: KanonZkPathService
  ) {}

  public async createProof(
    agentContext: AgentContext,
    options: CreateProofOptions
  ): Promise<AnonCredsProof> {
    // Defensive: the BabyJubjub signature on the credential's leaf
    // (`kanonZkSig`) is a credential-unique handle. If a verifier asks the
    // holder to disclose it via a proof request, the holder would emit the
    // same value across every presentation — linkable across verifiers and
    // across time. The wrapper refuses to participate. Wallet UIs that
    // would otherwise silently include this attribute will surface this
    // error to the user.
    assertProofRequestDoesNotAskForKanonZkSig(agentContext, options)
    const augmented = await this.augmentSelfAttested(agentContext, options)
    return this.inner.createProof(agentContext, augmented)
  }

  // ─── transparent delegates ────────────────────────────────────────────

  public createLinkSecret(
    agentContext: AgentContext,
    options: CreateLinkSecretOptions
  ): Promise<CreateLinkSecretReturn> {
    return this.inner.createLinkSecret(agentContext, options)
  }

  public createCredentialRequest(
    agentContext: AgentContext,
    options: CreateCredentialRequestOptions
  ): Promise<CreateCredentialRequestReturn> {
    return this.inner.createCredentialRequest(agentContext, options)
  }

  public storeCredential(
    agentContext: AgentContext,
    options: StoreCredentialOptions,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.inner.storeCredential(agentContext, options, metadata)
  }

  public getCredential(
    agentContext: AgentContext,
    options: GetCredentialOptions
  ): Promise<AnonCredsCredentialInfo> {
    return this.inner.getCredential(agentContext, options)
  }

  public getCredentials(
    agentContext: AgentContext,
    options: GetCredentialsOptions
  ): Promise<AnonCredsCredentialInfo[]> {
    return this.inner.getCredentials(agentContext, options)
  }

  public deleteCredential(agentContext: AgentContext, credentialId: string): Promise<void> {
    return this.inner.deleteCredential(agentContext, credentialId)
  }

  public getCredentialsForProofRequest(
    agentContext: AgentContext,
    options: GetCredentialsForProofRequestOptions
  ): Promise<GetCredentialsForProofRequestReturn> {
    return this.inner.getCredentialsForProofRequest(agentContext, options)
  }

  public createW3cPresentation(
    agentContext: AgentContext,
    options: CreateW3cPresentationOptions
  ): Promise<W3cJsonLdVerifiablePresentation> {
    // W3C presentations don't route through `createProof`; Mode B over W3C is
    // a separate follow-on (the binding is different — VC subject + JSON-LD
    // proof). We delegate untouched so the W3C path stays standard.
    return this.inner.createW3cPresentation(agentContext, options)
  }

  public w3cToLegacyCredential(
    agentContext: AgentContext,
    options: W3cToLegacyCredentialOptions
  ): Promise<import('@credo-ts/anoncreds').AnonCredsCredential> {
    return this.inner.w3cToLegacyCredential(agentContext, options)
  }

  public legacyToW3cCredential(
    agentContext: AgentContext,
    options: LegacyToW3cCredentialOptions
  ): Promise<W3cJsonLdVerifiableCredential> {
    return this.inner.legacyToW3cCredential(agentContext, options)
  }

  // NOTE: credo-ts 0.6 added `generateNonce(agentContext)` to
  // `AnonCredsHolderService`; credo-ts 0.5 doesn't have it. The 0.5
  // proof-request flow generates the nonce upstream, so this wrapper
  // doesn't need a passthrough on 0.5.

  // ─── Mode B injection ────────────────────────────────────────────────

  /**
   * For every Mode B credential referenced in `selectedCredentials`, compute
   * the SNARK proof and add it to `selfAttestedAttributes` under
   * `kanon_<credDefId>_zkProof`. The original options object is left
   * untouched — we return a shallow copy with augmented self-attested attrs.
   */
  private async augmentSelfAttested(
    agentContext: AgentContext,
    options: CreateProofOptions
  ): Promise<CreateProofOptions> {
    const credDefIds = collectCredDefIds(options)
    if (credDefIds.size === 0) return options

    // Filter to Mode B credDefs the VERIFIER actually asked for.
    //
    // Graceful degradation: anoncreds-rs verifyProof rejects any
    // `self_attested_attrs` entry that isn't declared as a
    // `requested_attribute`. So if the verifier sent a vanilla proof
    // request (no kanon referent), we silently fall back to standard
    // AnonCreds — interop with non-Kanon verifiers works at the cost of
    // skipping the on-chain non-revocation check on that one hop. The
    // verifier opts in by including `kanon_<credDefId>_zkProof` in their
    // request (via `buildKanonProofRequest`, or by hand).
    //
    // The Mode A status check has the same semantics: only Kanon-aware
    // verifiers consult the on-chain status registry. Mode B follows the
    // same opt-in pattern.
    const requestedAttrs = ((options.proofRequest as { requested_attributes?: Record<string, unknown> })
      ?.requested_attributes ?? {}) as Record<string, unknown>
    const modeB: string[] = []
    for (const credDefId of credDefIds) {
      const mask = await this.getPolicyMask(agentContext, credDefId)
      if ((mask & TIER_ZK_SNARK) === 0) continue
      const ref = kanonZkProofReferent(credDefId)
      if (!(ref in requestedAttrs)) {
        agentContext.config.logger.debug(
          `KanonWrappedAnonCredsHolderService: Mode B credDef ${credDefId} present but verifier did not request ${ref} — skipping SNARK injection (proof will be a standard AnonCreds presentation)`
        )
        continue
      }
      modeB.push(credDefId)
    }
    if (modeB.length === 0) return options

    const challenge = await this.challengeFromProofRequest(options)
    const augmentedSelfAttested: Record<string, string> = {
      ...(options.selectedCredentials.selfAttestedAttributes ?? {}),
    }

    for (const credDefId of modeB) {
      try {
        const credInfo = findCredentialInfoForCredDef(options, credDefId)
        if (!credInfo) {
          agentContext.config.logger.warn(
            `KanonWrappedAnonCredsHolderService: Mode B credDef ${credDefId} referenced in selection but no credentialInfo found — skipping injection (proof will likely fail)`
          )
          continue
        }
        // Find which credential attribute the verifier asked the holder to
        // reveal for this credDef. The SNARK's `disclosedIndex` /
        // `disclosedValue` public signals will be BOUND to exactly that
        // attribute so a verifier (a) cannot link presentations by the
        // disclosed slot — the slot mirrors what AnonCreds is already
        // revealing, never more — and (b) gets a cryptographic guarantee
        // that the AnonCreds-revealed value is the same one the SNARK saw.
        const revealed = findRevealedAttributeForCredDef(options, credDefId)
        if (!revealed) {
          throw new Error(
            `kanon: Mode B credDef ${credDefId} is in the presentation but the verifier did not request any revealed attribute restricted to it. ` +
              `Mode B requires the SNARK's disclosed slot to be bound to an AnonCreds-revealed attribute — otherwise either the SNARK leaks something AnonCreds isn't, or every presentation shares the same disclosed slot (linkable). ` +
              `Have the verifier add at least one revealed requested_attribute with restrictions: [{ cred_def_id: '${credDefId}' }].`
          )
        }
        const referent = kanonZkProofReferent(credDefId)
        const encoded = await this.buildZkProofAttr(
          agentContext,
          credDefId,
          credInfo,
          challenge,
          revealed
        )
        augmentedSelfAttested[referent] = encoded
        agentContext.config.logger.debug(
          `KanonWrappedAnonCredsHolderService: injected ${referent} for credId=${credInfo.credentialId}, disclosing '${revealed.name}'`
        )
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        agentContext.config.logger.error(
          `KanonWrappedAnonCredsHolderService: failed to build Mode B proof for ${credDefId}: ${message}`
        )
        throw err
      }
    }

    // No proof-request mutation needed: we already filtered above to only
    // Mode B credDefs whose `kanon_<credDefId>_zkProof` referent was
    // declared by the verifier. Adding it again would be a no-op.
    return {
      ...options,
      selectedCredentials: {
        ...options.selectedCredentials,
        selfAttestedAttributes: augmentedSelfAttested,
      },
    }
  }

  private async buildZkProofAttr(
    agentContext: AgentContext,
    credDefId: string,
    credInfo: AnonCredsCredentialInfo,
    challenge: bigint,
    revealed: { name: string; value: string }
  ): Promise<string> {
    const attrs = credInfo.attributes
    const kanonCredId = attrs[KANON_CRED_ID_ATTRIBUTE]
    const kanonZkSig = attrs[KANON_ZK_SIG_ATTRIBUTE]
    if (typeof kanonCredId !== 'string' || typeof kanonZkSig !== 'string') {
      throw new Error(
        `kanon-zk: credential ${credInfo.credentialId} for Mode B credDef ${credDefId} is missing ${KANON_CRED_ID_ATTRIBUTE} / ${KANON_ZK_SIG_ATTRIBUTE} attributes — was it issued through prepareModeBCredential?`
      )
    }

    // Felt-encode using the SDK's CANONICAL ordering (lexicographic byte
    // sort of attribute names, SDK-reserved names excluded). Same encoder
    // as `prepareModeBCredential` and `extractLeafAttributes`, so all
    // three sites produce the same leaf without depending on JS object
    // iteration order surviving anoncreds-rs serialization.
    const values: Record<string, string> = {}
    for (const [name, value] of Object.entries(attrs)) {
      if (typeof value === 'string') values[name] = value
    }
    const domainAttrFelts = encodeAttributesCanonical(values)
    const paddedAttrs = padAttrsToCircuit(domainAttrFelts)

    // Resolve the disclosed slot AGAINST the canonical order so the SNARK's
    // `disclosedIndex` lines up with `paddedAttrs[i]`. The slot bound here is
    // the one the verifier asked AnonCreds to reveal — the SNARK adds a
    // cryptographic guarantee that the value AnonCreds revealed is the same
    // value the SNARK saw, but it does NOT leak any attribute the verifier
    // didn't already see in the AnonCreds proof.
    const sortedDomainNames = Object.keys(values)
      .filter((n) => n !== KANON_CRED_ID_ATTRIBUTE && n !== KANON_ZK_SIG_ATTRIBUTE)
      .sort()
    const disclosedIndex = sortedDomainNames.indexOf(revealed.name)
    if (disclosedIndex < 0) {
      throw new Error(
        `kanon-zk: verifier asked to reveal '${revealed.name}' but the credential's domain attributes don't include it (after stripping kanon-reserved names). Available: ${sortedDomainNames.join(', ')}`
      )
    }
    const disclosedValue = paddedAttrs[disclosedIndex]
    // Defensive: the felt at the canonical slot MUST match the felt-encoding
    // of the revealed value the verifier sees in the AnonCreds proof. Any
    // mismatch means the holder's view of the attribute differs from the
    // verifier's — bail loudly rather than producing a proof the verifier
    // will silently reject.
    const expectedRevealedFelt = attrValueToFelt(revealed.value)
    if (disclosedValue !== expectedRevealedFelt) {
      throw new Error(
        `kanon-zk: internal felt-encoding mismatch for '${revealed.name}' — canonical slot ${disclosedIndex} holds ${disclosedValue} but the revealed value encodes to ${expectedRevealedFelt}. This indicates a bug in attribute encoding or canonical ordering.`
      )
    }

    // Compute the local Poseidon leaf so the path lookup can find it.
    const credDefFelt = BigInt(credDefId) % BN254_SCALAR_FIELD
    const credIdFelt = BigInt(kanonCredIdHash(kanonCredId)) % BN254_SCALAR_FIELD
    const leaf = await computeZkLeaf(credDefFelt, credIdFelt, paddedAttrs)

    const pathInfo = await this.pathService.findPath(agentContext, credDefId, leaf)
    if (!pathInfo) {
      throw new Error(
        `kanon-zk: could not find Merkle path for credential ${credInfo.credentialId} in credDef ${credDefId} — credential may have been revoked or not yet published`
      )
    }

    // Look up the on-chain issuer pubkey so the circuit and the registry
    // agree on `(Ax, Ay)`.
    const credDefRegistry = this.clientService.contracts.credDefRegistry as unknown as {
      getIssuerZkPubKey: (credDefId: string) => Promise<{ ax: bigint; ay: bigint; set: boolean }>
    }
    const onChainKey = await credDefRegistry.getIssuerZkPubKey(credDefId)
    if (!onChainKey.set) {
      throw new Error(`kanon-zk: credDef ${credDefId} has no Tier 2 key published`)
    }

    const sig = decodeZkSignature(kanonZkSig)

    // Witness — exactly the layout the compiled circuit expects.
    const input = {
      root: pathInfo.root.toString(),
      credDefId: credDefFelt.toString(),
      challenge: challenge.toString(),
      issuerAx: BigInt(onChainKey.ax).toString(),
      issuerAy: BigInt(onChainKey.ay).toString(),
      // Bound to the AnonCreds-revealed attribute resolved above — same
      // canonical-sort position the leaf used, same felt value the verifier
      // sees in the AnonCreds proof. This is the privacy hinge: as long as
      // both sides only use this slot for attributes the verifier ALREADY
      // sees via AnonCreds, the SNARK's public signals don't leak anything
      // new across presentations.
      disclosedIndex: [disclosedIndex.toString()],
      disclosedValue: [disclosedValue.toString()],
      credId: credIdFelt.toString(),
      attributes: paddedAttrs.map((a) => a.toString()),
      pathElements: pathInfo.pathElements.map((p) => p.toString()),
      pathIndices: pathInfo.pathIndices.map((p) => p.toString()),
      sigS: sig.S.toString(),
      sigR8x: sig.R8x.toString(),
      sigR8y: sig.R8y.toString(),
    }

    // Dynamic snarkjs import (it has no types). The string-variable
    // indirection prevents tsdown from trying to resolve at build time.
    type SnarkjsModule = {
      groth16: {
        fullProve: (
          input: unknown,
          wasmPath: string,
          zkeyPath: string
        ) => Promise<{ proof: unknown; publicSignals: string[] }>
        exportSolidityCallData: (proof: unknown, publicSignals: string[]) => Promise<string>
      }
    }
    const snarkjsModuleName = 'snarkjs'
    const snarkjs = (await import(snarkjsModuleName)) as unknown as SnarkjsModule
    const wasmPath = process.env.KANON_ZK_WASM
    const zkeyPath = process.env.KANON_ZK_ZKEY
    if (!wasmPath || !zkeyPath) {
      throw new Error(
        'kanon-zk: KANON_ZK_WASM and KANON_ZK_ZKEY env vars must point at the snarkjs artifacts (non_revocation.wasm + nr_final.zkey) for Mode B presentations to work'
      )
    }
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath)
    const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)
    const [a, b, c] = JSON.parse('[' + calldata + ']') as [
      [string, string],
      [[string, string], [string, string]],
      [string, string],
      string[],
    ]
    const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
      ['uint256[2]', 'uint256[2][2]', 'uint256[2]'],
      [a, b, c]
    )
    const toBytes32 = (v: string) => '0x' + BigInt(v).toString(16).padStart(64, '0')
    return encodeKanonZkProofAttr({
      proofBytes,
      publicSignals: publicSignals.map(toBytes32),
    })
  }

  private async getPolicyMask(agentContext: AgentContext, credDefId: string): Promise<number> {
    const cached = this.policyCache.get(credDefId)
    if (cached !== undefined) return cached
    try {
      const mask = await this.clientService.client.getCredDefPolicy(credDefId)
      this.policyCache.set(credDefId, mask)
      return mask
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      agentContext.config.logger.debug(
        `KanonWrappedAnonCredsHolderService: getCredDefPolicy(${credDefId}) failed (${message}); assuming Mode A only`
      )
      this.policyCache.set(credDefId, 0b01)
      return 0b01
    }
  }

  /**
   * Bind the SNARK challenge to the verifier's session. We use the
   * `proofRequest.nonce` directly — AnonCreds already guarantees freshness
   * + binding to this exchange, which is exactly the property the verifier
   * needs to detect replay.
   */
  private async challengeFromProofRequest(options: CreateProofOptions): Promise<bigint> {
    // biome-ignore lint/suspicious/noExplicitAny: proofRequest is a permissive AnonCreds JSON
    const nonce: string | undefined = (options.proofRequest as any)?.nonce
    if (!nonce) {
      throw new Error('kanon-zk: proofRequest is missing nonce — cannot derive Mode B challenge')
    }
    // AnonCreds nonces are decimal strings; convert to felt.
    return BigInt(nonce) % BN254_SCALAR_FIELD
  }
}

/** `kanon_<credDefId>_zkProof` — the self-attested attribute name we inject. */
export function kanonZkProofReferent(credDefId: string): string {
  return `kanon_${credDefId.toLowerCase()}_zkProof`
}

/**
 * Insert the `kanon_<credDefId>_zkProof` referents into a proof request's
 * `requested_attributes` so anoncreds-rs's createProof / verifyProof accept
 * them as self-attestable. Exported so the verifier wrapper applies the
 * identical augmentation before delegating to `verifyProof` — keeping the
 * referent set symmetric on both sides.
 *
 * `name` is set to the SDK-reserved `kanonZkProof` constant — the value is
 * the base64 SNARK blob; nothing else looks at the name once anoncreds-rs
 * accepts the referent. `restrictions` is intentionally omitted, which is
 * how anoncreds marks an attribute as self-attestable.
 *
 * No-ops when the referent is already declared (caller might have used
 * `buildKanonProofRequest` which adds them up-front).
 */
export function augmentProofRequestForKanon<T extends Record<string, unknown>>(
  proofRequest: T,
  credDefIds: Iterable<string>
): T {
  const requested = {
    ...((proofRequest as { requested_attributes?: Record<string, unknown> }).requested_attributes ?? {}),
  }
  let mutated = false
  for (const credDefId of credDefIds) {
    const ref = kanonZkProofReferent(credDefId)
    if (ref in requested) continue
    requested[ref] = { name: KANON_ZK_PROOF_ATTRIBUTE }
    mutated = true
  }
  if (!mutated) return proofRequest
  return { ...proofRequest, requested_attributes: requested }
}

// ─── helpers ────────────────────────────────────────────────────────────

/**
 * Throws if the proof request asks the holder to disclose the
 * `kanonZkSig` attribute via any requested-attributes referent.
 *
 * The kanonZkSig is a per-credential constant (the issuer's BabyJubjub
 * EdDSA signature over the leaf). Disclosing it across multiple
 * presentations defeats the Mode B unlinkability guarantee — every
 * verifier that sees it gets the same value, trivially correlating the
 * holder across sessions. We treat this as a hard error rather than a
 * silent acceptance: wallet UIs should surface it so the holder
 * understands the request is suspicious.
 *
 * Matches both shapes AnonCreds supports for revealed attributes:
 *   - `requested_attributes[<ref>].name = "kanonZkSig"`
 *   - `requested_attributes[<ref>].names = [..., "kanonZkSig", ...]`
 */
function assertProofRequestDoesNotAskForKanonZkSig(
  agentContext: AgentContext,
  options: CreateProofOptions
): void {
  const requested = (options.proofRequest as { requested_attributes?: Record<string, unknown> })
    ?.requested_attributes
  if (!requested) return
  for (const [referent, meta] of Object.entries(requested)) {
    const requestedName = (meta as { name?: string })?.name
    const requestedNames = Array.isArray((meta as { names?: string[] })?.names)
      ? ((meta as { names: string[] }).names as string[])
      : []
    const asksForKanonZkSig =
      requestedName === KANON_ZK_SIG_ATTRIBUTE ||
      requestedNames.includes(KANON_ZK_SIG_ATTRIBUTE)
    if (asksForKanonZkSig) {
      const msg = `kanon: refusing to disclose the reserved '${KANON_ZK_SIG_ATTRIBUTE}' attribute (proof-request referent '${referent}') — revealing it across presentations would link the holder. The verifier should NEVER request this attribute.`
      agentContext.config.logger.warn(msg)
      throw new Error(msg)
    }
  }
}

function collectCredDefIds(options: CreateProofOptions): Set<string> {
  const out = new Set<string>()
  for (const match of Object.values(options.selectedCredentials.attributes ?? {})) {
    const id = match?.credentialInfo?.credentialDefinitionId
    if (typeof id === 'string') out.add(id)
  }
  for (const match of Object.values(options.selectedCredentials.predicates ?? {})) {
    const id = match?.credentialInfo?.credentialDefinitionId
    if (typeof id === 'string') out.add(id)
  }
  return out
}

/**
 * Find the first attribute the verifier asked the holder to REVEAL for the
 * given credDef, returning its name + the value the credential holds for it.
 *
 * The lookup walks `selectedCredentials.attributes` for entries that are:
 *   1. Backed by a credential whose credentialDefinitionId === credDefId
 *   2. Set to `revealed: true` in the selection
 * For each match it reads the proof request's `requested_attributes[ref]`
 * to learn the attribute name (or names[0]).
 *
 * Reserved kanon names (`kanonCredId`, `kanonZkSig`) are NOT eligible —
 * `kanonZkSig` is refused outright (see `assertProofRequestDoesNotAskForKanonZkSig`)
 * and `kanonCredId` would defeat the unlinkability the SNARK is meant to
 * provide. Returns `null` when no eligible revealed attribute exists, which
 * the caller turns into a clear "verifier needs to request something
 * revealed" error.
 */
function findRevealedAttributeForCredDef(
  options: CreateProofOptions,
  credDefId: string
): { name: string; value: string } | null {
  const requested = (options.proofRequest as { requested_attributes?: Record<string, unknown> })
    ?.requested_attributes ?? {}
  for (const [ref, match] of Object.entries(options.selectedCredentials.attributes ?? {})) {
    if (match?.credentialInfo?.credentialDefinitionId !== credDefId) continue
    if (!match.revealed) continue
    const meta = requested[ref] as { name?: string; names?: string[] } | undefined
    if (!meta) continue
    const candidates: string[] = meta.name
      ? [meta.name]
      : Array.isArray(meta.names)
        ? meta.names
        : []
    for (const name of candidates) {
      if (name === KANON_CRED_ID_ATTRIBUTE || name === KANON_ZK_SIG_ATTRIBUTE) continue
      const value = match.credentialInfo.attributes[name]
      if (typeof value === 'string') return { name, value }
    }
  }
  return null
}

/**
 * Find the credentialInfo of the credential selected for `credDefId`. We pick
 * the FIRST match across attributes / predicates — AnonCreds allows a single
 * credential to back many referents so any match is the right one.
 */
function findCredentialInfoForCredDef(
  options: CreateProofOptions,
  credDefId: string
): AnonCredsCredentialInfo | null {
  for (const match of Object.values(options.selectedCredentials.attributes ?? {})) {
    if (match?.credentialInfo?.credentialDefinitionId === credDefId) {
      return match.credentialInfo
    }
  }
  for (const match of Object.values(options.selectedCredentials.predicates ?? {})) {
    if (match?.credentialInfo?.credentialDefinitionId === credDefId) {
      return match.credentialInfo
    }
  }
  return null
}
