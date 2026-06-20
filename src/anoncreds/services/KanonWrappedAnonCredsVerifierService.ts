import type {
  AnonCredsVerifierService,
  VerifyProofOptions,
  VerifyW3cPresentationOptions,
} from '@credo-ts/anoncreds'
import type { AgentContext } from '@credo-ts/core'

import { attrValueToFelt, BN254_SCALAR_FIELD, decodeKanonZkProofAttr, KANON_ZK_SIG_ATTRIBUTE } from '@ajna-inc/kanon-sdk'
import { inject, injectable } from '@credo-ts/core'

import { KanonClientService } from '../../ledger'
import { KANON_CRED_ID_ATTRIBUTE, kanonCredIdHash } from '../utils/credIdHash'
import {
  augmentProofRequestForKanon,
  kanonZkProofReferent,
} from './KanonWrappedAnonCredsHolderService'

const TIER_ZK_SNARK = 0b10

/**
 * Injection token used by {@link KanonModule} to register the original
 * `AnonCredsRsVerifierService` so the {@link KanonWrappedAnonCredsVerifierService}
 * can inject it without pulling in a deep `@credo-ts/anoncreds/build/...` import.
 *
 * The module registers the original verifier under this symbol, then overrides
 * the public `AnonCredsVerifierServiceSymbol` binding with the wrapper.
 */
export const OriginalAnonCredsVerifierServiceSymbol = Symbol('OriginalAnonCredsVerifierService')

/**
 * Wraps Credo's default `AnonCredsVerifierService` so that, after the standard
 * AnonCreds proof verifies, the verifier additionally checks the on-chain
 * `AnonCredsStatusRegistry` for revocation. Both checks must pass.
 *
 * Privacy model: the credential schema must include the canonical `kanonCredId`
 * attribute and the verifier proof request must mark it as revealed. The verifier
 * extracts the disclosed value, hashes it with `kanonCredIdHash`, and looks up
 * the (credDefId, credIdHash) status.
 *
 * If no AnonCredsStatusRegistry is configured on the Kanon module, this wrapper
 * skips the on-chain check and returns whatever the inner verifier returned —
 * useful for tests and for credentials not under kanon governance.
 */
@injectable()
export class KanonWrappedAnonCredsVerifierService implements AnonCredsVerifierService {
  public constructor(
    @inject(OriginalAnonCredsVerifierServiceSymbol) private readonly inner: AnonCredsVerifierService,
    private readonly ledgerService: KanonClientService
  ) {}

  public async verifyProof(agentContext: AgentContext, options: VerifyProofOptions): Promise<boolean> {
    // Mode B is OPT-IN per presentation:
    //
    //   - If THIS verifier declared the `kanon_<credDefId>_zkProof` referent in
    //     the proof request, the holder (if Kanon-aware) injected the SNARK
    //     proof; we delegate to `inner.verifyProof` unchanged and then
    //     additionally check the SNARK on chain.
    //
    //   - If THIS verifier sent a vanilla proof request (no kanon referent),
    //     we skip the SNARK check — the wire-format presentation is a plain
    //     AnonCreds proof that any AnonCreds verifier would accept, and we
    //     have nothing to validate against. This preserves interop with
    //     legacy verifiers and matches the Mode A status-registry pattern
    //     (also opt-in).
    //
    // Either way the AnonCreds CL signature is checked unchanged.
    const modeBCredDefs = await this.collectModeBCredDefIds(agentContext, options)

    const innerResult = await this.inner.verifyProof(agentContext, options)
    if (!innerResult) return false

    // ── Mode B: on-chain SNARK check for every Tier-2 credDef the verifier
    //    asked the holder to prove non-revocation for ──
    const modeBOk = await this.verifyModeBProofs(agentContext, options, modeBCredDefs)
    if (!modeBOk) return false

    if (!this.ledgerService.hasAnonCredsStatusRegistry()) {
      agentContext.config.logger.debug(
        'KanonWrappedAnonCredsVerifierService: status registry not configured; skipping on-chain revocation check'
      )
      return true
    }

    // Mode A is opt-in per-presentation, same as Mode B. The signal is that
    // the verifier declared a `kanonCredId` referent in the proof request —
    // either with `name: kanonCredId` or via the `kanon_*_credId` referent
    // pattern produced by `buildKanonProofRequest`. If the verifier did not
    // ask for it, we skip the on-chain status lookup. This matters because:
    //
    //   - Mode-B-only credentials don't disclose `kanonCredId` in their
    //     proofs. Without the gate, this wrapper would reject every valid
    //     Mode B presentation when a status registry happens to be wired up.
    //
    //   - Verifiers that don't want Mode A revocation checks (e.g. test or
    //     read-only flows) shouldn't be forced to pay for them.
    if (!proofRequestHasKanonCredIdReferent(options)) {
      agentContext.config.logger.debug(
        `KanonWrappedAnonCredsVerifierService: proof request did not declare a ${KANON_CRED_ID_ATTRIBUTE} referent; skipping Mode A revocation check`
      )
      return true
    }

    const checks = collectKanonCredentialIdentifiers(options)
    if (checks.length === 0) {
      // Verifier declared `kanonCredId` but the holder revealed none. This
      // is the suspicious case the original wrapper was trying to detect:
      // the verifier asked but didn't get an answer.
      agentContext.config.logger.warn(
        `KanonWrappedAnonCredsVerifierService: no disclosed ${KANON_CRED_ID_ATTRIBUTE} attribute found; cannot verify revocation status — rejecting proof`
      )
      return false
    }

    for (const { credDefId, credId } of checks) {
      const credIdHash = kanonCredIdHash(credId)
      const revoked = await this.ledgerService.isCredentialRevokedOnStatus(credDefId, credIdHash)
      if (revoked) {
        agentContext.config.logger.debug(
          `KanonWrappedAnonCredsVerifierService: credential ${credId} is revoked on-chain under credDef ${credDefId}`
        )
        return false
      }
    }
    return true
  }

  /**
   * Verify the Mode B SNARK proof carried by each Tier-2 credDef in the
   * presentation.
   *
   * For every credDef referenced in `proof.identifiers` whose on-chain
   * policyMask includes `TIER_ZK_SNARK`, we look for
   * `proof.requested_proof.self_attested_attrs[kanon_<credDefId>_zkProof]`,
   * decode it, and submit to `MerkleStateRegistry.verifyZKMembership`. Any
   * missing or rejected proof fails the whole presentation.
   *
   * Mode A-only credDefs are unaffected — their presentations don't carry a
   * `kanonZkProof` referent and this check is a no-op for them.
   */
  /**
   * Scan `proof.identifiers` for credDefs that satisfy BOTH:
   *
   *   1. On-chain policyMask includes `TIER_ZK_SNARK` (the credDef opted into
   *      Mode B at registration).
   *   2. This verifier's proof request DECLARED the
   *      `kanon_<credDefId>_zkProof` referent (the verifier opted in to
   *      checking it here).
   *
   * Both conditions must hold — Mode B is opt-in per-verifier-per-request.
   */
  private async collectModeBCredDefIds(
    agentContext: AgentContext,
    options: VerifyProofOptions
  ): Promise<string[]> {
    // biome-ignore lint/suspicious/noExplicitAny: AnonCreds proof JSON is permissive
    const proof = options.proof as any
    // biome-ignore lint/suspicious/noExplicitAny: identifiers is a permissive payload
    const identifiers: any[] = Array.isArray(proof?.identifiers) ? proof.identifiers : []
    const requestedAttrs = ((options.proofRequest as { requested_attributes?: Record<string, unknown> })
      ?.requested_attributes ?? {}) as Record<string, unknown>
    const out: string[] = []
    const seen = new Set<string>()
    for (const id of identifiers) {
      const credDefId = id?.cred_def_id
      if (typeof credDefId !== 'string' || seen.has(credDefId)) continue
      seen.add(credDefId)
      const mask = await this.getPolicyMask(agentContext, credDefId)
      if ((mask & TIER_ZK_SNARK) === 0) continue
      // Opt-in: verifier must have declared the kanon referent. Otherwise we
      // treat the credential as a standard AnonCreds presentation.
      if (!(kanonZkProofReferent(credDefId) in requestedAttrs)) continue
      out.push(credDefId)
    }
    return out
  }

  private async verifyModeBProofs(
    agentContext: AgentContext,
    options: VerifyProofOptions,
    modeBCredDefs: string[]
  ): Promise<boolean> {
    if (modeBCredDefs.length === 0) return true
    // biome-ignore lint/suspicious/noExplicitAny: AnonCreds proof JSON is permissive
    const proof = options.proof as any
    // biome-ignore lint/suspicious/noExplicitAny: self_attested_attrs is permissive
    const selfAttested: Record<string, string> = proof?.requested_proof?.self_attested_attrs ?? {}

    // The proof-request nonce IS the SNARK challenge — the holder wrapper
    // derives `challenge = uint256(nonce) mod p` and feeds it as
    // `publicSignals[2]`. AnonCreds already binds the nonce to this
    // exchange (freshness, anti-replay), so reusing it is exactly the
    // property we need: a SNARK proof from a previous exchange has a
    // different `publicSignals[2]` and will not match the current nonce.
    const nonceRaw = (options.proofRequest as { nonce?: string })?.nonce
    if (typeof nonceRaw !== 'string' || nonceRaw.length === 0) {
      agentContext.config.logger.warn(
        'KanonWrappedAnonCredsVerifierService: proof request missing nonce; cannot bind Mode B challenge — rejecting'
      )
      return false
    }
    const expectedChallenge = BigInt(nonceRaw) % BN254_SCALAR_FIELD

    for (const credDefId of modeBCredDefs) {
      const referent = kanonZkProofReferent(credDefId)
      const encoded = selfAttested[referent]
      if (typeof encoded !== 'string' || encoded.length === 0) {
        agentContext.config.logger.warn(
          `KanonWrappedAnonCredsVerifierService: Mode B credDef ${credDefId} requires ${referent} self-attested attribute; not found in proof — rejecting`
        )
        return false
      }
      let wire: ReturnType<typeof decodeKanonZkProofAttr>
      try {
        wire = decodeKanonZkProofAttr(encoded)
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        agentContext.config.logger.warn(
          `KanonWrappedAnonCredsVerifierService: failed to decode ${referent}: ${message} — rejecting`
        )
        return false
      }
      // Challenge binding: `publicSignals[2]` MUST equal the proof-request
      // nonce reduced mod p. Without this, a SNARK from a previous exchange
      // would replay successfully — `verifyZKMembership` checks the recent
      // root window but not the challenge.
      const providedChallenge = BigInt(wire.publicSignals[2])
      if (providedChallenge !== expectedChallenge) {
        agentContext.config.logger.warn(
          `KanonWrappedAnonCredsVerifierService: Mode B challenge mismatch for ${credDefId} — expected=${expectedChallenge}, got=${providedChallenge} (possible replay) — rejecting`
        )
        return false
      }
      // Disclosed-attribute binding. The SNARK's `publicSignals[5]/[6]` are
      // `(disclosedIndex, disclosedValue)` for the credential's domain
      // attributes (in canonical sort order). For the SNARK to add meaning
      // beyond "non-revocation", we require BOTH coordinates to match a
      // SPECIFIC AnonCreds-revealed attribute:
      //
      //   - `publicSignals[5]` (position) MUST equal the canonical-sort
      //     position of one of the revealed attribute names.
      //   - `publicSignals[6]` (felt) MUST equal `attrValueToFelt(rawValue)`
      //     of that SAME attribute.
      //
      // Without the position constraint, a holder presenting two attributes
      // with the same felt value (e.g. both equal "25") could SNARK-bind to
      // attribute Y while AnonCreds revealed attribute X — the verifier
      // would accept both as consistent even though they prove different
      // facts. Requiring the matching pair closes that gap.
      const providedDisclosedIndex = Number(BigInt(wire.publicSignals[5]))
      const providedDisclosedFelt = BigInt(wire.publicSignals[6])
      const matchingRevealed = collectAnonCredsRevealedFelts(options, credDefId)
      if (matchingRevealed.length === 0) {
        agentContext.config.logger.warn(
          `KanonWrappedAnonCredsVerifierService: Mode B credDef ${credDefId} requires a revealed AnonCreds attribute the SNARK can bind to, but the proof has none — rejecting`
        )
        return false
      }
      const hasMatchingPair = matchingRevealed.some(
        (p) => p.position === providedDisclosedIndex && p.felt === providedDisclosedFelt
      )
      if (!hasMatchingPair) {
        agentContext.config.logger.warn(
          `KanonWrappedAnonCredsVerifierService: Mode B disclosed (idx=${providedDisclosedIndex}, val=${providedDisclosedFelt}) for ${credDefId} does not match any AnonCreds-revealed (position, felt) pair — rejecting`
        )
        return false
      }
      const merkleStateRegistry = this.ledgerService.contracts.merkleStateRegistry as unknown as {
        verifyZKMembership: (
          credDefId: string,
          proof: string,
          publicSignals: string[]
        ) => Promise<boolean>
      }
      let ok = false
      try {
        ok = await merkleStateRegistry.verifyZKMembership(credDefId, wire.proofBytes, wire.publicSignals)
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        agentContext.config.logger.warn(
          `KanonWrappedAnonCredsVerifierService: verifyZKMembership(${credDefId}) reverted: ${message}`
        )
        return false
      }
      if (!ok) {
        agentContext.config.logger.warn(
          `KanonWrappedAnonCredsVerifierService: Mode B proof for ${credDefId} rejected on chain`
        )
        return false
      }
      agentContext.config.logger.debug(
        `KanonWrappedAnonCredsVerifierService: Mode B proof for ${credDefId} verified on chain`
      )
    }
    return true
  }

  private readonly policyCache = new Map<string, number>()

  private async getPolicyMask(agentContext: AgentContext, credDefId: string): Promise<number> {
    const cached = this.policyCache.get(credDefId)
    if (cached !== undefined) return cached
    try {
      const mask = await this.ledgerService.client.getCredDefPolicy(credDefId)
      this.policyCache.set(credDefId, mask)
      return mask
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      agentContext.config.logger.debug(
        `KanonWrappedAnonCredsVerifierService: getCredDefPolicy(${credDefId}) failed (${message}); defaulting to Mode A only`
      )
      this.policyCache.set(credDefId, 0b01)
      return 0b01
    }
  }

  public async verifyW3cPresentation(
    agentContext: AgentContext,
    options: VerifyW3cPresentationOptions
  ): Promise<boolean> {
    const innerResult = await this.inner.verifyW3cPresentation(agentContext, options)
    if (!innerResult) return false

    if (!this.ledgerService.hasAnonCredsStatusRegistry()) return true

    const checks = collectKanonCredentialIdentifiersFromW3c(options)
    if (checks.length === 0) {
      agentContext.config.logger.warn(
        `KanonWrappedAnonCredsVerifierService: no disclosed ${KANON_CRED_ID_ATTRIBUTE} found in W3C presentation; rejecting`
      )
      return false
    }

    for (const { credDefId, credId } of checks) {
      const credIdHash = kanonCredIdHash(credId)
      const revoked = await this.ledgerService.isCredentialRevokedOnStatus(credDefId, credIdHash)
      if (revoked) return false
    }
    return true
  }
}

interface KanonCredentialIdentifier {
  credDefId: string
  credId: string
}

/**
 * Matches the referent naming convention produced by `buildKanonProofRequest`,
 * which scopes the disclosed `kanonCredId` per credDef as `kanon_<credDefId>_credId`.
 * The verifier accepts either the simple `kanonCredId` attribute name or any
 * referent matching this pattern, so callers can use the helper or hand-craft
 * the request.
 */
const KANON_REFERENT_PATTERN = /^kanon_.+_credId$/

/**
 * One `(position, value)` pair from an AnonCreds-revealed attribute. The
 * position is the canonical-sort index of the attribute *name* within the
 * credDef's domain attributes (the SDK-reserved names excluded). The value
 * is `attrValueToFelt` of the raw revealed value — same felt the holder
 * passed to `publicSignals[6]`.
 *
 * The verifier requires `(publicSignals[5], publicSignals[6])` to equal
 * exactly one of these pairs. That binds the SNARK's disclosed slot to a
 * SPECIFIC AnonCreds-revealed attribute, not just any value that happens
 * to match — defends against collision-style abuse where two attributes
 * share the same felt value and a holder could otherwise claim to prove
 * one while AnonCreds revealed the other.
 */
interface RevealedFeltPair {
  position: number
  felt: bigint
}

/**
 * Collect AnonCreds-revealed (position, felt) pairs for `credDefId`.
 *
 * Walks `proof.requested_proof.revealed_attrs` (and `revealed_attr_groups`)
 * matching against `proof.identifiers[sub_proof_index].cred_def_id` to find
 * entries that belong to the credDef. For each match, we look up the
 * attribute name in the canonical (lexicographic) order of the credDef's
 * schema attrNames — same order the holder + leaf use. SDK-reserved names
 * (`kanonCredId`, `kanonZkSig`) are excluded both from the canonical
 * ordering AND from eligibility.
 *
 * Returns the list of valid `(position, felt)` pairs. Empty if none are
 * eligible (verifier should reject the Mode B presentation in that case).
 */
function collectAnonCredsRevealedFelts(options: VerifyProofOptions, credDefId: string): RevealedFeltPair[] {
  // biome-ignore lint/suspicious/noExplicitAny: AnonCreds proof JSON is permissive
  const proof = options.proof as any
  // biome-ignore lint/suspicious/noExplicitAny: identifiers payload is permissive
  const identifiers: any[] = Array.isArray(proof?.identifiers) ? proof.identifiers : []
  // biome-ignore lint/suspicious/noExplicitAny: revealed_attrs payload is permissive
  const revealedAttrs: Record<string, any> = proof?.requested_proof?.revealed_attrs ?? {}
  // biome-ignore lint/suspicious/noExplicitAny: revealed_attr_groups payload is permissive
  const revealedAttrGroups: Record<string, any> = proof?.requested_proof?.revealed_attr_groups ?? {}
  // biome-ignore lint/suspicious/noExplicitAny: proofRequest is permissive
  const requested: Record<string, any> = options.proofRequest?.requested_attributes ?? {}

  // Map credDefId -> schemaId via the credentialDefinitions block, then
  // schemaId -> attrNames via the schemas block. Both blocks are supplied
  // by the AnonCreds caller (they're required for verifyProof anyway).
  const credDef = options.credentialDefinitions?.[credDefId]
  if (!credDef) return []
  const schema = options.schemas?.[credDef.schemaId]
  if (!schema) return []
  const reserved = new Set([KANON_CRED_ID_ATTRIBUTE, KANON_ZK_SIG_ATTRIBUTE])
  // Canonical position = index in lexicographic sort of NON-reserved attrNames.
  const sortedDomainNames = [...schema.attrNames]
    .filter((n) => !reserved.has(n))
    .sort()
  const positionOf = (name: string): number => sortedDomainNames.indexOf(name)

  const out: RevealedFeltPair[] = []

  const isForCredDef = (subProofIndex: number) => identifiers[subProofIndex]?.cred_def_id === credDefId

  for (const [ref, value] of Object.entries(revealedAttrs)) {
    const subProofIndex: number = value.sub_proof_index
    if (!isForCredDef(subProofIndex)) continue
    const meta = requested[ref]
    const name = meta?.name as string | undefined
    if (!name || reserved.has(name)) continue
    const position = positionOf(name)
    if (position < 0) continue
    const raw = value?.raw
    if (typeof raw !== 'string') continue
    out.push({ position, felt: attrValueToFelt(raw) })
  }
  for (const [ref, group] of Object.entries(revealedAttrGroups)) {
    const subProofIndex: number = group.sub_proof_index
    if (!isForCredDef(subProofIndex)) continue
    const meta = requested[ref]
    const names: string[] = Array.isArray(meta?.names) ? meta.names : []
    const values = group?.values ?? {}
    for (const name of names) {
      if (reserved.has(name)) continue
      const position = positionOf(name)
      if (position < 0) continue
      const raw = values[name]?.raw
      if (typeof raw !== 'string') continue
      out.push({ position, felt: attrValueToFelt(raw) })
    }
  }
  return out
}

/**
 * `true` iff the verifier declared a referent in the proof request that
 * targets `kanonCredId` — either by attribute name or via the
 * `kanon_<credDefId>_credId` referent pattern. Used to gate the Mode A
 * status-registry check: if the verifier didn't ask for `kanonCredId`,
 * Mode A is skipped (the verifier opted out).
 */
function proofRequestHasKanonCredIdReferent(options: VerifyProofOptions): boolean {
  // biome-ignore lint/suspicious/noExplicitAny: proofRequest is a permissive payload
  const requested: Record<string, any> = options.proofRequest?.requested_attributes ?? {}
  for (const [referent, meta] of Object.entries(requested)) {
    if (!meta) continue
    const candidates: string[] = (meta as { name?: string }).name
      ? [(meta as { name: string }).name]
      : Array.isArray((meta as { names?: string[] }).names)
        ? (meta as { names: string[] }).names
        : []
    if (candidates.includes(KANON_CRED_ID_ATTRIBUTE)) return true
    if (KANON_REFERENT_PATTERN.test(referent)) return true
  }
  return false
}

/**
 * Walks an AnonCreds proof for revealed `kanonCredId` attributes and pairs each
 * with the corresponding cred_def_id from `proof.identifiers`.
 */
function collectKanonCredentialIdentifiers(options: VerifyProofOptions): KanonCredentialIdentifier[] {
  const out: KanonCredentialIdentifier[] = []
  // biome-ignore lint/suspicious/noExplicitAny: AnonCreds proof JSON is permissive
  const proof = options.proof as any
  // biome-ignore lint/suspicious/noExplicitAny: cred_def_id lives on a permissive identifier struct
  const identifiers: any[] = Array.isArray(proof?.identifiers) ? proof.identifiers : []
  // biome-ignore lint/suspicious/noExplicitAny: revealed_attrs is a permissive map
  const revealed: Record<string, any> = proof?.requested_proof?.revealed_attrs ?? {}
  // biome-ignore lint/suspicious/noExplicitAny: revealed_attr_groups is a permissive map
  const revealedGroups: Record<string, any> = proof?.requested_proof?.revealed_attr_groups ?? {}
  // biome-ignore lint/suspicious/noExplicitAny: proofRequest carries permissive attribute metadata
  const requestedAttrs: Record<string, any> = options.proofRequest?.requested_attributes ?? {}

  const pickByReferent = (referent: string): string | undefined => {
    const meta = requestedAttrs[referent]
    if (!meta) {
      // Referent has no metadata in the proof request; fall back to naming convention.
      return KANON_REFERENT_PATTERN.test(referent) ? KANON_CRED_ID_ATTRIBUTE : undefined
    }
    const candidates: string[] = meta.name ? [meta.name] : Array.isArray(meta.names) ? meta.names : []
    if (candidates.find((n) => n === KANON_CRED_ID_ATTRIBUTE)) return KANON_CRED_ID_ATTRIBUTE
    // Accept the referent naming pattern as a fallback (`kanon_<credDefId>_credId`).
    return KANON_REFERENT_PATTERN.test(referent) ? KANON_CRED_ID_ATTRIBUTE : undefined
  }

  for (const [referent, value] of Object.entries(revealed)) {
    const attrName = pickByReferent(referent)
    if (attrName !== KANON_CRED_ID_ATTRIBUTE) continue
    // biome-ignore lint/suspicious/noExplicitAny: sub_proof_index is on permissive payload
    const subProofIndex: number = (value as any).sub_proof_index
    const identifier = identifiers[subProofIndex]
    if (!identifier?.cred_def_id) continue
    out.push({
      credDefId: identifier.cred_def_id,
      // biome-ignore lint/suspicious/noExplicitAny: raw is on permissive payload
      credId: String((value as any).raw),
    })
  }

  for (const [referent, group] of Object.entries(revealedGroups)) {
    const meta = requestedAttrs[referent]
    const names: string[] = Array.isArray(meta?.names) ? meta.names : []
    if (!names.includes(KANON_CRED_ID_ATTRIBUTE) && !KANON_REFERENT_PATTERN.test(referent)) continue
    // biome-ignore lint/suspicious/noExplicitAny: sub_proof_index is on permissive payload
    const subProofIndex: number = (group as any).sub_proof_index
    const identifier = identifiers[subProofIndex]
    // biome-ignore lint/suspicious/noExplicitAny: values map is permissive
    const values = (group as any).values ?? {}
    const raw = values[KANON_CRED_ID_ATTRIBUTE]?.raw
    if (!identifier?.cred_def_id || raw === undefined) continue
    out.push({ credDefId: identifier.cred_def_id, credId: String(raw) })
  }

  return out
}

function collectKanonCredentialIdentifiersFromW3c(
  options: VerifyW3cPresentationOptions
): KanonCredentialIdentifier[] {
  const out: KanonCredentialIdentifier[] = []
  // biome-ignore lint/suspicious/noExplicitAny: presentation is a permissive W3C VP
  const presentation: any = options.presentation as any
  // biome-ignore lint/suspicious/noExplicitAny: verifiableCredential entries are permissive
  const vcs: any[] = Array.isArray(presentation?.verifiableCredential)
    ? presentation.verifiableCredential
    : presentation?.verifiableCredential
      ? [presentation.verifiableCredential]
      : []
  for (const vc of vcs) {
    const subject = vc?.credentialSubject
    const credDefId = vc?.credentialSchema?.id ?? vc?.credentialSchema?.[0]?.id ?? vc?.credentialDefinitionId
    const credId = subject?.[KANON_CRED_ID_ATTRIBUTE] ?? subject?.kanonCredId
    if (credDefId && credId) {
      out.push({ credDefId: String(credDefId), credId: String(credId) })
    }
  }
  return out
}
