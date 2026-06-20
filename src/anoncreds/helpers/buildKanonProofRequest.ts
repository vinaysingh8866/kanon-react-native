import { KANON_CRED_ID_ATTRIBUTE } from '../utils/credIdHash'

// AnonCreds proof requests are inherently permissive shapes; we don't import a
// concrete type from `@credo-ts/anoncreds` to keep this helper usable from both
// issuer and verifier code paths without dragging the full module surface in.
// biome-ignore lint/suspicious/noExplicitAny: AnonCreds proof request is permissive
export type KanonProofRequest = Record<string, any>

export interface BuildKanonProofRequestInput {
  /**
   * The verifier's existing AnonCreds proof request. Not mutated.
   */
  proofRequest: KanonProofRequest
  /**
   * The list of credDefIds the caller knows live on the Kanon VDR. For each
   * entry an extra revealed attribute named `kanon_<credDefId>_credId` is added
   * with `restrictions: [{ cred_def_id: credDefId }]`, so the verifier can
   * extract the credId per credDef during {@link KanonWrappedAnonCredsVerifierService}.
   *
   * Entries already present (by referent name) are left untouched, making the
   * helper idempotent.
   */
  kanonCredDefIds: string[]
}

/**
 * Augments an AnonCreds proof request with the `kanonCredId` revealed entries
 * required by the Kanon verifier wrapper. The caller passes in the set of
 * credDefIds known to live on the Kanon VDR; for each one we add a uniquely
 * named revealed attribute (`kanon_<credDefId>_credId`) restricted to that
 * credDefId. Idempotent — calling twice produces the same request.
 *
 * The original `proofRequest` argument is not mutated; a shallow copy with a
 * cloned `requested_attributes` map is returned.
 */
export function buildKanonProofRequest(input: BuildKanonProofRequestInput): KanonProofRequest {
  const { proofRequest, kanonCredDefIds } = input
  if (!proofRequest || typeof proofRequest !== 'object') {
    throw new Error('buildKanonProofRequest: proofRequest must be an object')
  }
  if (!Array.isArray(kanonCredDefIds)) {
    throw new Error('buildKanonProofRequest: kanonCredDefIds must be an array of strings')
  }

  const requestedAttributes = { ...(proofRequest.requested_attributes ?? {}) }

  for (const credDefId of kanonCredDefIds) {
    if (typeof credDefId !== 'string' || credDefId.length === 0) {
      throw new Error('buildKanonProofRequest: each kanonCredDefIds entry must be a non-empty string')
    }
    const referent = `kanon_${credDefId}_credId`
    if (referent in requestedAttributes) continue
    requestedAttributes[referent] = {
      name: KANON_CRED_ID_ATTRIBUTE,
      restrictions: [{ cred_def_id: credDefId }],
    }
  }

  return {
    ...proofRequest,
    requested_attributes: requestedAttributes,
    requested_predicates: { ...(proofRequest.requested_predicates ?? {}) },
  }
}
