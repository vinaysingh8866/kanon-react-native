import { KANON_CRED_ID_ATTRIBUTE } from '../utils/credIdHash'

/**
 * Input shape for {@link buildKanonSchema}: the standard AnonCreds schema shape
 * minus the `kanonCredId` housekeeping attribute.
 */
export interface BuildKanonSchemaInput {
  name: string
  version: string
  attrNames: string[]
  issuerId: string
}

/**
 * Returns an AnonCreds schema with the canonical `kanonCredId` attribute prepended
 * to `attrNames` when missing. Idempotent: if the caller already included
 * `kanonCredId` the schema is returned unchanged (modulo array copies).
 *
 * Throws when `attrNames` already contains a duplicate of `kanonCredId` (defensive
 * — AnonCreds schemas must not have duplicate attribute names).
 */
export function buildKanonSchema(input: BuildKanonSchemaInput): BuildKanonSchemaInput {
  if (!Array.isArray(input.attrNames)) {
    throw new Error('buildKanonSchema: attrNames must be an array of strings')
  }

  const occurrences = input.attrNames.filter((n) => n === KANON_CRED_ID_ATTRIBUTE).length
  if (occurrences > 1) {
    throw new Error(
      `buildKanonSchema: attrNames already contains duplicate '${KANON_CRED_ID_ATTRIBUTE}' entries; schemas may not declare duplicate attribute names`
    )
  }

  const attrNames =
    occurrences === 1 ? [...input.attrNames] : [KANON_CRED_ID_ATTRIBUTE, ...input.attrNames]

  return {
    name: input.name,
    version: input.version,
    issuerId: input.issuerId,
    attrNames,
  }
}
