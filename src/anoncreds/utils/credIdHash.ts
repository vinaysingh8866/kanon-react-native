/**
 * Re-export of the canonical credId hash helpers from `@ajna-inc/kanon-sdk`.
 * Issuer (at issuance time) and verifier (at status lookup time) MUST use the
 * exact same function so the bytes32 keys line up — keeping the source of
 * truth in the SDK guarantees that.
 */
export { kanonCredIdHash, KANON_CRED_ID_ATTRIBUTE } from '@ajna-inc/kanon-sdk/anoncreds'
