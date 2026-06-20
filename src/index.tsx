/**
 * kanon-react-native — Kanon Credo-ts plugin, RN-ready.
 *
 * Owns the kanon plugin source directly — no runtime dep on `@ajna-inc/kanon`.
 * Credo is pinned as a peer dependency so mobile apps choose their own
 * Credo line. Sourced from the credo-ts-kanon v5 tree (Credo 0.5.x).
 *
 * Mobile setup notes
 * ------------------
 * React Native lacks Node's `crypto`, `Buffer`, and `process.env`.
 * Install the standard polyfills in your app entry (`index.js`), before
 * the first `import` of this module:
 *
 *     import 'react-native-get-random-values'  // crypto.getRandomValues
 *     import { Buffer } from '@craftzdog/react-native-buffer'
 *     global.Buffer = Buffer
 *     import 'reflect-metadata'                // tsyringe DI
 *
 * For the askar wallet on mobile, install
 * `@hyperledger/aries-askar-react-native` and pass `agentDependencies`
 * from `@credo-ts/react-native` into the Credo `Agent({ dependencies })`.
 */
import 'reflect-metadata';

// AnonCreds
export {
  KanonAnonCredsRegistry,
  KanonWrappedAnonCredsVerifierService,
  OriginalAnonCredsVerifierServiceSymbol,
  KanonWrappedAnonCredsHolderService,
  OriginalAnonCredsHolderServiceSymbol,
  KanonIssuanceTracker,
  KANON_CRED_ID_ATTRIBUTE,
  kanonCredIdHash,
  buildKanonSchema,
  buildKanonCredentialAttributes,
  buildKanonProofRequest,
} from './anoncreds';
export type {
  BuildKanonSchemaInput,
  BuildKanonCredentialAttributesResult,
  BuildKanonProofRequestInput,
  KanonCredentialAttribute,
  KanonProofRequest,
} from './anoncreds';

// Dids
export {
  KanonDidRegistrar,
} from './dids/KanonDidRegistrar';
export type {
  KanonDidCreateOptions,
  KanonDidUpdateOptions,
  KanonDidDeactivateOptions,
  KanonDidServiceOptions,
} from './dids/KanonDidRegistrar';
export { KanonDidResolver } from './dids/KanonDidResolver';
export {
  validateSpecCompliantPayload,
  VerificationMethods,
} from './dids/didEtherUtils';
export type { SpecValidationResult } from './dids/didEtherUtils';

// Ledger / SDK client
export { KanonClientService } from './ledger';

// Mode B (Groth16 non-revocation) — restart-survivable revoke surface.
export {
  KanonZkService,
  KanonZkApi,
  KanonZkIssuerKeyService,
  KanonZkPathService,
  padAttrsToCircuit,
  KANON_ZK_CIRCUIT_ATTRS,
} from './zk';

// Identifiers
export {
  parsekanonDid,
  kanonDidRegex,
  kanonDidUrlRegex,
  kanonPrefixRegex,
  orgDid,
  userDid,
} from './utils/identifiers';
export type { ParsedKanonDid } from './utils/identifiers';

// Module
export { KanonModule } from './KanonModule';
export { KanonModuleConfig } from './KanonModuleConfig';
export type {
  KanonModuleConfigOptions,
  KanonDeploymentInput,
  KanonDeploymentAddresses,
} from './KanonModuleConfig';
export { KanonApi } from './KanonApi';
