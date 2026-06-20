import type { KanonDeployment } from '@ajna-inc/kanon-sdk/core'

import { loadDeployment } from '@ajna-inc/kanon-sdk'

/**
 * The address book for a kanon deployment. Mirrors the `addresses` block of a
 * kanon `deployments/<chainId>.json` file. `AnonCredsStatusRegistry` is optional
 * here (the SDK's own deployment type does not carry it) but is required for
 * per-credential issuance + revocation status.
 */
export interface KanonDeploymentAddresses {
  OrganizationRegistry: string
  DIDRegistry: string
  SchemaRegistry: string
  CredentialDefinitionRegistry: string
  MerkleStateRegistry: string
  Halo2VerifierRegistry: string
  AnonCredsStatusRegistry?: string
}

/**
 * A kanon deployment record. Either passed inline or loaded from a deployment
 * JSON file path (`deploymentPath`). Matches the SDK's `KanonDeployment` shape
 * but the `addresses` block may additionally carry `AnonCredsStatusRegistry`.
 */
export interface KanonDeploymentInput {
  chainId: number
  network?: string
  deployedAt?: string
  deployer?: string
  rootAdmin?: string
  addresses: KanonDeploymentAddresses
  implementations?: Partial<KanonDeploymentAddresses>
}

/**
 * KanonModuleConfigOptions defines the interface for the options of the
 * KanonModuleConfig class. The full kanon deployment is required so the SDK
 * `KanonClient` can be constructed; the issuing org id is required for issuer
 * (schema / credential-definition) flows.
 */
export interface KanonModuleConfigOptions {
  /** RPC endpoint of the chain the kanon registries are deployed to. */
  rpcUrl: string
  /** Private key of the operator account used to sign on-chain writes. */
  privateKey: string
  /**
   * Address of the on-chain `KanonAddressBook` directory contract. When set,
   * the seven registry addresses are resolved from it on-chain (single-address
   * ergonomics) and an explicit `deployment`/`deploymentPath`/`chainId` is not
   * required. Falls back to the `KANON_ADDRESS_BOOK` env var.
   */
  addressBook?: string
  /**
   * The kanon deployment. Provide either an inline deployment object or a
   * `deploymentPath` to a deployment JSON file. If neither is given, the
   * deployment is loaded by `chainId` via the SDK's `loadDeployment`.
   */
  deployment?: KanonDeploymentInput
  /** Path to a kanon deployment JSON file (alternative to `deployment`). */
  deploymentPath?: string
  /** Chain id to load a bundled deployment for (when no inline/path given). */
  chainId?: number
  /**
   * Organization this agent issues under. Org-scoped issuer DIDs are
   * `did:kanon:org:<issuerOrgId>`. The orgId is a bytes32 value encoded as a
   * 0x<64 hex> string. Required for issuer flows.
   */
  issuerOrgId?: string
  /**
   * Address of the kanon AnonCredsStatusRegistry contract for per-credential
   * issuance + revocation status. Falls back to
   * `deployment.addresses.AnonCredsStatusRegistry`. If unset, status checks are
   * skipped (every credential is treated as not-revoked) and the issuance
   * tracker does nothing. Set this in production.
   */
  anonCredsStatusRegistryAddress?: string
}

function readDeploymentFile(path: string): KanonDeploymentInput {
  // `fs` is required lazily so the static-import surface stays
  // RN-clean (Metro doesn't try to resolve `node:fs`). Callers on
  // React Native should pass `deployment` inline or use `addressBook`
  // instead — `deploymentPath` only works on Node runtimes.
  let fsMod: typeof import('node:fs')
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    fsMod = require('node:fs') as typeof import('node:fs')
  } catch {
    throw new Error(
      `KanonModuleConfig: deploymentPath="${path}" is not supported on this ` +
        `runtime (no 'node:fs'). On React Native, pass the deployment inline via ` +
        `\`deployment\` or use \`addressBook\`.`
    )
  }
  const raw = fsMod.readFileSync(path, 'utf-8')
  const data = JSON.parse(raw)
  if (!data || typeof data !== 'object' || !data.addresses) {
    throw new Error(`Kanon deployment file ${path} is missing an 'addresses' block`)
  }
  return data as KanonDeploymentInput
}

export class KanonModuleConfig {
  private options: KanonModuleConfigOptions
  private resolvedDeployment: KanonDeploymentInput | undefined

  public constructor(options: KanonModuleConfigOptions) {
    this.options = options
    this.resolvedDeployment = KanonModuleConfig.resolveDeployment(options)
  }

  private static resolveDeployment(options: KanonModuleConfigOptions): KanonDeploymentInput | undefined {
    if (options.deployment) return options.deployment
    if (options.deploymentPath) return readDeploymentFile(options.deploymentPath)
    if (options.chainId != null) {
      // The SDK's bundled deployment for the chain id (throws if not found).
      return loadDeployment(options.chainId) as unknown as KanonDeploymentInput
    }
    // An address book resolves the registries on-chain, so an explicit
    // deployment is not required when one is configured.
    if (options.addressBook || process.env.KANON_ADDRESS_BOOK) return undefined
    throw new Error(
      'KanonModuleConfig: a kanon deployment is required — pass `deployment`, `deploymentPath`, `chainId`, or `addressBook`.'
    )
  }

  /** See {@link KanonModuleConfigOptions.addressBook} */
  public get addressBook(): string | undefined {
    return this.options.addressBook ?? process.env.KANON_ADDRESS_BOOK ?? undefined
  }

  /** See {@link KanonModuleConfigOptions.rpcUrl} */
  public get rpcUrl(): string {
    return this.options.rpcUrl
  }

  /** See {@link KanonModuleConfigOptions.privateKey} */
  public get privateKey(): string {
    return this.options.privateKey
  }

  /** See {@link KanonModuleConfigOptions.issuerOrgId} */
  public get issuerOrgId(): string | undefined {
    return this.options.issuerOrgId
  }

  /** The resolved kanon deployment (inline, file, or bundled), if any.
   * Undefined when the registries are resolved via an `addressBook`. */
  public get deployment(): KanonDeploymentInput | undefined {
    return this.resolvedDeployment
  }

  /**
   * The deployment in the exact shape the SDK's `connectKanon` / `KanonClient`
   * expects (i.e. without the optional AnonCredsStatusRegistry field that the
   * SDK type does not declare). Throws if only an `addressBook` is configured
   * (use `KanonClient.fromAddressBook` in that case).
   */
  public get sdkDeployment(): KanonDeployment {
    const d = this.resolvedDeployment
    if (!d) {
      throw new Error(
        'KanonModuleConfig.sdkDeployment is unavailable when only an addressBook is configured; resolve the client via KanonClient.fromAddressBook.'
      )
    }
    return {
      chainId: d.chainId,
      network: d.network ?? 'kanon',
      deployedAt: d.deployedAt ?? '',
      deployer: d.deployer ?? '',
      rootAdmin: d.rootAdmin ?? '',
      addresses: {
        OrganizationRegistry: d.addresses.OrganizationRegistry,
        DIDRegistry: d.addresses.DIDRegistry,
        SchemaRegistry: d.addresses.SchemaRegistry,
        CredentialDefinitionRegistry: d.addresses.CredentialDefinitionRegistry,
        MerkleStateRegistry: d.addresses.MerkleStateRegistry,
        Halo2VerifierRegistry: d.addresses.Halo2VerifierRegistry,
      },
    }
  }

  /** See {@link KanonModuleConfigOptions.anonCredsStatusRegistryAddress}.
   * When only an `addressBook` is configured, this may be resolved on-chain
   * by the client service during init (see `KanonClientService`). */
  public get anonCredsStatusRegistryAddress(): string | undefined {
    return (
      this.options.anonCredsStatusRegistryAddress ??
      this.resolvedDeployment?.addresses.AnonCredsStatusRegistry ??
      process.env.KANON_ANONCREDS_STATUS_REGISTRY_ADDRESS
    )
  }
}
