import type { KanonContracts } from '@ajna-inc/kanon-sdk/core'

import { KanonClient } from '@ajna-inc/kanon-sdk'
import { inject, injectable, InjectionSymbols, type Logger } from '@credo-ts/core'
import { ethers } from 'ethers'

import { KanonModuleConfig } from '../KanonModuleConfig'

/**
 * ABI for the kanon AnonCredsStatusRegistry (per-credential issuance + revocation
 * status). The status registry is keyed by (credDefId, credIdHash) bytes32 pairs.
 */
const ANONCREDS_STATUS_REGISTRY_ABI = [
  'function issueCredential(bytes32 credDefId, bytes32 credIdHash)',
  'function revokeCredential(bytes32 credDefId, bytes32 credIdHash)',
  'function getStatus(bytes32 credDefId, bytes32 credIdHash) view returns (uint8)',
  'function isRevoked(bytes32 credDefId, bytes32 credIdHash) view returns (bool)',
  'function isActive(bytes32 credDefId, bytes32 credIdHash) view returns (bool)',
  'event CredentialIssued(bytes32 indexed credDefId, bytes32 indexed credIdHash, address indexed issuer, uint64 issuedAt)',
  'event CredentialRevoked(bytes32 indexed credDefId, bytes32 indexed credIdHash, address indexed issuer, uint64 revokedAt)',
]

/**
 * Thin wrapper over the kanon SDK `KanonClient`. Builds an ethers provider +
 * signer from the module config and exposes the SDK client, its typechain
 * registries, and the per-credential AnonCredsStatusRegistry helpers.
 */
/**
 * Minimal ABI for the kanon AnonCredsStatusRegistry getter on the address book.
 * The address book's `registries()` tuple exposes the status registry at the
 * `anonCredsStatusRegistry` field, but the SDK's `KanonClient` does not surface
 * it, so we read it directly when resolving via an address book.
 */
const ADDRESS_BOOK_STATUS_ABI = ['function anonCredsStatusRegistry() view returns (address)']

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

/**
 * Thin wrapper over the kanon SDK `KanonClient`. Builds an ethers provider +
 * signer from the module config and exposes the SDK client, its typechain
 * registries, and the per-credential AnonCredsStatusRegistry helpers.
 */
@injectable()
export class KanonClientService {
  private logger: Logger
  private provider: ethers.JsonRpcProvider
  private signer: ethers.Wallet
  private _client?: KanonClient
  private statusRegistryAddress?: string
  private addressBook?: string

  public constructor(config: KanonModuleConfig, @inject(InjectionSymbols.Logger) logger: Logger) {
    this.logger = logger
    if (!config.rpcUrl) throw new Error('KanonClientService: rpcUrl is required')
    if (!config.privateKey) throw new Error('KanonClientService: privateKey is required')

    this.provider = new ethers.JsonRpcProvider(config.rpcUrl)
    this.signer = new ethers.Wallet(config.privateKey, this.provider)
    this.statusRegistryAddress = config.anonCredsStatusRegistryAddress
    this.addressBook = config.addressBook

    // With an explicit deployment the client is built synchronously here. With
    // an address book the registries must be read on-chain first, so the client
    // is built lazily by `init()` (awaited by the module's `initialize`).
    if (!this.addressBook) {
      this._client = new KanonClient(config.sdkDeployment, this.signer)
    }
  }

  /**
   * Resolve the registries via the configured address book and build the SDK
   * client. No-op when an explicit deployment was used (client already built).
   * Called by the module's async `initialize`.
   */
  public async init(): Promise<void> {
    if (this._client) return
    if (!this.addressBook) {
      throw new Error('KanonClientService.init: no addressBook configured and client not built')
    }
    this._client = await KanonClient.fromAddressBook(this.addressBook, this.signer)
    // Resolve the status registry from the address book if not set explicitly.
    if (!this.statusRegistryAddress) {
      try {
        const book = new ethers.Contract(this.addressBook, ADDRESS_BOOK_STATUS_ABI, this.provider)
        const addr: string = await book.anonCredsStatusRegistry()
        if (addr && addr !== ZERO_ADDRESS) this.statusRegistryAddress = addr
      } catch (error) {
        this.logger.debug(`KanonClientService: could not resolve AnonCredsStatusRegistry from address book: ${error}`)
      }
    }
  }

  /** The SDK orchestration client. */
  public get client(): KanonClient {
    if (!this._client) {
      throw new Error('KanonClientService: client not initialized — addressBook resolution pending (call init()).')
    }
    return this._client
  }

  /** Typechain registries (orgRegistry, didRegistry, schemaRegistry, …). */
  public get contracts(): KanonContracts {
    return this.client.contracts
  }

  /** The operator signer used for on-chain writes. */
  public getSigner(): ethers.Wallet {
    return this.signer
  }

  // ─────────────────────────────────────────────────────────────────────────
  // AnonCredsStatusRegistry — kanon per-credential issuance + revocation status
  // ─────────────────────────────────────────────────────────────────────────

  public hasAnonCredsStatusRegistry(): boolean {
    return Boolean(this.statusRegistryAddress)
  }

  private getStatusRegistryAddress(): string {
    if (!this.statusRegistryAddress) {
      throw new Error(
        'AnonCredsStatusRegistry address not configured. Set anonCredsStatusRegistryAddress in KanonModuleConfig (or in the deployment addresses).'
      )
    }
    return this.statusRegistryAddress
  }

  private getStatusRegistry(forWrite = false) {
    const runner = forWrite ? this.signer : this.provider
    return new ethers.Contract(this.getStatusRegistryAddress(), ANONCREDS_STATUS_REGISTRY_ABI, runner)
  }

  public async issueCredentialStatus(credDefId: string, credIdHash: string) {
    const contract = this.getStatusRegistry(true)
    const tx = await contract.issueCredential(credDefId, credIdHash)
    return tx.wait()
  }

  public async revokeCredentialStatus(credDefId: string, credIdHash: string) {
    const contract = this.getStatusRegistry(true)
    const tx = await contract.revokeCredential(credDefId, credIdHash)
    return tx.wait()
  }

  public async isCredentialRevokedOnStatus(credDefId: string, credIdHash: string): Promise<boolean> {
    const contract = this.getStatusRegistry(false)
    return contract.isRevoked(credDefId, credIdHash)
  }

  public async getCredentialStatus(credDefId: string, credIdHash: string): Promise<number> {
    const contract = this.getStatusRegistry(false)
    const status: bigint = await contract.getStatus(credDefId, credIdHash)
    return Number(status)
  }
}
