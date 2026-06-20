import type {
  AgentContext,
  DidCreateOptions,
  DidCreateResult,
  DidDeactivateOptions,
  DidDeactivateResult,
  DidOperationStateActionBase,
  DidRegistrar,
  DidUpdateOptions,
  DidUpdateResult,
} from '@credo-ts/core'

import { VerificationMethodType } from '@ajna-inc/kanon-sdk'
import { orgDid } from '@ajna-inc/kanon-sdk/anoncreds'
import {
  DidDocument,
  DidDocumentRole,
  DidDocumentService,
  DidRecord,
  DidRepository,
  KeyType,
  injectable,
} from '@credo-ts/core'
import { ethers } from 'ethers'

import { KanonModuleConfig } from '../KanonModuleConfig'
import { KanonClientService } from '../ledger'

export interface KanonDidServiceOptions {
  id: string
  type: string
  serviceEndpoint: string
}

/**
 * Mints + on-chain registers did:kanon DIDs against the kanon `DIDRegistry`.
 * Issuer DIDs are org-scoped (`did:kanon:org:<orgId>`); holder DIDs are
 * user-scoped (`did:kanon:user:0x<hash>`). Each DID gets a fresh Ed25519 key
 * minted in the agent wallet and registered as its first verification method.
 */
@injectable()
export class KanonDidRegistrar implements DidRegistrar {
  public readonly supportedMethods = ['kanon']

  public constructor(
    private clientService: KanonClientService,
    private config: KanonModuleConfig
  ) {}

  public async create(
    agentContext: AgentContext,
    options: KanonDidCreateOptions
  ): Promise<DidCreateResult<DidOperationStateActionBase>> {
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)
    // Ensure the address-book-resolved client is built (idempotent).
    await this.clientService.init()
    const client = this.clientService.client
    const signer = this.clientService.getSigner()

    const scope = options.scope ?? 'org'
    const services = options.options?.services ?? []
    // For user-scoped DIDs the salt must be generated ONCE and reused at
    // registration — computeUserDid() mints a fresh random salt per call.
    let userSalt: string | undefined

    try {
      // Credo 0.5 has no KMS; mint the Ed25519 verification key via the wallet API.
      // The returned Key exposes the raw public-key bytes and a base58 encoding.
      const key = await agentContext.wallet.createKey({ keyType: KeyType.Ed25519 })
      const publicKeyBase58 = key.publicKeyBase58
      const publicKeyHex = ethers.hexlify(key.publicKey)

      let did: string
      if (scope === 'org') {
        const orgId = options.orgId ?? this.config.issuerOrgId
        if (orgId == null) {
          throw new Error(
            'did:kanon: org-scoped DID needs an org id (set issuerOrgId in KanonModuleConfig or pass orgId)'
          )
        }
        did = orgDid(orgId)
      } else if (scope === 'user') {
        // Capture BOTH the did and its salt from a SINGLE computeUserDid call so
        // the same salt is reused below — otherwise the on-chain DID (salt #2)
        // would differ from the returned/saved DID (salt #1).
        const u = client.computeUserDid(await signer.getAddress())
        did = u.did
        userSalt = u.salt
      } else {
        throw new Error(`did:kanon: unknown scope '${scope}' (use 'org' or 'user')`)
      }

      const kid = `${did}#key-1`
      const vmId = ethers.keccak256(ethers.toUtf8Bytes(kid))

      const verificationMethods = [
        { id: vmId, vmType: VerificationMethodType.Ed25519VerificationKey2020, publicKey: publicKeyHex },
      ]
      const serviceStructs = services.map((svc) => ({
        id: ethers.keccak256(ethers.toUtf8Bytes(svc.id)),
        serviceType: svc.type,
        endpoint: svc.serviceEndpoint,
      }))

      if (scope === 'org') {
        // orgId is a bytes32 value encoded as a 0x<64 hex> string. Any revert
        // from registerOrgDid (e.g. a duplicate DID) propagates and is caught
        // below, surfacing as a `failed` DidCreateResult — never a fake success.
        const orgId = options.orgId ?? (this.config.issuerOrgId as string)
        await client.registerOrgDid(signer, orgId, {
          verificationMethods,
          services: serviceStructs,
        })
      } else {
        await client.registerUserDid(signer, userSalt as string, { verificationMethods })
      }

      // Build the W3C DID document we persist locally and return to the caller.
      const didDocument = new DidDocument({
        id: did,
        context: ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
        verificationMethod: [
          {
            id: kid,
            type: 'Ed25519VerificationKey2020',
            controller: did,
            publicKeyBase58,
          },
        ],
        authentication: [kid],
        assertionMethod: [kid],
        service: serviceStructs.length
          ? services.map(
              (svc) => new DidDocumentService({ id: svc.id, type: svc.type, serviceEndpoint: svc.serviceEndpoint })
            )
          : undefined,
      })

      const didRecord = new DidRecord({
        did,
        role: DidDocumentRole.Created,
        didDocument,
        tags: { method: 'kanon', role: DidDocumentRole.Created },
      })
      await didRepository.save(agentContext, didRecord)

      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'finished',
          did,
          didDocument,
          secret: options.secret,
        },
      }
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e)
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: { state: 'failed', reason },
      }
    }
  }

  public async update(_agentContext: AgentContext, _options: KanonDidUpdateOptions): Promise<DidUpdateResult> {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: 'did:kanon: update is not supported by this registrar',
      },
    }
  }

  public async deactivate(
    _agentContext: AgentContext,
    _options: KanonDidDeactivateOptions
  ): Promise<DidDeactivateResult> {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: 'did:kanon: deactivate is not supported by this registrar',
      },
    }
  }
}

export interface KanonDidCreateOptions extends DidCreateOptions {
  method: 'kanon'
  /** 'org' (issuer) or 'user' (holder). Defaults to 'org'. */
  scope?: 'org' | 'user'
  /** Org id (bytes32 as 0x<64 hex>) for org-scoped DIDs; falls back to config.issuerOrgId. */
  orgId?: string
  options?: {
    services?: KanonDidServiceOptions[]
  }
}

export interface KanonDidUpdateOptions extends DidUpdateOptions {
  method?: 'kanon'
  did: string
}

export interface KanonDidDeactivateOptions extends DidDeactivateOptions {
  method: 'kanon'
  did: string
}
