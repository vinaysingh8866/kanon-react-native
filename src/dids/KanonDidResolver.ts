import type { AgentContext, DidResolutionResult, DidResolver, ParsedDid } from '@credo-ts/core'

import { DidDocument, DidDocumentService, injectable, TypedArrayEncoder } from '@credo-ts/core'
import { ethers } from 'ethers'

import { parsekanonDid } from '../utils/identifiers'
import { KanonClientService } from '../ledger'

// VerificationMethodType (on-chain enum index) -> W3C type string.
const VM_TYPES = [
  'Ed25519VerificationKey2020',
  'EcdsaSecp256k1VerificationKey2019',
  'Bls12381G2Key2020',
  'JsonWebKey2020',
]

@injectable()
export class KanonDidResolver implements DidResolver {
  public readonly supportedMethods = ['kanon']
  public readonly allowsCaching = true
  public readonly allowsLocalDidRecord = true

  public constructor(private clientService: KanonClientService) {}

  public async resolve(agentContext: AgentContext, did: string, _parsed: ParsedDid): Promise<DidResolutionResult> {
    try {
      const parsed = parsekanonDid(did)
      if (!parsed) return this.errorResponse('notFound', `not a did:kanon DID: ${did}`)
      const baseDid = parsed.did

      const record = await this.clientService.client.resolveDidRecord(baseDid)
      if (!record) return this.errorResponse('notFound', `no DID document on chain for ${baseDid}`)
      if (record.deactivated) return this.errorResponse('notFound', `DID is deactivated: ${baseDid}`)

      const didDocument = this.toDidDocument(baseDid, record)
      return {
        didDocument,
        didDocumentMetadata: {},
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      agentContext.config.logger.error(`KanonDidResolver: error resolving DID ${did}: ${message}`)
      return this.errorResponse('notFound', `error resolving DID: ${message}`)
    }
  }

  private toDidDocument(
    did: string,
    record: NonNullable<Awaited<ReturnType<KanonClientService['client']['resolveDidRecord']>>>
  ): DidDocument {
    // On-chain VM ids are keccak hashes (not reversible), so we synthesize stable
    // `#key-N` fragments by position and map relationship references back to them.
    const idToFragment = new Map<string, string>()
    const verificationMethod = record.verificationMethods.map((vm, i) => {
      const fragment = `${did}#key-${i + 1}`
      idToFragment.set(vm.id.toLowerCase(), fragment)
      const type = vm.vmType < VM_TYPES.length ? VM_TYPES[vm.vmType] : 'JsonWebKey2020'
      const entry: Record<string, unknown> = { id: fragment, type, controller: did }
      const keyBytes = ethers.getBytes(vm.publicKeyHex)
      if (vm.vmType === 0) {
        entry.publicKeyBase58 = TypedArrayEncoder.toBase58(keyBytes)
      } else {
        entry.publicKeyHex = vm.publicKeyHex.replace(/^0x/, '')
      }
      return entry
    })

    const refs = (ids: string[]): string[] =>
      ids.map((r) => idToFragment.get(r.toLowerCase())).filter((f): f is string => Boolean(f))

    const service = record.services.map(
      (svc, i) =>
        new DidDocumentService({
          id: `${did}#service-${i + 1}`,
          type: svc.serviceType,
          serviceEndpoint: svc.endpoint,
        })
    )

    return new DidDocument({
      id: did,
      context: ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      // VM entries are dynamically typed per key type.
      verificationMethod: verificationMethod as never,
      authentication: refs(record.authentication),
      assertionMethod: refs(record.assertionMethod),
      service: service.length ? service : undefined,
    })
  }

  private errorResponse(error: string, message: string): DidResolutionResult {
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: { error, message },
    }
  }
}
