import type {
  AnonCredsCredentialDefinition,
  AnonCredsRegistry,
  AnonCredsSchema,
  GetCredentialDefinitionReturn,
  GetRevocationRegistryDefinitionReturn,
  GetRevocationStatusListReturn,
  GetSchemaReturn,
  RegisterCredentialDefinitionOptions,
  RegisterCredentialDefinitionReturn,
  RegisterRevocationRegistryDefinitionOptions,
  RegisterRevocationRegistryDefinitionReturn,
  RegisterRevocationStatusListOptions,
  RegisterRevocationStatusListReturn,
  RegisterSchemaOptions,
  RegisterSchemaReturn,
} from '@credo-ts/anoncreds'
import type { AgentContext } from '@credo-ts/core'

import { TIER_ONE_TIME } from '@ajna-inc/kanon-sdk'
import {
  anchorJson,
  credDefResourceId,
  decodeDataUri,
  encodeAnonCredsSchema,
  issuerOrgId,
  parseKanonDid,
  resourceIdToBytes32,
} from '@ajna-inc/kanon-sdk/anoncreds'
// Credo 0.5 does not re-export GenericRecordsApi from the package root (it was
// added to the public surface in 0.6). Import it from its module path so the
// class can be used both as the DI resolution token and for typing.
import { GenericRecordsApi } from '@credo-ts/core/build/modules/generic-records/GenericRecordsApi'
import { ethers } from 'ethers'

import { KanonClientService } from '../../ledger'
import { kanonCredIdHash } from '../utils/credIdHash'

// Tag prefix for the local GenericRecord that holds a cred-def body. kanon's
// CredentialDefinitionRegistry anchors only (schemaId, issuerOrg, issuerPubKey,
// policyMask) — the AnonCreds CL `value` has no on-chain home, so the issuing
// agent keeps the full body locally and serves it on resolve.
const CRED_DEF_RECORD_TAG = 'kanonCredDefBody'

function assertOrgIssuer(issuerId: string, kind: string): string {
  const parsed = parseKanonDid(issuerId)
  if (!parsed || parsed.scope !== 'org' || parsed.orgId == null) {
    throw new Error(`did:kanon: ${kind} issuer must be an org DID (did:kanon:org:0x<64 hex>), got '${issuerId}'`)
  }
  return issuerOrgId(issuerId)
}

export class KanonAnonCredsRegistry implements AnonCredsRegistry {
  public supportedIdentifier = /^did:kanon:.+$/

  public methodName = 'kanon'

  // ── Schemas ────────────────────────────────────────────────────────────

  public async registerSchema(
    agentContext: AgentContext,
    options: RegisterSchemaOptions
  ): Promise<RegisterSchemaReturn> {
    const schema = options.schema
    try {
      const orgId = assertOrgIssuer(schema.issuerId, 'schema')
      const enc = encodeAnonCredsSchema({
        issuerId: schema.issuerId,
        name: schema.name,
        version: schema.version,
        attrNames: schema.attrNames,
      })

      const clientService = agentContext.dependencyManager.resolve(KanonClientService)
      await clientService.client.registerSchema(
        clientService.getSigner(),
        orgId,
        enc.schemaIdBytes32,
        enc.schemaHash,
        enc.uri
      )

      return {
        schemaState: { state: 'finished', schema, schemaId: enc.schemaId },
        registrationMetadata: {},
        schemaMetadata: {},
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      agentContext.config.logger.debug(`Error registering schema for '${schema.issuerId}': ${message}`)
      return {
        schemaMetadata: {},
        registrationMetadata: {},
        schemaState: { state: 'failed', schema, reason: `unknownError: ${message}` },
      }
    }
  }

  public async getSchema(agentContext: AgentContext, schemaId: string): Promise<GetSchemaReturn> {
    try {
      const clientService = agentContext.dependencyManager.resolve(KanonClientService)
      const record = await clientService.contracts.schemaRegistry.getSchema(resourceIdToBytes32(schemaId))
      const body = record?.uri ? (decodeDataUri(record.uri) as Record<string, unknown> | null) : null
      if (!body) {
        return {
          schemaId,
          resolutionMetadata: { error: 'notFound', message: `schema not found: ${schemaId}` },
          schemaMetadata: {},
        }
      }
      const schema: AnonCredsSchema = {
        issuerId: String(body.issuerId),
        attrNames: (body.attrNames as string[]) ?? [],
        name: String(body.name),
        version: String(body.version),
      }
      return { schema, schemaId, resolutionMetadata: {}, schemaMetadata: {} }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      agentContext.config.logger.error(`Error retrieving schema '${schemaId}': ${message}`)
      return {
        schemaId,
        resolutionMetadata: { error: 'notFound', message: `unable to resolve schema: ${message}` },
        schemaMetadata: {},
      }
    }
  }

  // ── Credential definitions ───────────────────────────────────────────────

  public async registerCredentialDefinition(
    agentContext: AgentContext,
    options: RegisterCredentialDefinitionOptions
  ): Promise<RegisterCredentialDefinitionReturn> {
    const credentialDefinition = options.credentialDefinition
    try {
      const orgId = assertOrgIssuer(credentialDefinition.issuerId, 'cred-def')

      // The cred-def id is a DID URL under the issuer DID. We need the schema's
      // name as the schema tag; fetch the schema body for it.
      const schema = await this.getSchema(agentContext, credentialDefinition.schemaId)
      if (!schema.schema) throw new Error(`Schema not found: ${credentialDefinition.schemaId}`)

      const credDefId = credDefResourceId(credentialDefinition.issuerId, schema.schema.name, credentialDefinition.tag)

      // Store the full CL body inline as a data: URI (source of truth on
      // resolve, mirroring SchemaRegistry). issuerPubKey = keccak(canonical
      // body) stays the integrity anchor binding the entry to the body.
      const anchored = anchorJson(credentialDefinition)
      const issuerPubKey = ethers.getBytes(anchored.hash)

      await this.storeCredDefBody(agentContext, credDefId, credentialDefinition)

      const clientService = agentContext.dependencyManager.resolve(KanonClientService)
      await clientService.client.registerCredentialDefinition(
        clientService.getSigner(),
        resourceIdToBytes32(credDefId),
        resourceIdToBytes32(credentialDefinition.schemaId),
        issuerPubKey,
        TIER_ONE_TIME,
        anchored.uri
      )

      // Validate the org id matches the on-chain expectation (defensive — the
      // SDK already enforces membership; kept for parity with the reference).
      void orgId

      return {
        credentialDefinitionState: { state: 'finished', credentialDefinition, credentialDefinitionId: credDefId },
        registrationMetadata: {},
        credentialDefinitionMetadata: {},
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      agentContext.config.logger.debug(`Error registering cred-def for '${credentialDefinition.issuerId}': ${message}`)
      return {
        credentialDefinitionState: { state: 'failed', credentialDefinition, reason: `unknownError: ${message}` },
        registrationMetadata: {},
        credentialDefinitionMetadata: {},
      }
    }
  }

  public async getCredentialDefinition(
    agentContext: AgentContext,
    credentialDefinitionId: string
  ): Promise<GetCredentialDefinitionReturn> {
    try {
      // The full CL body is stored inline on-chain as a data: URI (source of
      // truth, mirroring schemas), so cross-agent resolution works. The local
      // store is consulted first only as an optional fast-path cache.
      let body = await this.loadCredDefBody(agentContext, credentialDefinitionId)
      if (!body) {
        const clientService = agentContext.dependencyManager.resolve(KanonClientService)
        const record = await clientService.contracts.credDefRegistry.getCredentialDefinition(
          resourceIdToBytes32(credentialDefinitionId)
        )
        const decoded = record?.uri ? (decodeDataUri(record.uri) as AnonCredsCredentialDefinition | null) : null
        if (!decoded) {
          return {
            credentialDefinitionId,
            resolutionMetadata: { error: 'notFound', message: `cred-def not found: ${credentialDefinitionId}` },
            credentialDefinitionMetadata: {},
          }
        }
        body = decoded
      }

      return {
        credentialDefinitionId,
        resolutionMetadata: {},
        credentialDefinitionMetadata: {},
        credentialDefinition: body,
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return {
        credentialDefinitionId,
        resolutionMetadata: { error: 'notFound', message: `unable to resolve cred-def: ${message}` },
        credentialDefinitionMetadata: {},
      }
    }
  }

  private async storeCredDefBody(
    agentContext: AgentContext,
    credDefId: string,
    body: AnonCredsCredentialDefinition
  ): Promise<void> {
    const genericRecords = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const existing = await genericRecords.findById(credDefId)
    if (existing) {
      existing.content = { body: body as unknown as Record<string, unknown> }
      await genericRecords.update(existing)
      return
    }
    await genericRecords.save({
      id: credDefId,
      content: { body: body as unknown as Record<string, unknown> },
      tags: { [CRED_DEF_RECORD_TAG]: credDefId },
    })
  }

  private async loadCredDefBody(
    agentContext: AgentContext,
    credDefId: string
  ): Promise<AnonCredsCredentialDefinition | null> {
    const genericRecords = agentContext.dependencyManager.resolve(GenericRecordsApi)
    const record = await genericRecords.findById(credDefId)
    if (!record) return null
    const body = record.content?.body
    return body ? (body as unknown as AnonCredsCredentialDefinition) : null
  }

  // ── Revocation (per-credential status registry; CL rev-reg unsupported) ─

  /**
   * Kanon does NOT implement the AnonCreds CKS revocation-registry model.
   * Per-credential status is tracked in `AnonCredsStatusRegistry` instead,
   * looked up by the verifier after `verifyProof` succeeds. These four methods
   * stay rejected so callers expecting CKS revocation surface a clear error.
   */
  public async getRevocationRegistryDefinition(
    _agentContext: AgentContext,
    revocationRegistryDefinitionId: string
  ): Promise<GetRevocationRegistryDefinitionReturn> {
    return {
      revocationRegistryDefinitionId,
      resolutionMetadata: {
        error: 'notFound',
        message:
          'Kanon VDR does not implement AnonCreds CKS revocation registries. Credentials use AnonCredsStatusRegistry status lookup after verifyProof.',
      },
      revocationRegistryDefinitionMetadata: {},
    }
  }

  public async registerRevocationRegistryDefinition(
    _agentContext: AgentContext,
    options: RegisterRevocationRegistryDefinitionOptions
  ): Promise<RegisterRevocationRegistryDefinitionReturn> {
    return {
      revocationRegistryDefinitionMetadata: {},
      registrationMetadata: {},
      revocationRegistryDefinitionState: {
        state: 'failed',
        revocationRegistryDefinition: options.revocationRegistryDefinition,
        reason:
          'Kanon VDR does not support AnonCreds CKS revocation registries. Issue credentials without revocationRegistryId; use KanonAnonCredsRegistry.revokeCredentialOnChain to revoke.',
      },
    }
  }

  public async getRevocationStatusList(
    _agentContext: AgentContext,
    _revocationRegistryId: string,
    _timestamp: number
  ): Promise<GetRevocationStatusListReturn> {
    return {
      resolutionMetadata: {
        error: 'notFound',
        message: 'Kanon VDR uses on-chain per-credential status, not CKS status lists.',
      },
      revocationStatusListMetadata: {},
    }
  }

  public async registerRevocationStatusList(
    _agentContext: AgentContext,
    options: RegisterRevocationStatusListOptions
  ): Promise<RegisterRevocationStatusListReturn> {
    return {
      revocationStatusListMetadata: {},
      registrationMetadata: {},
      revocationStatusListState: {
        state: 'failed',
        revocationStatusList: options.revocationStatusList,
        reason:
          'Kanon VDR uses on-chain per-credential status, not CKS status lists. Use revokeCredentialOnChain to revoke.',
      },
    }
  }

  // ────────────────────────────────────────────────────────────────────────
  // Kanon-specific status registry helpers (not part of AnonCredsRegistry)
  // ────────────────────────────────────────────────────────────────────────

  /**
   * Revokes a previously-issued credential by writing to the on-chain
   * `AnonCredsStatusRegistry`. The signer must be a member of the credDef's org.
   */
  public async revokeCredentialOnChain(agentContext: AgentContext, credDefId: string, credId: string): Promise<void> {
    const clientService = agentContext.dependencyManager.resolve(KanonClientService)
    if (!clientService.hasAnonCredsStatusRegistry()) {
      throw new Error('Cannot revoke: KanonModule was loaded without anonCredsStatusRegistryAddress')
    }
    await clientService.revokeCredentialStatus(credDefId, kanonCredIdHash(credId))
  }

  /**
   * Reads the on-chain revocation status of a credential.
   */
  public async isCredentialRevokedOnChain(
    agentContext: AgentContext,
    credDefId: string,
    credId: string
  ): Promise<boolean> {
    const clientService = agentContext.dependencyManager.resolve(KanonClientService)
    if (!clientService.hasAnonCredsStatusRegistry()) return false
    return clientService.isCredentialRevokedOnStatus(credDefId, kanonCredIdHash(credId))
  }
}
