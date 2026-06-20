# kanon-react-native

React-Native distribution of the **kanon AnonCreds VDR** Credo-ts plugin. Re-exports the public surface of [`@ajna-inc/kanon`](https://www.npmjs.com/package/@ajna-inc/kanon) (Credo-ts `0.6.x` build) so mobile wallets can drop kanon into a Credo agent the same way they would on Node.

## Install

```sh
yarn add kanon-react-native @ajna-inc/kanon \
  @credo-ts/core@^0.6.1 @credo-ts/anoncreds@^0.6.1 @credo-ts/didcomm@^0.6.1 \
  @credo-ts/react-native @hyperledger/aries-askar-react-native \
  ethers@^6 reflect-metadata
```

### Polyfills

React Native has no Node `Buffer`, no `crypto.getRandomValues`, and no metadata reflection out of the box. Install the polyfills the kanon SDK + ethers need at the top of your app entry, **before** importing anything else:

```sh
yarn add react-native-get-random-values @craftzdog/react-native-buffer
```

```ts
// index.js (or App.tsx top)
import 'react-native-get-random-values'        // crypto.getRandomValues
import { Buffer } from '@craftzdog/react-native-buffer'
global.Buffer = Buffer
import 'reflect-metadata'                       // tsyringe DI
```

## Usage

```ts
import { Agent, DidsModule } from '@credo-ts/core'
import { AnonCredsModule } from '@credo-ts/anoncreds'
import { agentDependencies } from '@credo-ts/react-native'
import { AskarModule } from '@credo-ts/askar'
import { askar } from '@hyperledger/aries-askar-react-native'
import {
  KanonModule,
  KanonAnonCredsRegistry,
  KanonDidRegistrar,
  KanonDidResolver,
  buildKanonSchema,
} from 'kanon-react-native'

const agent = new Agent({
  config: {
    label: 'mobile-wallet',
    walletConfig: { id: 'kanon-mobile', key: '<derive-from-secure-storage>' },
  },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({ askar }),
    anoncreds: new AnonCredsModule({
      registries: [new KanonAnonCredsRegistry()],
    }),
    dids: new DidsModule({
      registrars: [new KanonDidRegistrar()],
      resolvers: [new KanonDidResolver()],
    }),
    // KanonModule MUST come AFTER AnonCredsModule so its on-chain status
    // verifier override wins.
    kanon: new KanonModule({
      rpcUrl: '<your kanon RPC>',
      privateKey: '<holder operator key>',
      addressBook: '<KanonAddressBook contract address>',
      issuerOrgId: '<0x… 64-hex issuer org id>',
    }),
  },
})

await agent.initialize()

// Mint a holder DID
const { didState } = await agent.dids.create({
  method: 'kanon',
  scope: 'user',
})
const holderDid = didState.did!
```

## What ships

Re-exports from `@ajna-inc/kanon@^0.6`:

| Surface | Symbol |
|---|---|
| Module + config | `KanonModule`, `KanonApi`, `KanonModuleConfig`, `KanonModuleConfigOptions` |
| AnonCreds | `KanonAnonCredsRegistry`, `KanonWrappedAnonCredsVerifierService`, `KanonIssuanceTracker` |
| DID method | `KanonDidRegistrar`, `KanonDidResolver` |
| Helpers | `buildKanonSchema`, `buildKanonCredentialAttributes`, `buildKanonProofRequest` |
| Hashing | `KANON_CRED_ID_ATTRIBUTE`, `kanonCredIdHash` |
| Identifiers | `parsekanonDid`, `kanonDidRegex`, `orgDid`, `userDid` |
| Ledger | `KanonClientService` |

## Related

- Contracts: [`didkanon/contracts`](https://github.com/didkanon/contracts)
- SDK: [`@ajna-inc/kanon-sdk`](https://www.npmjs.com/package/@ajna-inc/kanon-sdk)
- Node-side plugin: [`@ajna-inc/kanon`](https://www.npmjs.com/package/@ajna-inc/kanon)
- ACA-Py plugin: [`didkanon/aca-py-did-kanon`](https://github.com/didkanon/aca-py-did-kanon)

## License

MIT.
