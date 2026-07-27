import { HDKey } from '@scure/bip32'
import * as bip39 from '@scure/bip39'
import {
  indexToDerivationPath,
  indexToLocktime,
  timelockedAddressFromLocktimeAndPublicKey,
} from './utils.js'

const DEFAULT_NETWORK = 'regtest'

const args = process.argv.slice(2)

const arg = (name, defaultValue) => args.filter(it => it.startsWith(`--${name}=`))
  .map(it => it.slice(`--${name}=`.length))[0] || defaultValue

const network = arg('network', DEFAULT_NETWORK)

const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

;(async function () {
  const HD_KEY = HDKey.fromMasterSeed(await bip39.mnemonicToSeed(mnemonic))

  for (let index = 0; index < 960; index++) {
    const locktime = indexToLocktime(index)
    const path = indexToDerivationPath(index, network)
    const derivedKey = HD_KEY.derive(path)
    const address = timelockedAddressFromLocktimeAndPublicKey(
      locktime,
      derivedKey.publicKey,
      network,
    )

    const humanReadableTime = new Date(locktime * 1_000).toLocaleDateString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    })

    console.log(`#${index} (${locktime}; ${humanReadableTime}): ${address}`)
  }
})()
