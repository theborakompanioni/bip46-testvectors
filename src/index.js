import { HDKey } from '@scure/bip32'
import * as bip39 from '@scure/bip39'
import { indexToDerivationPath, indexToLocktime, timelockedAddressFromLocktimeAndPublicKey } from './utils.js'

const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

;(async function() {
  const HD_KEY = HDKey.fromMasterSeed(
    await bip39.mnemonicToSeed(mnemonic),
  )

  for (let index = 0; index < 960; index++) {
    const locktime = indexToLocktime(index)
    const path = indexToDerivationPath(index)
    const derivedKey = HD_KEY.derive(path)
    const address = timelockedAddressFromLocktimeAndPublicKey(locktime, derivedKey.publicKey)
    console.log(`${index}: ${address}`)
  }
})()
