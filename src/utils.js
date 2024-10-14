import * as secp from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils'
import { networks, script, opcodes, payments } from 'bitcoinjs-lib'
import * as varint from 'varuint-bitcoin'

const __checkIndex = (index) => {
  if (index < 0 || index > 959) {
    throw new Error(
      `Unexpected value of index: Must be between 0 and 959, got ${index}`,
    )
  }
}

const indexToLocktime = (index) => {
  __checkIndex(index)
  const year = 2020 + Math.floor(index / 12)
  const month = 1 + (index % 12)
  const day = 1
  return Date.UTC(year, month - 1, day, 0, 0, 0, 0) / 1_000
}

const indexFromLocktime = (locktime) => {
  const date = new Date(locktime * 1_000)
  if (date.getUTCFullYear() < 2020 || date.getUTCFullYear() > 2099) {
    throw new Error(
      `Unexpected value of date: Year (UTC) must be between 2020 and 2099, got ${date.getUTCFullYear()}`,
    )
  }
  if (date.getUTCDate() != 1) {
    throw new Error(
      `Unexpected value of date: Day (UTC) must be 1, got ${date.getUTCDate()}`,
    )
  }
  if (
    date.getUTCHours() !== 0 ||
    date.getUTCMinutes() !== 0 ||
    date.getUTCSeconds() !== 0 ||
    date.getUTCMilliseconds() !== 0
  ) {
    throw new Error(
      `Unexpected value of date: Time (UTC) must be at midnight, got ${date.toUTCString()}`,
    )
  }

  return (date.getUTCFullYear() - 2020) * 12 + date.getUTCMonth()
}

const indexFromYearAndMonth = (year, month) => {
  const date = new Date()
  date.setUTCFullYear(year)
  date.setUTCMonth(month)
  date.setUTCDate(1)
  date.setUTCHours(0)
  date.setUTCMinutes(0)
  date.setUTCSeconds(0)
  date.setUTCMilliseconds(0)
  return indexFromLocktime(date.getTime() / 1_000)
}

const indexFromLocktimeUnsafe = (locktime) => {
  const date = new Date(locktime * 1_000)
  return indexFromYearAndMonth(date.getUTCFullYear(), date.getUTCMonth())
}

const NETWORKS = {
  bitcoin: networks.bitcoin,
  testnet: networks.testnet,
  regtest: networks.regtest,
}

const __toNetwork = (valueString) => {
  if (
    valueString !== undefined &&
    !Object.keys(NETWORKS).includes(valueString)
  ) {
    throw new Error(
      `Unexpected value of network type: Must be one of ${Object.keys(NETWORKS)}, got ${valueString}`,
    )
  }
  return (valueString && NETWORKS[valueString]) || NETWORKS['bitcoin']
}

const DERIVATION_PATH_MAINNET = `m/84'/0'/0'/2`
const DERIVATION_PATH_OTHERS = `m/84'/1'/0'/2`

const indexToDerivationPath = (index, networkString) => {
  __checkIndex(index)
  const network = __toNetwork(networkString)
  const pathPrefix =
    network === NETWORKS.bitcoin
      ? DERIVATION_PATH_MAINNET
      : DERIVATION_PATH_OTHERS
  return `${pathPrefix}/${index}`
}

const timelockedAddressFromLocktimeAndPublicKey = (
  nLockTime,
  publicKey,
  networkString,
) => {
  // If the nLockTime is less than 500 million, it is interpreted as a blockheight.
  // If the nLockTime is 500 million or more, it is interpreted as a UNIX timestamp.
  if (nLockTime < 500_000_000) {
    throw new Error(
      `Unexpected value of nLockTime: Must be greater or equal to 500_000_000, got ${nLockTime}`,
    )
  }
  if (publicKey.length !== 33) {
    throw new Error(
      `Unexpected length of public key: Must be 33 bytes, got ${publicKey.length}`,
    )
  }
  const network = __toNetwork(networkString)

  // <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP <derived_key> OP_CHECKSIG
  const locking_script = script.compile([
    script.number.encode(nLockTime),
    opcodes.OP_CHECKLOCKTIMEVERIFY,
    opcodes.OP_DROP,
    publicKey,
    opcodes.OP_CHECKSIG,
  ])
  const p2wsh = payments.p2wsh({
    redeem: { output: locking_script, network },
    network,
  })
  return p2wsh.address
}

const armorMessage = (message) => {
  const prefix_bytes = utf8ToBytes('\x18Bitcoin Signed Message:\n')
  const message_bytes = utf8ToBytes(message)
  const length_bytes = varint.encode(message_bytes.length).buffer

  const prefixed_message_raw = new Uint8Array(
    prefix_bytes.length + length_bytes.length + message_bytes.length,
  )
  prefixed_message_raw.set(prefix_bytes)
  prefixed_message_raw.set(length_bytes, prefix_bytes.length)
  prefixed_message_raw.set(
    message_bytes,
    prefix_bytes.length + length_bytes.length,
  )

  return prefixed_message_raw
}

const armorMessageHash = (message) => sha256(sha256(armorMessage(message)))

const SIG_RECOVERY_TYPE = {
  P2PKH_uncompressed: 27,
  P2PKH_compressed: 31,
  Segwit_P2SH: 35,
  Segwit_Bech32: 39,
}

const __toSigRecoveryType = (valueString) => {
  if (
    valueString !== undefined &&
    !Object.keys(SIG_RECOVERY_TYPE).includes(valueString)
  ) {
    throw new Error(
      `Unexpected value of signature type: Must be one of ${Object.keys(SIG_RECOVERY_TYPE)}, got ${valueString}`,
    )
  }
  return (
    (valueString && SIG_RECOVERY_TYPE[valueString]) ||
    SIG_RECOVERY_TYPE['P2PKH_compressed']
  )
}

const __toSignatureWithRecovery = (signature) => {
  if (signature.length !== 65) {
    throw new Error(
      `Signature length out of range: Must be 65 bytes, got ${signature.length}`,
    )
  }

  const headerInt = Buffer.from(signature.subarray(0, 1)).readInt8(0)
  const sigBytes = signature.subarray(1, 65)

  const recoveryId = ((headerInt) => {
    if (headerInt < 27 || headerInt > 42) {
      throw new Error(
        `Header byte out of range: Must be between 27 and 42, got ${headerInt}`,
      )
    }

    if (headerInt >= 39) return headerInt - 12 - 27
    if (headerInt >= 35) return headerInt - 8 - 27
    if (headerInt >= 31) return headerInt - 4 - 27
    return headerInt - 27
  })(headerInt)

  return secp.Signature.fromCompact(sigBytes)
    .addRecoveryBit(recoveryId)
    .assertValidity()
}

const sign = async (message, privateKey, typeString) => {
  const sig_recovery_type = __toSigRecoveryType(typeString)
  const message_hash = armorMessageHash(message)

  const signature = await secp.signAsync(message_hash, privateKey)
  const signature_bytes = signature.toCompactRawBytes()

  const header_number = sig_recovery_type + signature.recovery

  const header_bytes = hexToBytes(Number(header_number).toString(16))

  if (header_bytes.length !== 1) {
    throw new Error(
      `Unexpected length of header: Must be 1 byte, got ${header_bytes.length}`,
    )
  }

  const signature_with_header = new Uint8Array(
    header_bytes.length + signature_bytes.length,
  )
  signature_with_header.set(header_bytes)
  signature_with_header.set(signature_bytes, header_bytes.length)

  return signature_with_header
}

const verify = (message, signature) => {
  const sigWithRecovery = __toSignatureWithRecovery(signature)
  const messageHash = armorMessageHash(message)
  const publicKey = __recoverPublicKeyFromSignatureWithRecovery(
    message,
    sigWithRecovery,
  )
  return secp.verify(sigWithRecovery, messageHash, publicKey)
}

const __recoverPublicKeyFromSignatureWithRecovery = (
  message,
  sigWithRecovery,
) => {
  const messageHash = armorMessageHash(message)
  return sigWithRecovery.recoverPublicKey(messageHash)
}

const recoverPublicKey = (message, signature) => {
  const sigWithRecovery = __toSignatureWithRecovery(signature)
  return __recoverPublicKeyFromSignatureWithRecovery(message, sigWithRecovery)
}

export {
  indexToLocktime,
  indexFromYearAndMonth,
  indexFromLocktime,
  indexFromLocktimeUnsafe,
  indexToDerivationPath,
  timelockedAddressFromLocktimeAndPublicKey,
  armorMessageHash as __armorMessageHash,
  recoverPublicKey,
  sign,
  verify,
}
