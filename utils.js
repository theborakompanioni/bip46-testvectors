import * as secp from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils'
import { networks, script, opcodes, payments } from 'bitcoinjs-lib'
import * as varint from 'varuint-bitcoin'

const redeemscriptAddressFromPublicKey = (nLockTime, publicKey, network) => {   
    // If the nLockTime is less than 500 million, it is interpreted as a blockheight.
    // If the nLockTime is 500 million or more, it is interpreted as a UNIX timestamp.
    if (nLockTime < 500_000_000) {
        throw new Error(`Unexpected value of nLockTime: Must be greater or equal to 500_000_000, got ${nLockTime}`)
    } 
    if (publicKey.length !== 33) {
        throw new Error(`Unexpected length of public key: Must be 33 bytes, got ${publicKey.length}`)
    }
    if (network !== 'bitcoin' && network !== 'testnet' && network !== 'regtest' && network !== undefined) {
        throw new Error(`Unexpected value of network: Must be one of "bitcoin", "testnet" or "regtest", got ${nLockTime}`)
    }
    const _network = network === 'regtest' ? networks.regtest : (network === 'testnet' ? networks.testnet : networks.bitcoin)
    
    // <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP <derived_key> OP_CHECKSIG
    const locking_script = script.compile([
        script.number.encode(nLockTime),
        opcodes.OP_CHECKLOCKTIMEVERIFY,
        opcodes.OP_DROP,
        publicKey,
        opcodes.OP_CHECKSIG,
      ])
    const p2wsh = payments.p2wsh({ redeem: { output: locking_script, network: _network }, network: _network })
    return p2wsh.address
}

const armorMessage = (message) => {
    const prefix_bytes = utf8ToBytes("\x18Bitcoin Signed Message:\n")
    const message_bytes = utf8ToBytes(message)
    const length_bytes = varint.encode(message_bytes.length).buffer

    const prefixed_message_raw = new Uint8Array(prefix_bytes.length + length_bytes.length + message_bytes.length)
    prefixed_message_raw.set(prefix_bytes)
    prefixed_message_raw.set(length_bytes, prefix_bytes.length)
    prefixed_message_raw.set(message_bytes, prefix_bytes.length + length_bytes.length)

    return prefixed_message_raw
}

const armorMessageHash = (message) => {
    const prefixed_message_raw = armorMessage(message)
    return sha256(sha256(prefixed_message_raw))
}

const SIG_RECOVERY_TYPE = {
    'P2PKH_uncompressed': 27,
    'P2PKH_compressed': 31,
    'Segwit_P2SH': 35,
    'Segwit_Bech32': 39
}

const sign = async (message, privateKey, type) => {
    const message_hash = armorMessageHash(message)

    const signature = await secp.signAsync(message_hash, privateKey)
    const signature_bytes = signature.toCompactRawBytes()

    const _type = (type && SIG_RECOVERY_TYPE[type]) || SIG_RECOVERY_TYPE['P2PKH_compressed']

    const header_number = _type + signature.recovery

    const header_bytes = hexToBytes(Number(header_number).toString(16))

    if (header_bytes.length !== 1) {
        throw new Error(`Unexpected length of header: Must be 1 byte, got ${header_bytes.length}`)
    }

    const signature_with_header = new Uint8Array(header_bytes.length + signature_bytes.length);
    signature_with_header.set(header_bytes);
    signature_with_header.set(signature_bytes, header_bytes.length);

    return signature_with_header
}

const recoverPublicKey = (message, signature) => {
    if (signature.length !== 65) {
        throw new Error(`Signature length out of range: Must be 65 bytes, got ${signature.length}`)
    }

    const headerInt = Buffer.from(signature.subarray(0, 1)).readInt8(0)
    const sigBytes = signature.subarray(1, 65)

    const recoveryId = ((headerInt) => {
        if (headerInt < 27 || headerInt > 42) {
            throw new Error(`Header byte out of range: Must be between 27 and 42, got ${headerInt}`)
        }

        if(headerInt >= 39) return headerInt - 12 - 27
        if(headerInt >= 35) return headerInt - 8 - 27
        if(headerInt >= 31) return headerInt - 4 - 27
        return headerInt - 27
    })(headerInt)

    const sigWithRecovery = secp.Signature.fromCompact(sigBytes).addRecoveryBit(recoveryId).assertValidity()

    const message_hash = armorMessageHash(message)

    return sigWithRecovery.recoverPublicKey(message_hash)
}

export {
    redeemscriptAddressFromPublicKey,
    armorMessageHash as __armorMessageHash,
    recoverPublicKey,
    sign
}
