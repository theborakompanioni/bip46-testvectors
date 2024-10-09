import * as secp from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils'
import * as varint from 'varuint-bitcoin'

const SIG_RECOVERY_TYPE = {
    'P2PKH_uncompressed': 27,
    'P2PKH_compressed': 31,
    'Segwit_P2SH': 35,
    'Segwit_Bech32': 39
}

const sign = async (message, privateKey, type) => {
    const prefix_bytes = utf8ToBytes("\x18Bitcoin Signed Message:\n")
    const message_bytes = utf8ToBytes(message)
    const length_bytes = varint.encode(message_bytes.length).buffer

    const prefixed_message_raw = new Uint8Array(prefix_bytes.length + length_bytes.length + message_bytes.length)
    prefixed_message_raw.set(prefix_bytes)
    prefixed_message_raw.set(length_bytes, prefix_bytes.length)
    prefixed_message_raw.set(message_bytes, prefix_bytes.length + length_bytes.length)

    const message_hash = sha256(sha256(prefixed_message_raw))

    const signature = await secp.signAsync(message_hash, privateKey)
    const signature_bytes = signature.toCompactRawBytes()

    const type_constant = (type && SIG_RECOVERY_TYPE[type]) || SIG_RECOVERY_TYPE['P2PKH_compressed']

    const header_number = type_constant + signature.recovery

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

    const prefix_bytes = utf8ToBytes("\x18Bitcoin Signed Message:\n")
    const message_bytes = utf8ToBytes(message)
    const length_bytes = varint.encode(message_bytes.length).buffer

    const prefixed_message_raw = new Uint8Array(prefix_bytes.length + length_bytes.length + message_bytes.length)
    prefixed_message_raw.set(prefix_bytes)
    prefixed_message_raw.set(length_bytes, prefix_bytes.length)
    prefixed_message_raw.set(message_bytes, prefix_bytes.length + length_bytes.length)

    const message_hash = sha256(sha256(prefixed_message_raw))

    return sigWithRecovery.recoverPublicKey(message_hash)
}

export {
    recoverPublicKey,
    sign
}
