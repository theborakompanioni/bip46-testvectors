import * as secp from '@noble/secp256k1'
import { sha256} from '@noble/hashes/sha256'
import { hexToBytes} from '@noble/hashes/utils'

const utf8ToBytes = (str) => {
    let binaryArray = new Uint8Array(str.length)
    Array.prototype.forEach.call(binaryArray, function (el, idx, arr) { arr[idx] = str.charCodeAt(idx) })
    return binaryArray
}

const recoverPublicKey = (message, signature) => {
    if (signature.length !== 65) {
        throw new Error(`Signature length out of range: Must be 65 bytes, got ${signature.length}`)
    }

    const headerByte = signature.subarray(0, 1)
    const sigBytes = signature.subarray(1, 65)

    const recoveryId = ((headerByte) => {
        const headerInt = parseInt(headerByte.toString('hex'), 16)
        if (headerInt < 27 || headerInt > 42) {
            throw new Error(`Header byte out of range: Must be between 27 and 42, got ${headerInt}`)
        }

        if(headerInt >= 39) return headerInt - 12 - 27
        if(headerInt >= 35) return headerInt - 8 - 27
        if(headerInt >= 31) return headerInt - 4 - 27
        return headerInt - 27
    })(headerByte)

    const sigWithRecovery = secp.Signature.fromCompact(sigBytes).addRecoveryBit(recoveryId).assertValidity()

    const prefix_bytes = utf8ToBytes("\x18Bitcoin Signed Message:\n")
    const message_bytes = utf8ToBytes(message)

    const prefixed_message_raw = new Uint8Array(prefix_bytes.length + 1 + message_bytes.length)
    prefixed_message_raw.set(prefix_bytes)
    prefixed_message_raw.set(hexToBytes(Number(message_bytes.length).toString(16)), prefix_bytes.length)
    prefixed_message_raw.set(message_bytes, prefix_bytes.length + 1)

    const message_hash = sha256(sha256(prefixed_message_raw))

    return sigWithRecovery.recoverPublicKey(message_hash)
}

export {
    recoverPublicKey,
}
