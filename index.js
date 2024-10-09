import * as secp from '@noble/secp256k1'
import { sha256} from '@noble/hashes/sha256'
import { bytesToHex, hexToBytes} from '@noble/hashes/utils'

function convertStringToUTF8ByteArray(str) {
    let binaryArray = new Uint8Array(str.length)
    Array.prototype.forEach.call(binaryArray, function (el, idx, arr) { arr[idx] = str.charCodeAt(idx) })
    return binaryArray
}

const sigBase64 = 'H2b/90XcKnIU/D1nSCPhk8OcxrHebMCr4Ok2d2yDnbKDTSThNsNKA64CT4v2kt+xA1JmGRG/dMnUUH1kKqCVSHo='
const sigBuffer = Buffer.from(sigBase64, 'base64')
const headerByte = sigBuffer.subarray(0, 1)
const sigBytes = sigBuffer.subarray(1, 65)

const recoveryId = ((headerByte) => {
    const headerInt = parseInt(headerByte.toString('hex'), 16)
    if (headerInt < 27 || headerInt > 42)
        throw new Error("Header byte out of range: " + headerInt);

    if(headerInt >= 39) return headerInt - 12 - 27
    if(headerInt >= 35) return headerInt - 8 - 27
    if(headerInt >= 31) return headerInt - 4 - 27
    return headerInt - 27
})(headerByte)

// const sig = secp.Signature.fromCompact(hexToBytes(sigBuffer.subarray(1, 65).toString('hex'))).assertValidity()
const sigWithRecovery = secp.Signature.fromCompact(sigBytes).addRecoveryBit(recoveryId).assertValidity()

const cert_content = "fidelity-bond-cert|020000000000000000000000000000000000000000000000000000000000000001|375"

const prefix_bytes = convertStringToUTF8ByteArray("\x18Bitcoin Signed Message:\n")
const cert_content_bytes = convertStringToUTF8ByteArray(cert_content)

const message = new Uint8Array(prefix_bytes.length + 1 + cert_content_bytes.length);
message.set(prefix_bytes)
message.set(hexToBytes(Number(cert_content_bytes.length).toString(16)), prefix_bytes.length)
message.set(cert_content_bytes, prefix_bytes.length + 1);
console.log('message: ' + bytesToHex(message))

const message_hash = sha256(sha256(message))
console.log('message hash:' + bytesToHex(message_hash))

const recoveredPubkey = sigWithRecovery.recoverPublicKey(message_hash)
console.log(recoveredPubkey.toHex())

if (recoveredPubkey.toHex() === '02a1b09f93073c63f205086440898141c0c3c6d24f69a18db608224bcf143fa011') {
    console.log('SUCCESS: Public Key matches!')
} else {
    console.log('ERROR: Public Key does not match!')
}
