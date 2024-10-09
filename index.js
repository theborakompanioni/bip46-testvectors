import { recoverPublicKey } from './utils.js'

const sigBase64 = 'H2b/90XcKnIU/D1nSCPhk8OcxrHebMCr4Ok2d2yDnbKDTSThNsNKA64CT4v2kt+xA1JmGRG/dMnUUH1kKqCVSHo='
const cert_content = "fidelity-bond-cert|020000000000000000000000000000000000000000000000000000000000000001|375"
const sigBuffer = Buffer.from(sigBase64, 'base64')

const recoveredPubkey = recoverPublicKey(cert_content, sigBuffer)
console.log(recoveredPubkey.toHex())

if (recoveredPubkey.toHex() === '02a1b09f93073c63f205086440898141c0c3c6d24f69a18db608224bcf143fa011') {
    console.log('SUCCESS: Public Key matches!')
} else {
    console.log('ERROR: Public Key does not match!')
}
