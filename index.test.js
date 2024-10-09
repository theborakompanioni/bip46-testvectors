import { base64 } from '@scure/base'
import * as secp from '@noble/secp256k1'
import { bytesToHex } from '@noble/hashes/utils'
import * as wif from 'wif'
import { recoverPublicKey, sign } from './utils'
import TEST_VECTORS from './test_vectors'

describe('BIP-0046', () => {
    it(`should verify pubkey from private key (m/84'/0'/0'/2/0)`, () => {
        const privateKey = wif.decode(TEST_VECTORS.first_derived_private_key).privateKey
        const recoveredPubkey = secp.getPublicKey(privateKey)

        expect(bytesToHex(recoveredPubkey)).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should recover public key from signature (m/84'/0'/0'/2/0)`, () => {
        const message = TEST_VECTORS.first_cert_message
        const signatures = base64.decode(TEST_VECTORS.first_cert_signature)
        const recoveredPubkey = recoverPublicKey(message, signatures)

        expect(recoveredPubkey.toHex()).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should recover public key from signature for example bond certificate`, () => {
        const message = TEST_VECTORS.example_bond_certificate_message
        const signatures = base64.decode(TEST_VECTORS.example_bond_certificate_signature)
        const recoveredPubkey = recoverPublicKey(message, signatures)

        expect(recoveredPubkey.toHex()).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should verify signature for example endpoint`, async () => {
        const message = TEST_VECTORS.example_endpoint_message
        const privateKey = wif.decode(TEST_VECTORS.example_bond_certificate_private_key).privateKey
        const signature = await sign(message, privateKey)

        expect(base64.encode(signature)).toBe(TEST_VECTORS.example_endpoint_signature)
    })

    it(`should recover public key from signature for example endpoint`, () => {
        const message = TEST_VECTORS.example_endpoint_message
        const signatures = base64.decode(TEST_VECTORS.example_endpoint_signature)
        const recoveredPubkey = recoverPublicKey(message, signatures)

        expect(recoveredPubkey.toHex()).toBe(TEST_VECTORS.example_bond_certificate_public_key)
    })
})
