import { recoverPublicKey } from './utils'
import TEST_VECTORS from './test_vectors'

describe('BIP-0046', () => {
    it(`should recover public key from signature (m/84'/0'/0'/2/0)`, () => {
        const message = TEST_VECTORS.first_cert_message
        const signatures = Buffer.from(TEST_VECTORS.first_cert_signature, 'base64')
        const recoveredPubkey = recoverPublicKey(message, signatures)

        expect(recoveredPubkey.toHex()).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should recover public key from signature for example bond certificate`, () => {
        const message = TEST_VECTORS.example_bond_certificate_message
        const signatures = Buffer.from(TEST_VECTORS.example_bond_certificate_signature, 'base64')
        const recoveredPubkey = recoverPublicKey(message, signatures)

        expect(recoveredPubkey.toHex()).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should recover public key from signature for example endpoint`, () => {
        const message = TEST_VECTORS.example_endpoint_message
        const signatures = Buffer.from(TEST_VECTORS.example_endpoint_signature, 'base64')
        const recoveredPubkey = recoverPublicKey(message, signatures)

        expect(recoveredPubkey.toHex()).toBe(TEST_VECTORS.example_bond_certificate_public_key)
    })
})
