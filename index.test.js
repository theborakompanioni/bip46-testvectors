import { base64 } from '@scure/base'
import * as secp from '@noble/secp256k1'
import { bytesToHex } from '@noble/hashes/utils'
import * as wif from 'wif'
import { recoverPublicKey, sign, __armorMessageHash } from './utils'
import TEST_VECTORS from './test_vectors'

describe('BIP-0046', () => {
    it(`should verify private key (m/84'/0'/0'/2/0)`, async () => {
        const privateKey = wif.decode(TEST_VECTORS.first_derived_private_key).privateKey
        expect(bytesToHex(privateKey)).toBe('a91720ac2166678a3020a89db803b038e1a1549b88af8751b89c5efddfa99f67')
    })

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

    it(`should verify message hash for first certificate`, async () => {
        expect(bytesToHex(__armorMessageHash(TEST_VECTORS.first_cert_message))).toBe('b35542aaf7c0acdb9ab3a9c48197d9bc323dd45d66afca33d226643356ff023a')
    })

    it(`should verify signature for first certificate`, async () => {
        const message = TEST_VECTORS.first_cert_message
        const privateKey = wif.decode(TEST_VECTORS.first_derived_private_key).privateKey
        const signature = await sign(message, privateKey)

        console.log(bytesToHex(signature))

        expect(base64.encode(signature)).toBe(TEST_VECTORS.first_cert_signature)
    })

    it(`should verify message hash for example bond certificate`, async () => {
        expect(bytesToHex(__armorMessageHash(TEST_VECTORS.example_bond_certificate_message))).toBe('0bf60ceb8c54f310460710ce2f782d4f9e53fdfd4e9230032e53fb814a6ee176')
    })

    it(`should verify signature for example bond certificate`, async () => {
        const message = TEST_VECTORS.example_bond_certificate_message
        const privateKey = wif.decode(TEST_VECTORS.first_derived_private_key).privateKey
        const signature = await sign(message, privateKey)

        expect(base64.encode(signature)).toBe(TEST_VECTORS.example_bond_certificate_signature)
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
