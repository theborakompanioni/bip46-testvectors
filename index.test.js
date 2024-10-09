import { base64 } from '@scure/base'
import * as secp from '@noble/secp256k1'
import * as bip39 from '@scure/bip39'
import { HDKey } from '@scure/bip32'
import { bytesToHex } from '@noble/hashes/utils'
import { networks } from 'bitcoinjs-lib'
import * as wif from 'wif'
import { indexToLocktime, timelockedAddressFromLocktimeAndPublicKey, recoverPublicKey, sign, __armorMessageHash } from './utils'
import TEST_VECTORS from './test_vectors'

describe('BIP-0046', () => {
    it(`should verify xpriv/xpub`, async () => {
        const seed = await bip39.mnemonicToSeed(TEST_VECTORS.mnemonic)
        const hdkey = HDKey.fromMasterSeed(seed)
        
        expect(hdkey.privateExtendedKey).toBe(TEST_VECTORS.rootpriv)
        expect(hdkey.publicExtendedKey).toBe(TEST_VECTORS.rootpub)
    })

    it(`should verify keys (m/84'/0'/0'/2/0)`, async () => {
        const hdkey = HDKey.fromMasterSeed(await bip39.mnemonicToSeed(TEST_VECTORS.mnemonic))

        const derivedKey = hdkey.derive(`m/84'/0'/0'/2/0`)
        expect(wif.encode({
            version: networks.bitcoin.wif /*parseInt('0x80')*/,
            privateKey: derivedKey.privateKey,
            compressed: true
        })).toBe(TEST_VECTORS.first_derived_private_key)
        expect(bytesToHex(derivedKey.privateKey)).toBe('a91720ac2166678a3020a89db803b038e1a1549b88af8751b89c5efddfa99f67')
        expect(bytesToHex(derivedKey.publicKey)).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should verify pubkey from private key (m/84'/0'/0'/2/0)`, () => {
        const privateKey = wif.decode(TEST_VECTORS.first_derived_private_key).privateKey
        const recoveredPubkey = secp.getPublicKey(privateKey)

        expect(bytesToHex(recoveredPubkey)).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should verify timelocked address (m/84'/0'/0'/2/0)`, async () => {
        const hdkey = HDKey.fromMasterSeed(await bip39.mnemonicToSeed(TEST_VECTORS.mnemonic))
        
        const index = 0
        const locktime = indexToLocktime(index)
        expect(locktime).toBe(TEST_VECTORS.first_unix_locktime)

        const derivedKey = hdkey.derive(`m/84'/0'/0'/2/${index}`)
        const address = timelockedAddressFromLocktimeAndPublicKey(locktime, derivedKey.publicKey)

        expect(address).toBe(TEST_VECTORS.first_address)
    })

    it(`should verify keys (m/84'/0'/0'/2/1)`, async () => {
        const hdkey = HDKey.fromMasterSeed(await bip39.mnemonicToSeed(TEST_VECTORS.mnemonic))

        const derivedKey = hdkey.derive(`m/84'/0'/0'/2/1`)
        expect(wif.encode({
            version: networks.bitcoin.wif /*parseInt('0x80')*/,
            privateKey: derivedKey.privateKey,
            compressed: true
        })).toBe(TEST_VECTORS.second_derived_private_key)
        expect(bytesToHex(derivedKey.privateKey)).toBe('29c2f965ba6375d902c2e800550b7bd8d9b46b6ba9a55edcd5f6811dc97b9b48')
        expect(bytesToHex(derivedKey.publicKey)).toBe(TEST_VECTORS.second_derived_public_key)
    })

    it(`should verify timelocked address (m/84'/0'/0'/2/1)`, async () => {
        const hdkey = HDKey.fromMasterSeed(await bip39.mnemonicToSeed(TEST_VECTORS.mnemonic))

        const index = 1
        const locktime = indexToLocktime(index)
        expect(locktime).toBe(TEST_VECTORS.second_unix_locktime)

        const derivedKey = hdkey.derive(`m/84'/0'/0'/2/${index}`)
        const address = timelockedAddressFromLocktimeAndPublicKey(TEST_VECTORS.second_unix_locktime, derivedKey.publicKey)

        expect(address).toBe(TEST_VECTORS.second_address)
    })

    it(`should verify keys (m/84'/0'/0'/2/959)`, async () => {
        const hdkey = HDKey.fromMasterSeed(await bip39.mnemonicToSeed(TEST_VECTORS.mnemonic))

        const derivedKey = hdkey.derive(`m/84'/0'/0'/2/959`)
        expect(wif.encode({
            version: networks.bitcoin.wif /*parseInt('0x80')*/,
            privateKey: derivedKey.privateKey,
            compressed: true
        })).toBe(TEST_VECTORS.last_derived_private_key)
        expect(bytesToHex(derivedKey.privateKey)).toBe('f8b20a5e63f6ecce5497ad21c6e8d3878d26e8c7685729152b2df747cb038175')
        expect(bytesToHex(derivedKey.publicKey)).toBe(TEST_VECTORS.last_derived_public_key)
    })

    it(`should verify timelocked address (m/84'/0'/0'/2/959)`, async () => {
        const hdkey = HDKey.fromMasterSeed(await bip39.mnemonicToSeed(TEST_VECTORS.mnemonic))
        
        const index = 959
        const locktime = indexToLocktime(index)
        expect(locktime).toBe(TEST_VECTORS.last_unix_locktime)

        const derivedKey = hdkey.derive(`m/84'/0'/0'/2/${index}`)
        const address = timelockedAddressFromLocktimeAndPublicKey(TEST_VECTORS.last_unix_locktime, derivedKey.publicKey)

        expect(address).toBe(TEST_VECTORS.last_address)
    })

    it(`should recover public key from signature (m/84'/0'/0'/2/0)`, () => {
        const message = TEST_VECTORS.first_cert_message
        const signatures = base64.decode(TEST_VECTORS.first_cert_signature)
        const recoveredPubkey = recoverPublicKey(message, signatures)

        expect(recoveredPubkey.toHex()).toBe(TEST_VECTORS.first_derived_public_key)
    })

    it(`should verify message hash for first certificate`, () => {
        expect(bytesToHex(__armorMessageHash(TEST_VECTORS.first_cert_message))).toBe('b35542aaf7c0acdb9ab3a9c48197d9bc323dd45d66afca33d226643356ff023a')
    })

    it(`should verify signature for first certificate`, async () => {
        const message = TEST_VECTORS.first_cert_message
        const privateKey = wif.decode(TEST_VECTORS.first_derived_private_key).privateKey
        const signature = await sign(message, privateKey)

        expect(base64.encode(signature)).toBe(TEST_VECTORS.first_cert_signature)
    })

    it(`should verify message hash for example bond certificate`, () => {
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
