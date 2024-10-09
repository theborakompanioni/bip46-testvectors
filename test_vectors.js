
export default {
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    rootpriv: 'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu',
    rootpub: 'xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8',

    // First timelocked address = m/84'/0'/0'/2/0
    first_derived_private_key: 'L2tQBEdhC48YLeEWNg3e4msk94iKfyVa9hdfzRwUERabZ53TfH3d',
    first_derived_public_key: '02a1b09f93073c63f205086440898141c0c3c6d24f69a18db608224bcf143fa011',
    first_unix_locktime: 1577836800,
    first_string_locktime: '2020-01-01 00:00:00',
    first_redeemscript: '0400e10b5eb1752102a1b09f93073c63f205086440898141c0c3c6d24f69a18db608224bcf143fa011ac',
    first_scriptPubKey: '0020bdee9515359fc9df912318523b4cd22f1c0b5410232dc943be73f9f4f07e39ad',
    first_address: 'bc1qhhhf29f4nlyalyfrrpfrknxj9uwqk4qsyvkujsa7w0ulfur78xkspsqn84',

    // Test certificate using the first timelocked address
    // Note that as signatures contains a random nonce, it might not be exactly the same when your code generates it
    // p2pkh address is the p2pkh address corresponding to the derived public key, it can be used to verify the message
    //  signature in any wallet that supports Verify Message.
    // As mentioned before, it is more important for implementors of this standard to support signing such messages, not verifying them
    first_cert_message: 'fidelity-bond-cert|020000000000000000000000000000000000000000000000000000000000000001|375',
    first_cert_p2pkh_address: '16vmiGpY1rEaYnpGgtG7FZgr2uFCpeDgV6',
    first_cert_signature: 'H2b/90XcKnIU/D1nSCPhk8OcxrHebMCr4Ok2d2yDnbKDTSThNsNKA64CT4v2kt+xA1JmGRG/dMnUUH1kKqCVSHo=',
}