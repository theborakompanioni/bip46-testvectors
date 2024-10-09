
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

    // 2nd timelocked address = m/84'/0'/0'/2/1
    second_derived_private_key: 'KxctaFBzetyc9KXeUr6jxESCZiCEXRuwnQMw7h7hroP6MqnWN6Pf',
    second_derived_public_key: '02599f6db8b33265a44200fef0be79c927398ed0b46c6a82fa6ddaa5be2714002d',
    second_unix_locktime: 1580515200,
    second_string_locktime: '2020-02-01 00:00:00',
    second_redeemscript: '0480bf345eb1752102599f6db8b33265a44200fef0be79c927398ed0b46c6a82fa6ddaa5be2714002dac',
    second_scriptPubKey: '0020b8f898643991608524ed04e0c6779f632a57f1ffa3a3a306cd81432c5533e9ae',
    second_address: 'bc1qhrufsepej9sg2f8dqnsvvaulvv490u0l5w36xpkds9pjc4fnaxhq7pcm4h',

    // last timelocked address = m/84'/0'/0'/2/959
    last_derived_private_key: 'L5Z9DDMnj5RZMyyPiQLCvN48Xt7GGmev6cjvJXD8uz5EqiY8trNJ',
    last_derived_public_key: '0308c5751121b1ae5c973cdc7071312f6fc10ab864262f0cbd8134f056166e50f3',
    last_unix_locktime: 4099766400,
    last_string_locktime: '2099-12-01 00:00:00',
    last_redeemscript: '0580785df400b175210308c5751121b1ae5c973cdc7071312f6fc10ab864262f0cbd8134f056166e50f3ac',
    last_scriptPubKey: '0020803268e042008737cf439748cbb5a4449e311da9aa64ae3ac56d84d059654f85',
    last_address: 'bc1qsqex3czzqzrn0n6rjayvhddygj0rz8df4fj2uwk9dkzdqkt9f7zs5c493u',

    // Test certificate and endpoint signing using the first timelocked address = m/84'/0'/0'/2/0 (see above)
    example_bond_certificate_private_key: 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d',
    example_bond_certificate_public_key: '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c',
    example_bond_certificate_p2pkh_address: '1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso',
    example_bond_certificate_message: 'fidelity-bond-cert|0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c|375',
    example_bond_certificate_signature: 'INOP3cB9UW7F1e1Aglj8rI9QhnyxmgWDEPt+nOMvl7hJJne7rH/KCNDYvLiqNuB9qWaWUojutjRsgPJrvyDQ+0Y=',
    // example endpoint signing two IRC nicknames (used in JoinMarket)
    example_endpoint_message: 'J54LS6YyJPoseqFS|J55VZ6U6ZyFDNeuv',
    example_endpoint_signature: 'H18WE4MugDNoWZIf9jU0njhQptdUyBDUf7lToG9bpMKmeJK0lOoABaDs5bKnohSuZ0e9gnSco5OL9lXdKU7gP5E=',
}
