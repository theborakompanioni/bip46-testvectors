
export default {
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    rootpriv: 'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu',
    rootpub: 'xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8',

    // First timelocked address = m/84'/0'/0'/2/0
    first_derived_private_key: 'KxaN4YnskiixL5CrqjAN98CZ2GXatRrwtQFprAYMPysSzM2BE9Bt',
    first_derived_public_key: '03ff137af5f9b2e31e4bc2a75210c3f594c3a0c7881561c08560f5036e6831cabb',
    first_unix_locktime: 1577836800,
    first_string_locktime: '2020-01-01 00:00:00',
    first_redeemscript: '0400e10b5eb1752103ff137af5f9b2e31e4bc2a75210c3f594c3a0c7881561c08560f5036e6831cabbac',
    first_scriptPubKey: '0020bdee9515359fc9df912318523b4cd22f1c0b5410232dc943be73f9f4f07e39ad',
    first_address: 'bc1qx9fvepmj24wr4mr04zj22gtjx5eap8dy06v6c8evm44dkr3pm0yst3mmhn',

    // Test certificate using the first timelocked address
    // Note that as signatures contains a random nonce, it might not be exactly the same when your code generates it
    // p2pkh address is the p2pkh address corresponding to the derived public key, it can be used to verify the message
    //  signature in any wallet that supports Verify Message.
    // As mentioned before, it is more important for implementors of this standard to support signing such messages, not verifying them
    first_cert_message: 'fidelity-bond-cert|020000000000000000000000000000000000000000000000000000000000000001|375',
    first_cert_p2pkh_address: '16vmiGpY1rEaYnpGgtG7FZgr2uFCpeDgV6',
    first_cert_signature: 'H+ZQ9PqJFaUgkYx77cYCyO7pMrNUMTNsm98lApLzgLZxfjhCmmVMSJ0MiEo0UzE1tNpf+HGlXrDgtgxGvCcMgds=',

    // 2nd timelocked address = m/84'/0'/0'/2/1
    second_derived_private_key: 'KyfxXF38c6qdQ6q1XQsH3iZYuTrLUxd1h6QE2m5PdxC4jg4PyBKc',
    second_derived_public_key: '026c5f060538651b68ca3728a546c8e716abd1098da946adcf8e9fbdc3144a014c',
    second_unix_locktime: 1580515200,
    second_string_locktime: '2020-02-01 00:00:00',
    second_redeemscript: '0480bf345eb17521026c5f060538651b68ca3728a546c8e716abd1098da946adcf8e9fbdc3144a014cac',
    second_scriptPubKey: '0020b8f898643991608524ed04e0c6779f632a57f1ffa3a3a306cd81432c5533e9ae',
    second_address: 'bc1qcu9ydfp7a20hn0wjur3ht9ktweyjd98untdqk0f455f2r35a3zmsjscddw',

    // last timelocked address = m/84'/0'/0'/2/959
    last_derived_private_key: 'L1z276EvF9mN1c46aDGFLhQnGBosLKgNn5gRMDggbQfvsdaXugoD',
    last_derived_public_key: '03fe8c13f33af5d30d450acc2845e9982dbe37a667f190e68edb2b9bb7dd50232d',
    last_unix_locktime: 4099766400,
    last_string_locktime: '2099-12-01 00:00:00',
    last_redeemscript: '0580785df400b1752103fe8c13f33af5d30d450acc2845e9982dbe37a667f190e68edb2b9bb7dd50232dac',
    last_scriptPubKey: '0020803268e042008737cf439748cbb5a4449e311da9aa64ae3ac56d84d059654f85',
    last_address: 'bc1qa4hy8pjs7xk6c8gxq4e4qlcqgeef08k6uja9tet9mxf50u9f0h6sk0twmp',

    // Test certificate and endpoint signing using the first timelocked address = m/84'/0'/0'/2/0 (see above)
    example_bond_certificate_private_key: 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d',
    example_bond_certificate_public_key: '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c',
    example_bond_certificate_p2pkh_address: '1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso',
    example_bond_certificate_message: 'fidelity-bond-cert|0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c|375',
    example_bond_certificate_signature: 'IJxGwHOKrwUjTuRi0UVDYbh0Kbex9d8yR/x1KBe5rvCDVBohP0YC4R/p/x7vp/cGOm+/+jsxz121yJ7PGf+4EQ0=',
    // example endpoint signing two IRC nicknames (used in JoinMarket)
    example_endpoint_message: 'J54LS6YyJPoseqFS|J55VZ6U6ZyFDNeuv',
    example_endpoint_signature: 'H18WE4MugDNoWZIf9jU0njhQptdUyBDUf7lToG9bpMKmeJK0lOoABaDs5bKnohSuZ0e9gnSco5OL9lXdKU7gP5E=',

    // custom testnet vectors
    testnet_address0: 'tb1q45p4aqqla2pr0x95v0ukrkdgfu6t4hqklqlu6jum4pwh2may6pcqrjq6rn',
    testnet_address1: 'tb1qhzfrfmqea96qtmdgh2vskru9jjn9l6828s67ajy8r80zcmvamhgq0hm3sx',
    testnet_address959: 'tb1qrap6m7agdzdpmr3w5wuxynanrmk27kgd5f80l0fjjx5wmrf63zzsthvh6y',

    // custom regtest vectors
    regtest_address0: 'bcrt1q45p4aqqla2pr0x95v0ukrkdgfu6t4hqklqlu6jum4pwh2may6pcqwt2ukf',
    regtest_address1: 'bcrt1qhzfrfmqea96qtmdgh2vskru9jjn9l6828s67ajy8r80zcmvamhgqzw3h9u',
    regtest_address959: 'bcrt1qrap6m7agdzdpmr3w5wuxynanrmk27kgd5f80l0fjjx5wmrf63zzsxwx307',
}
