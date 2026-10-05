# Zero-OVK decoder

This utility parses a raw Zcash v6 transaction, attempts Ironwood output recovery with an all-zero outgoing viewing key, and checks whether the recovered recipient matches the Orchard/Ironwood receiver in a supplied unified address.

## Reproduce challenge 6

```bash
TXID=16c78159ec131f770cc396825a837e90ee7903de3f0aac329df4073598014d94
UA=u16pg4dnxy3a20qz4u2dccms6k50psm8s2vcwa5pvuksd2vc9kdzca0u7u2wx785em6jap5y9gn2vyxtc74mnzu2ak4ja6nd0hwxrzthpvnce2re04aef9z05qnjh7649h69atxxkq367ypzm6lqkq8mkn07qwwfqtyeyg4jcrpy9s5gy4

curl -sS "https://api.mainnet.cipherscan.app/api/tx/$TXID/raw" \
  | jq -r .hex \
  | xxd -r -p > challenge-6.bin

cargo run --release -- challenge-6.bin "$UA"
```

Expected core output:

```text
txid=16c78159ec131f770cc396825a837e90ee7903de3f0aac329df4073598014d94
ironwood_actions=1
ironwood[0] recovered_value_zat=143490
ironwood[0] target_ua_match=true
```

## Challenge 7 utilities

The additional binaries are `note_ledger` (JSON-line raw transaction decoding
and recoverable output values), `unified_receivers` (typed receiver bytes), and
`ironwood_anchor_scan` (public tree/anchor checks). Recovering an output does
not identify the private note consumed by a later transaction.

See the [Challenge 7 methods](../docs/challenge7/METHODS.md) for scope and data
requirements. Build in a separate target directory when preserving a pinned
historical binary; the publication deliberately excludes binaries and raw
evidence caches. The package's default run target remains the original
challenge-6 decoder, so adding these binaries does not change the command above.
