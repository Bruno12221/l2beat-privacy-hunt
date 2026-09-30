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

