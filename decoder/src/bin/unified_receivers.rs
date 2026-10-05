//! Address parsing only. No keys, note recovery, transactions or signing.
//! Keep this separate so frozen note-ledger binary hashes do not change.
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use zcash_address::unified::{self, Container, Encoding};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode(packet: &Value) -> Result<Value, String> {
    let address = packet["address"]
        .as_str()
        .ok_or("expected address string")?;
    let (network, ua) = unified::Address::decode(address).map_err(|e| e.to_string())?;
    let receivers: Vec<Value> = ua
        .items()
        .iter()
        .map(|receiver| {
            let (kind, typecode, raw): (&str, u32, &[u8]) = match receiver {
                unified::Receiver::Orchard(raw) => ("orchard", 3, raw),
                unified::Receiver::Sapling(raw) => ("sapling", 2, raw),
                unified::Receiver::P2pkh(raw) => ("p2pkh", 0, raw),
                unified::Receiver::P2sh(raw) => ("p2sh", 1, raw),
                unified::Receiver::Unknown { typecode, data } => ("unknown", *typecode, data),
            };
            json!({"kind":kind, "typecode":typecode, "bytes":raw.len(), "rawHex":hex(raw)})
        })
        .collect();
    for receiver in ua.items() {
        if let unified::Receiver::Orchard(raw) = receiver {
            if !bool::from(orchard::Address::from_raw_address_bytes(&raw).is_some()) {
                return Err("invalid Orchard receiver point/diversifier".into());
            }
        }
    }
    Ok(
        json!({"ok":true, "address":address, "network":format!("{network:?}"),
              "canonicalAddress":ua.encode(&network), "receivers":receivers,
              "warning":"A decoded receiver is not wallet ownership or a note-to-nullifier link."}),
    )
}

fn main() {
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
            .and_then(|packet| decode(&packet))
            .unwrap_or_else(|error| json!({"ok":false, "error":error}));
        writeln!(stdout, "{result}").expect("write JSON result");
        stdout.flush().expect("flush JSON result");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CONTROL: &str = "u137z8vppwfefedxphuq2m8mhapvnzcnyqrhq0nnyzyngpzkckwc58lkmrjw9u697sl9n4gmpj3yg2qvz05afev443st27xpzlanny5w5e8j7la6cjr63shsfvh20ga4dmsacxdcswt09w23t3x9t99fgel02nqajdc5y59m32xym06rcc";

    #[test]
    fn control_matches_independently_recovered_receiver() {
        let result = decode(&json!({"address":CONTROL})).unwrap();
        assert_eq!(result["network"], "Main");
        assert_eq!(result["canonicalAddress"], CONTROL);
        assert!(result["receivers"].as_array().unwrap().iter().any(|r| {
            r["kind"] == "orchard" && r["rawHex"] ==
            "f31e15106054776dfe3baa34c6cb15df5cc76f3bdd88d1bef81922027b7f0e86983c747efe02b1d27a8e1a"
        }));
    }

    #[test]
    fn malformed_or_checksum_damaged_addresses_fail() {
        for packet in [
            json!({}),
            json!({"address":1}),
            json!({"address":"u1bad"}),
            json!({"address":format!("{}q", &CONTROL[..CONTROL.len()-1])}),
        ] {
            assert!(decode(&packet).is_err());
        }
    }

    #[test]
    fn network_is_preserved_not_silently_assumed_mainnet() {
        let (_, ua) = unified::Address::decode(CONTROL).unwrap();
        let address = ua.encode(&zcash_protocol::consensus::NetworkType::Test);
        assert_eq!(
            decode(&json!({"address":address})).unwrap()["network"],
            "Test"
        );
    }
}
