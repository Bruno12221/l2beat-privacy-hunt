//! One JSON input per line -> one JSON result per line. Orchard and Ironwood.
//! Recovery with zero OVK proves an output's plaintext, not who later spent it.
use orchard::{Bundle, bundle::Authorized, keys::OutgoingViewingKey};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, Write},
};
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{consensus::BranchId, value::ZatBalance};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.is_ascii() {
        return Err("hex must contain an even number of ASCII characters".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| "invalid hex byte".into()))
        .collect()
}

fn outputs(bundle: &Bundle<Authorized, ZatBalance>, pool: &str, addresses: &[Value]) -> Vec<Value> {
    let ovk = OutgoingViewingKey::from([0u8; 32]);
    bundle
        .actions()
        .iter()
        .enumerate()
        .map(|(index, action)| {
            let mut record = json!({
                "pool": pool, "actionIndex": index,
                "cmx": hex(&(*action.cmx()).to_bytes()),
                "nullifier": hex(&(*action.nullifier()).to_bytes()),
                "recovered": false
            });
            if let Some((note, receiver, memo)) = bundle.recover_output_with_ovk(index, &ovk) {
                let receiver_raw = receiver.to_raw_address_bytes();
                let matching: Vec<Value> = addresses
                    .iter()
                    .filter_map(|value| {
                        let address = value.as_str()?;
                        let (_, ua) = unified::Address::decode(address).ok()?;
                        ua.items()
                            .iter()
                            .any(|item| {
                                matches!(item,
                    unified::Receiver::Orchard(raw) if raw == &receiver_raw)
                            })
                            .then(|| json!(address))
                    })
                    .collect();
                record["recovered"] = json!(true);
                record["valueZat"] = json!(note.value().inner());
                record["receiverRaw"] = json!(hex(&receiver_raw));
                record["memoHex"] = json!(hex(&memo));
                record["matchingUnifiedAddresses"] = json!(matching);
            }
            record
        })
        .collect()
}

fn decode(packet: &Value) -> Result<Value, String> {
    let raw = if let Some(text) = packet["hex"].as_str() {
        unhex(text)?
    } else if let Some(path) = packet["rawPath"].as_str() {
        fs::read(path).map_err(|error| error.to_string())?
    } else {
        return Err("expected hex or rawPath".into());
    };
    // V5/V6 embed their branch ID. V4 uses a serialization hash independent of
    // this parser's fallback branch. Its opt-in mode checks transparent bytes
    // only, reports no branch, and does NOT validate signatures or consensus.
    let mut cursor = &raw[..];
    let tx = Transaction::read(&mut cursor, BranchId::Nu6_3).map_err(|error| error.to_string())?;
    if !cursor.is_empty() {
        return Err("trailing bytes after transaction".into());
    }
    let txid = tx.txid().as_hex();
    if let Some(expected) = packet["expectedTxid"].as_str() {
        if expected.trim_start_matches("0x").to_ascii_lowercase() != txid {
            return Err(format!("transaction hash mismatch: computed {txid}"));
        }
    }
    let legacy_transparent = tx.version() == zcash_primitives::transaction::TxVersion::V4;
    if legacy_transparent {
        if packet["allowV4Transparent"].as_bool() != Some(true) {
            return Err(
                "decoder supports V5/V6 by default; V4 needs explicit transparent-only opt-in"
                    .into(),
            );
        }
        let mut serialized = Vec::new();
        tx.write(&mut serialized)
            .map_err(|error| error.to_string())?;
        if serialized != raw {
            return Err(
                "V4 does not round-trip exactly; no lossy transparent interpretation".into(),
            );
        }
    }
    let data = tx.into_data();
    if legacy_transparent {
        if data.sapling_bundle().is_some() || data.sprout_bundle().is_some() {
            return Err("V4 opt-in is transparent-only; shielded bundles are not supported".into());
        }
    } else if !matches!(
        data.version(),
        zcash_primitives::transaction::TxVersion::V5 | zcash_primitives::transaction::TxVersion::V6
    ) {
        return Err("decoder supports V5/V6 only; earlier branch selection is unverified".into());
    }
    let addresses = packet["unifiedAddresses"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut decoded_outputs = Vec::new();
    let mut bundles = Vec::new();
    for (pool, bundle) in [
        ("orchard", data.orchard_bundle()),
        ("ironwood", data.ironwood_bundle()),
    ] {
        if let Some(bundle) = bundle {
            let balance: i64 = (*bundle.value_balance()).into();
            let mut serialized_bundle = Vec::new();
            if data.version() == zcash_primitives::transaction::TxVersion::V6 {
                zcash_primitives::transaction::components::orchard::write_v6_bundle(
                    Some(bundle),
                    &mut serialized_bundle,
                )
                .map_err(|error| error.to_string())?;
            } else {
                zcash_primitives::transaction::components::orchard::write_v5_bundle(
                    Some(bundle),
                    &mut serialized_bundle,
                )
                .map_err(|error| error.to_string())?;
            }
            bundles.push(json!({
                "pool": pool, "valueBalanceZat": balance,
                "actions": bundle.actions().len(), "spendsEnabled": bundle.flags().spends_enabled(),
                "outputsEnabled": bundle.flags().outputs_enabled(),
                "crossAddressEnabled": bundle.flags().cross_address_enabled(),
                "anchor": hex(&(*bundle.anchor()).to_bytes()),
                "anchorIsEmptyTree": *bundle.anchor() == orchard::Anchor::empty_tree(),
                "bundleVersion": format!("{:?}", bundle.bundle_version()),
                "serializedBundleHex": hex(&serialized_bundle)
            }));
            decoded_outputs.extend(outputs(bundle, pool, &addresses));
        }
    }
    let transparent_outputs: Vec<Value> = data
        .transparent_bundle()
        .map(|bundle| {
            bundle
                .vout
                .iter()
                .enumerate()
                .map(|(index, output)| {
                    json!({
                        "index": index, "valueZat": output.value().into_u64(),
                        "scriptPubKeyHex": hex(&output.script_pubkey().0.0),
                        "recipientDebug": format!("{:?}", output.recipient_address())
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let transparent_inputs: Vec<Value> =
        data.transparent_bundle()
            .map(|bundle| {
                bundle.vin.iter().enumerate().map(|(index, input)| {
                let mut hash = *input.prevout().hash();
                hash.reverse();
                json!({"index": index, "prevTxid": hex(&hash), "prevVout": input.prevout().n()})
            }).collect()
            })
            .unwrap_or_default();
    Ok(json!({
        "ok": true, "txid": txid, "version": format!("{:?}", data.version()),
        "branch": if legacy_transparent { Value::Null } else { json!(format!("{:?}", data.consensus_branch_id())) },
        "legacyTransparentOnly": legacy_transparent,
        "locktime": data.lock_time(), "expiryHeight": u32::from(data.expiry_height()),
        "transparentInputCount": data.transparent_bundle().map(|b| b.vin.len()).unwrap_or(0),
        "transparentInputs": transparent_inputs,
        "transparentOutputs": transparent_outputs, "bundles": bundles, "outputs": decoded_outputs,
        "blockHeight": packet["blockHeight"], "blockTime": packet["blockTime"],
        "isCanonical": packet["isCanonical"],
        "warning": if legacy_transparent {
            "V4 serialization/txid/outpoints only; consensus branch, signatures and block inclusion are not independently verified."
        } else {
            "Zero-OVK recovery is an output disclosure, not a target spend/ownership proof."
        }
    }))
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let result = match line {
            Ok(line) => match serde_json::from_str::<Value>(&line) {
                Ok(packet) => decode(&packet).unwrap_or_else(|error| {
                    json!({
                        "ok": false, "expectedTxid": packet["expectedTxid"], "error": error
                    })
                }),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            },
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
        writeln!(stdout, "{result}").expect("write JSON result");
        stdout.flush().expect("flush JSON result");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_input_is_rejected() {
        assert!(unhex("a").is_err());
        assert!(unhex("zz").is_err());
        assert!(unhex("é").is_err());
        assert!(decode(&json!({})).is_err());
        assert!(decode(&json!({"hex": "00"})).is_err());
    }

    #[test]
    fn empty_anchor_matches_protocol_encoding() {
        assert_eq!(
            hex(&orchard::Anchor::empty_tree().to_bytes()),
            "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"
        );
    }

    fn transparent_v4_hex() -> String {
        let mut raw = unhex("0400008085202f890001").unwrap();
        raw.extend(100_000u64.to_le_bytes());
        raw.push(0); // empty output script; serialization test, not consensus-validity test
        raw.extend([0; 16]); // locktime, expiry, zero Sapling balance
        raw.extend([0; 3]); // empty Sapling spends/outputs and JoinSplits
        hex(&raw)
    }

    #[test]
    fn v4_requires_opt_in_and_does_not_claim_a_branch() {
        let raw = transparent_v4_hex();
        assert!(decode(&json!({"hex": raw})).is_err());
        let result = decode(&json!({"hex": raw, "allowV4Transparent": true})).unwrap();
        assert!(result["branch"].is_null());
        assert_eq!(result["version"], "V4");
        assert_eq!(result["transparentOutputs"][0]["valueZat"], 100_000);
        assert_eq!(result["legacyTransparentOnly"], true);
        assert!(
            decode(&json!({"hex": raw, "allowV4Transparent": true, "expectedTxid": "00"})).is_err()
        );
    }

    #[test]
    fn v4_trailing_bytes_and_lossy_balance_are_rejected() {
        let raw = transparent_v4_hex();
        assert!(decode(&json!({"hex": format!("{raw}00"), "allowV4Transparent": true})).is_err());
        let mut bytes = unhex(&raw).unwrap();
        let balance_offset = bytes.len() - 11;
        bytes[balance_offset] = 1; // no Sapling bundle to carry this invalid balance
        assert!(decode(&json!({"hex": hex(&bytes), "allowV4Transparent": true})).is_err());
    }
}
