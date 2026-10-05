use std::{env, fs};

use orchard::{keys::OutgoingViewingKey, note_encryption::IronwoodDomain};
use zcash_address::unified::{self, Container, Encoding};
use zcash_note_encryption::try_output_recovery_with_ovk;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let mut args = env::args().skip(1);
    let path = args
        .next()
        .expect("usage: zcash-zero-ovk-decoder RAW_TX TARGET_UA");
    let target_ua = args
        .next()
        .expect("usage: zcash-zero-ovk-decoder RAW_TX TARGET_UA");

    let raw = fs::read(path).expect("read raw transaction");
    let tx = Transaction::read(&raw[..], BranchId::Nu6_3).expect("parse transaction");
    println!("txid={}", tx.txid().as_hex());

    let data = tx.into_data();
    println!("version={:?}", data.version());

    if let Some(bundle) = data.transparent_bundle() {
        println!("transparent_inputs={}", bundle.vin.len());
        println!("transparent_outputs={}", bundle.vout.len());
        for (i, output) in bundle.vout.iter().enumerate() {
            println!(
                "vout[{i}] value_zat={} recipient={:?}",
                output.value().into_u64(),
                output.recipient_address(),
            );
        }
    }

    let (_, ua) = unified::Address::decode(&target_ua).expect("decode target UA");
    let ua_orchard = ua.items().into_iter().find_map(|receiver| match receiver {
        unified::Receiver::Orchard(raw) => Some(raw),
        _ => None,
    });

    if let Some(bundle) = data.ironwood_bundle() {
        println!("ironwood_bundle_version={:?}", bundle.bundle_version());
        println!("ironwood_anchor={}", hex(&(*bundle.anchor()).to_bytes()));
        println!(
            "ironwood_spends_enabled={}",
            bundle.flags().spends_enabled()
        );
        println!(
            "ironwood_outputs_enabled={}",
            bundle.flags().outputs_enabled()
        );
        println!(
            "ironwood_cross_address_enabled={}",
            bundle.flags().cross_address_enabled()
        );
        println!("ironwood_actions={}", bundle.actions().len());
        let ovk = OutgoingViewingKey::from([0u8; 32]);

        for (i, action) in bundle.actions().iter().enumerate() {
            println!(
                "ironwood[{i}] nullifier={}",
                hex(&(*action.nullifier()).to_bytes())
            );
            println!("ironwood[{i}] cmx={}", hex(&(*action.cmx()).to_bytes()));
            let domain = IronwoodDomain::for_action(action);
            let recovered = try_output_recovery_with_ovk(
                &domain,
                &ovk,
                action,
                action.cv_net(),
                &action.encrypted_note().out_ciphertext,
            );

            match recovered {
                Some((note, recipient, memo)) => {
                    let raw = recipient.to_raw_address_bytes();
                    println!("ironwood[{i}] recovered_value_zat={}", note.value().inner());
                    println!("ironwood[{i}] recovered_recipient_raw={}", hex(&raw));
                    println!("ironwood[{i}] target_ua_match={}", ua_orchard == Some(raw));
                    println!("ironwood[{i}] memo_prefix={}", hex(&memo[..32]));
                }
                None => println!("ironwood[{i}] zero_ovk_recovery=false"),
            }
        }
    }
}
