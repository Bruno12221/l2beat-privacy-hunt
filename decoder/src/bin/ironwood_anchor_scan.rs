use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
};

use incrementalmerkletree::frontier::Frontier;
use orchard::tree::MerkleHashOrchard;
use serde_json::Value;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "expected 32-byte hex value");
    let mut result = [0u8; 32];
    for (i, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    result
}

fn main() {
    let mut args = env::args().skip(1);
    let path = args
        .next()
        .expect("usage: ironwood_anchor_scan COMMITMENTS_JSONL TARGET_ANCHOR [TARGET_HEIGHT]");
    let target = args
        .next()
        .expect("usage: ironwood_anchor_scan COMMITMENTS_JSONL TARGET_ANCHOR [TARGET_HEIGHT]")
        .to_lowercase();
    let target_height = args.next().map(|value| {
        value
            .parse::<u64>()
            .expect("TARGET_HEIGHT must be an integer")
    });

    let mut frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();
    let mut count = 0u64;
    let mut matched = false;
    for line in BufReader::new(File::open(path).expect("open commitments JSONL")).lines() {
        let row: Value =
            serde_json::from_str(&line.expect("read JSONL line")).expect("parse JSONL");
        let height = row["height"].as_u64().expect("height");
        for cmx in row["cmx"].as_array().expect("cmx array") {
            let bytes = decode_32(cmx.as_str().expect("cmx string"));
            let leaf = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
                .expect("canonical cmx");
            assert!(frontier.append(leaf), "Ironwood tree is full");
            count += 1;
        }
        if target_height.is_none_or(|expected| expected == height) {
            let root = hex(&frontier.root().to_bytes());
            if root == target {
                println!("target_anchor_height={height}");
                println!("target_anchor_tree_size={count}");
                matched = true;
            }
        }
        if target_height == Some(height) {
            break;
        }
    }
    println!("final_tree_size={count}");
    println!("target_anchor_found={matched}");
}
