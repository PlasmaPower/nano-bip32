use std::env;

extern crate hex;

extern crate nano_bip32;
use nano_bip32::PublicChainState;

fn main() {
    let mut args = env::args();
    args.next();
    let extended_public_key = hex::decode(args.next().expect("Expected extended public key as first argument")).expect("Failed to decode extended public key as hex");
    assert_eq!(extended_public_key.len(), 64, "Incorrect extended public key length (should be 64 bytes)");
    let idx = args.next().expect("Expected index as second argument").parse().expect("Failed to parse index");

    let mut chain = PublicChainState::from_extended_key(&extended_public_key).expect("Invalid expanded public key");
    chain.iterate(idx);

    println!("Public key: {}", hex::encode(chain.key.as_bytes()));
}
