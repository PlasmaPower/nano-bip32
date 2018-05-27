use std::env;

extern crate hex;

extern crate nano_bip32;
use nano_bip32::ChainState;

fn main() {
    let mut args = env::args();
    args.next();
    let extended_private_key = hex::decode(args.next().expect("Expected extended private key as first argument")).expect("Failed to decode extended private key as hex");
    assert_eq!(extended_private_key.len(), 64, "Incorrect extended private key length (should be 64 bytes)");
    let idx = args.next().expect("Expected index as second argument").parse().expect("Failed to parse index");

    let mut chain = ChainState::from_extended_key(&extended_private_key);
    chain.iterate(idx);

    println!("Private key: {}", hex::encode(chain.key.as_bytes()));
    println!("Public key: {}", hex::encode(chain.as_public().key.as_bytes()));
}
