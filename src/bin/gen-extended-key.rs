use std::env;

extern crate sha2;
use sha2::Sha512;

extern crate digest;
use digest::{Digest, FixedOutput};

extern crate hex;

extern crate nano_bip32;
use nano_bip32::ChainState;

fn main() {
    let mut args = env::args();
    args.next();
    let master_seed = hex::decode(args.next().expect("Expected master seed as argument")).expect("Failed to decode master seed as hex");
    assert_eq!(master_seed.len(), 64, "Incorrect master seed length (should be 64 bytes)");

    let mut digest = Sha512::default();
    digest.input(b"ed25519 seed");
    digest.input(&master_seed);
    let mut chain = ChainState::from_extended_key(digest.fixed_result().as_slice());

    chain.iterate(44);  // 44'
    chain.iterate(165); // 44'/165'

    println!("Extended private key: {}", hex::encode(&chain.as_extended_key() as &[u8]));
    println!("Extended public key: {}", hex::encode(&chain.as_public().as_extended_key() as &[u8]));
}
