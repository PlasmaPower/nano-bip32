use std::mem;

extern crate sha2;
use sha2::Sha512;

extern crate digest;
use digest::FixedOutput;

extern crate hmac;
use hmac::{Hmac, Mac};

extern crate crypto_mac;
use crypto_mac::MacResult;

extern crate curve25519_dalek;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

pub fn bytes_to_scalar(bytes: &[u8]) -> Scalar {
    let mut fixed_size = [0u8; 32];
    fixed_size.copy_from_slice(bytes);
    Scalar::from_bytes_mod_order(fixed_size)
}

fn hash_state(chain_code: &[u8; 32], key: CompressedEdwardsY, idx: u32) -> MacResult<<Sha512 as FixedOutput>::OutputSize> {
    let mut mac = Hmac::<Sha512>::new_varkey(chain_code).unwrap();
    mac.input(&[0x00]);
    mac.input(&key.to_bytes());
    mac.input(&unsafe { mem::transmute::<u32, [u8; 4]>(idx.to_be()) });
    mac.result()
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ChainState {
    pub key: Scalar,
    pub chain_code: [u8; 32],
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PublicChainState {
    pub key: CompressedEdwardsY,
    pub chain_code: [u8; 32],
}

impl ChainState {
    pub fn from_extended_key(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 64, "Invalid extended key length (should be 64 bytes)");
        let mut chain_code = [0u8; 32];
        chain_code.clone_from_slice(&bytes[32..]);
        ChainState {
            key: bytes_to_scalar(&bytes[..32]),
            chain_code,
        }
    }

    pub fn iterate(&mut self, idx: u32) {
        let result = hash_state(&self.chain_code, (&self.key * &ED25519_BASEPOINT_TABLE).compress(), idx).code();
        self.key = &bytes_to_scalar(&result.as_slice()[..32]) + &self.key;
        self.chain_code.copy_from_slice(&result.as_slice()[32..]);
    }

    pub fn as_public(&self) -> PublicChainState {
        PublicChainState {
            key: (&self.key * &ED25519_BASEPOINT_TABLE).compress(),
            chain_code: self.chain_code.clone(),
        }
    }

    pub fn as_extended_key(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        (&mut bytes[..32]).clone_from_slice(self.key.as_bytes());
        (&mut bytes[32..]).clone_from_slice(&self.chain_code);
        bytes
    }
}

impl PublicChainState {
    pub fn from_extended_key(bytes: &[u8]) -> Option<Self> {
        assert_eq!(bytes.len(), 64, "Invalid extended key length (should be 64 bytes)");
        let mut key_bytes = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key_bytes.clone_from_slice(&bytes[..32]);
        chain_code.clone_from_slice(&bytes[32..]);
        let key = CompressedEdwardsY(key_bytes);
        if key.decompress().is_none() {
            return None;
        }
        Some(PublicChainState {
            key,
            chain_code,
        })
    }

    pub fn iterate(&mut self, idx: u32) {
        let result = hash_state(&self.chain_code, self.key, idx).code();
        self.key = ((&bytes_to_scalar(&result.as_slice()[..32]) * &ED25519_BASEPOINT_TABLE) + &self.key.decompress().unwrap()).compress();
        self.chain_code.copy_from_slice(&result.as_slice()[32..]);
    }

    pub fn as_extended_key(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        (&mut bytes[..32]).clone_from_slice(self.key.as_bytes());
        (&mut bytes[32..]).clone_from_slice(&self.chain_code);
        bytes
    }
}

