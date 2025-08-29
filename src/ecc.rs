use alloc::vec::Vec;
use core::fmt::Debug;
use rand_chacha::rand_core::RngCore;

mod sys {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/micro_ecc_bindings.rs"));
}

#[derive(Copy, Clone)]
pub struct PrivateKey {
    public_key: [u8; 64],
    private_key: [u8; 32],
}

struct Redacted;

impl Debug for Redacted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("REDACTED")
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("private_key", &Redacted)
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PublicKey {
    public_key: [u8; 64],
}

impl PrivateKey {
    pub fn new() -> Self {
        let mut public_key = [0u8; 64];
        let mut private_key = [0u8; 32];
        unsafe {
            sys::uECC_make_key(public_key.as_mut_ptr(), private_key.as_mut_ptr(), sys::uECC_secp256r1());
        }
        Self {
            public_key,
            private_key,
        }
    }

    pub fn from_bytes(private_key: [u8; 32]) -> Self {
        let mut public_key = [0u8; 64];
        unsafe {
            sys::uECC_compute_public_key(private_key.as_ptr(), public_key.as_mut_ptr(), sys::uECC_secp256r1());
        }
        Self {
            public_key,
            private_key,
        }
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.private_key
    }

    pub fn private_asn1(&self) -> Vec<u8> {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x04;
        public_key[1..].copy_from_slice(self.public_key.as_ref());
        rasn::der::encode(&ASN1PrivateKey {
            id: rasn::types::Integer::from(1),
            private_key: rasn::types::OctetString::from_slice(&self.private_key),
            curve: ASN1PrivateKeyCurve {
                curve: rasn::types::Oid::ISO_MEMBER_BODY_US_ANSI_X962_EC_PRIME_256V1.into(),
            },
            public_key: ASN1PrivateKeyPublic {
                public_key: rasn::types::BitString::from_slice(&public_key),
            }
        }).unwrap()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            public_key: self.public_key,
        }
    }

    pub fn sign(&self, message_digest: &[u8]) -> [u8; 64] {
        let mut signature = [0u8; 64];
        unsafe {
            sys::uECC_sign(self.private_key.as_ptr(), message_digest.as_ptr(), message_digest.len() as u32, signature.as_mut_ptr(), sys::uECC_secp256r1());
        }
        signature
    }

    pub fn shared_secret(&self, peer_key: &PublicKey) -> [u8; 32] {
        let mut shared_secret = [0u8; 32];
        unsafe {
            sys::uECC_shared_secret(peer_key.public_key.as_ptr(), self.private_key.as_ptr(), shared_secret.as_mut_ptr(), sys::uECC_secp256r1());
        }
        shared_secret
    }
}

impl PublicKey {
    pub fn from_compressed_point(compressed_point: [u8; 33]) -> Self {
        let mut uncompressed_point = [0u8; 64];
        unsafe {
            sys::uECC_decompress(compressed_point.as_ptr(), uncompressed_point.as_mut_ptr(), sys::uECC_secp256r1());
        }
        Self {
            public_key: uncompressed_point
        }
    }

    pub fn x(&self) -> [u8; 32] {
        self.public_key[0..32].try_into().unwrap()
    }

    pub fn public_compressed_point(&self) -> [u8; 33] {
        let mut compressed_point = [0u8; 33];
        unsafe {
            sys::uECC_compress(self.public_key.as_ptr(), compressed_point.as_mut_ptr(), sys::uECC_secp256r1());
        }
        compressed_point
    }

    pub fn public_asn1(&self) -> Vec<u8> {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x04;
        public_key[1..].copy_from_slice(self.public_key.as_ref());
        rasn::der::encode(&ASN1PublicKey {
            id: [
                rasn::types::Oid::ISO_MEMBER_BODY_US_ANSI_X962_KEY_TYPE_EC_PUBLIC_KEY.into(),
                rasn::types::Oid::ISO_MEMBER_BODY_US_ANSI_X962_EC_PRIME_256V1.into(),
            ],
            public_key: rasn::types::BitString::from_slice(&public_key)
        }).unwrap()
    }
}

#[derive(rasn::AsnType, rasn::Encode)]
struct ASN1PrivateKey {
    id: rasn::types::Integer,
    private_key: rasn::types::OctetString,
    #[rasn(tag(0))]
    curve: ASN1PrivateKeyCurve,
    #[rasn(tag(1))]
    public_key: ASN1PrivateKeyPublic
}

#[derive(rasn::AsnType, rasn::Encode)]
struct ASN1PrivateKeyCurve {
    curve: rasn::types::ObjectIdentifier,
}

#[derive(rasn::AsnType, rasn::Encode)]
struct ASN1PrivateKeyPublic {
    public_key: rasn::types::BitString,
}

#[derive(rasn::AsnType, rasn::Encode)]
struct ASN1PublicKey {
    id: [rasn::types::ObjectIdentifier; 2],
    public_key: rasn::types::BitString,
}

pub fn signature_to_der(signature: &[u8; 64]) -> Vec<u8> {
    let mut out = vec![];
    let mut len = 68;
    let mut r_len = 32;
    let mut s_len = 32;
    if signature[0] & 0x80 != 0 {
        len += 1;
        r_len += 1;
    }
    if signature[32] & 0x80 != 0 {
        len += 1;
        s_len += 1;
    }
    out.push(0x30);
    out.push(len);
    out.push(0x02);
    out.push(r_len);
    if r_len == 33 {
        out.push(0x00);
    }
    out.extend_from_slice(&signature[0..32]);
    out.push(0x02);
    out.push(s_len);
    if s_len == 33 {
        out.push(0x00);
    }
    out.extend_from_slice(&signature[32..64]);
    out
}

pub fn init() {
    unsafe {
        sys::uECC_set_rng(Some(ecc_rng))
    }
}

#[no_mangle]
unsafe extern "C" fn ecc_rng(buf: *mut u8, len: u32) -> i32 {
    let mut r = embassy_futures::block_on(crate::RAND.lock());
    let buf = core::slice::from_raw_parts_mut(buf, len as usize);
    r.assume_init_mut().fill_bytes(buf);
    1
}