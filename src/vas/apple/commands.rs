use crate::vas::{find_tlv_tag, get_tlv_primitive_value, VasError};

lazy_static::lazy_static! {
    pub static ref DEVICE_VERSION: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F21).unwrap();
    pub static ref TERMINAL_VERSION: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F22).unwrap();
    pub static ref DEVICE_CAPABILITIES: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F23).unwrap();
    pub static ref DEVICE_NONCE: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F24).unwrap();
    pub static ref PASS_ID_HASH: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F25).unwrap();
    pub static ref TERMINAL_CAPABILITIES: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F26).unwrap();
    pub static ref DEVICE_CRYPTOGRAM: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F27).unwrap();
    pub static ref TERMINAL_NONCE: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F28).unwrap();


    pub static ref GET_DATA_RESPONSE: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x70).unwrap();
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum TerminalCapabilities {
    VasOrEmv = 0,
    VasAndEmv = 1,
    VasOnly = 2,
    EmvOnly = 3,
}

#[derive(Debug)]
pub struct GetData {
    pub version: (u8, u8),
    pub pass_hash: [u8; 32],
    pub capabilities: TerminalCapabilities,
    pub final_command: bool
}

impl GetData {
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let mut out = vec![];
        out.extend(iso7816_tlv::ber::Tlv::new(
            TERMINAL_VERSION.clone(), iso7816_tlv::ber::Value::Primitive(vec![self.version.0, self.version.1])
        ).unwrap().to_vec());
        out.extend(iso7816_tlv::ber::Tlv::new(
            PASS_ID_HASH.clone(), iso7816_tlv::ber::Value::Primitive(self.pass_hash.to_vec())
        ).unwrap().to_vec());
        out.extend(iso7816_tlv::ber::Tlv::new(
            TERMINAL_CAPABILITIES.clone(), iso7816_tlv::ber::Value::Primitive(vec![0, 0, 0, self.capabilities as u8 | (if self.final_command { 0 } else { 128 })])
        ).unwrap().to_vec());
        out.extend(iso7816_tlv::ber::Tlv::new(
            TERMINAL_NONCE.clone(), iso7816_tlv::ber::Value::Primitive(vec![0, 0, 0, 0])
        ).unwrap().to_vec());
        out
    }
}

#[derive(Debug)]
pub struct GetDataResponse {
    pub device_key_id: [u8; 4],
    pub device_public_key: crate::ecc::PublicKey,
    pub encrypted_data: alloc::vec::Vec<u8>,
}

impl GetDataResponse {
    pub fn parse(data: &[u8]) -> Result<Self, VasError> {
        let (resp, left) = iso7816_tlv::ber::Tlv::parse(data);
        let resp = resp.map_err(VasError::TlvError)?;
        if !resp.tag().eq(&GET_DATA_RESPONSE) {
            return Err(VasError::CommunicationError("Wrong tag for data response"));
        }
        if !left.is_empty() {
            return Err(VasError::CommunicationError("Extra data after data response"));
        }

        let cryptogram = find_tlv_tag(&resp, &DEVICE_CRYPTOGRAM)
            .map(get_tlv_primitive_value)
            .ok_or(VasError::CommunicationError("Missing device cryptogram"))?;

        if cryptogram.len() < 36 {
            return Err(VasError::CommunicationError("Device cryptogram too short"));
        }

        let mut device_public_key = [0u8; 33];
        device_public_key[0] = 0x02;
        for (i, k) in cryptogram[4..36].iter().enumerate() {
            device_public_key[i + 1] = *k;
        }
        Ok(GetDataResponse {
            device_key_id: (&cryptogram[0..4]).try_into().unwrap(),
            device_public_key: crate::ecc::PublicKey::from_compressed_point(device_public_key),
            encrypted_data: cryptogram[36..].to_vec(),
        })
    }
}