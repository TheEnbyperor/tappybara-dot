use super::super::{VasError, get_tlv_primitive_value, find_tlv_tag};

lazy_static::lazy_static! {
    static ref VERSION: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F21).unwrap();
    static ref CAPABILITIES: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F23).unwrap();
    static ref NONCE: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x9F24).unwrap();
}

#[derive(Debug)]
pub struct FCI {
    version: (u8, u8),
    nonce: alloc::vec::Vec<u8>,
    capabilities: DeviceCapabilities
}

impl FCI {
    pub fn parse(fci: iso7816_tlv::ber::Tlv) -> Result<Self, VasError> {
        let version = find_tlv_tag(&fci, &VERSION)
            .map(get_tlv_primitive_value)
            .ok_or(VasError::CommunicationError("Missing version tag"))?;
        let caps = find_tlv_tag(&fci, &CAPABILITIES)
            .map(get_tlv_primitive_value)
            .ok_or(VasError::CommunicationError("Missing capabilities tag"))?;
        let nonce = find_tlv_tag(&fci, &NONCE)
            .map(get_tlv_primitive_value)
            .ok_or(VasError::CommunicationError("Missing nonce tag"))?;

        if version.len() != 2 {
            return Err(VasError::CommunicationError("Version tag wrong length"));
        }

        Ok(Self {
            version: (version[0], version[1]),
            nonce: nonce.to_vec(),
            capabilities: DeviceCapabilities {
                caps: caps.to_vec()
            }
        })
    }
}

pub struct DeviceCapabilities {
    caps: alloc::vec::Vec<u8>,
}

impl DeviceCapabilities {
    pub fn vas_enabled(&self) -> bool {
        self.caps[3] & 0b0001000 != 0
    }

    pub fn vas_supported(&self) -> bool {
        self.caps[3] & 0b0000100 != 0
    }
}

impl core::fmt::Debug for DeviceCapabilities {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceCapabilities")
            .field("vas_enabled", &self.vas_enabled())
            .field("vas_supported", &self.vas_supported())
            .finish()
    }
}