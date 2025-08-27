use super::super::{VasError, get_tlv_primitive_value, find_tlv_tag, find_tlv_tag_all};

lazy_static::lazy_static! {
    static ref VERSION: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xC0).unwrap();
    static ref TRANSACTION_DETAILS: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xC1).unwrap();
    static ref DEFAULT_DEVICE_NONCE: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xC2).unwrap();
    static ref DEFAULT_DEVICE_PUBLIC_KEY: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xC3).unwrap();
    static ref FCI_PROPRIATERY: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xA5).unwrap();
    static ref PPSE_DATA: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xBF0C).unwrap();
    static ref DIRECTORY_ENTRY: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x61).unwrap();
    static ref AID: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x4F).unwrap();
    static ref PRIORITY: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x87).unwrap();
    static ref DISCRETIONARY: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x73).unwrap();
    static ref MIN_VERSION: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xDF6D).unwrap();
    static ref MAX_VERSION: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xDF4D).unwrap();
    static ref CAPABILITIES: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xDF62).unwrap();
    static ref DEVICE_NONCE: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xDF6E).unwrap();
    static ref DEVICE_PUBLIC_KEY: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0xDF6B).unwrap();
}

#[derive(Debug)]
pub struct FCI {
    pub version: u16,
    pub transaction_mode: TransactionMode,
    pub encryption_type: EncryptionType,
    pub authentication_type: AuthenticationType,
    pub default_device_nonce: Option<[u8; 32]>,
    pub default_device_ephemeral_key: Option<crate::ecc::PublicKey>,
    pub directory: alloc::vec::Vec<ApplicationDirectoryEntry>,
}

#[derive(Debug)]
pub struct ApplicationDirectoryEntry {
    pub aid: alloc::vec::Vec<u8>,
    pub priority: usize,
    pub device_nonce: Option<[u8; 32]>,
    pub device_ephemeral_key: Option<crate::ecc::PublicKey>,
    pub min_version: Option<u16>,
    pub max_version: Option<u16>,
    pub capabilities: Option<ApplicationCapabilities>,
}

#[derive(Debug)]
pub enum EncryptionType {
    P256,
}

#[derive(Debug)]
pub enum AuthenticationType {
    GenericKeyAuthentication
}

pub struct TransactionMode(u8);

pub struct ApplicationCapabilities(u8);

impl TransactionMode {
    pub fn payment_enabled(&self) -> bool {
        self.0 & 0x80 != 0
    }

    pub fn payment_requested(&self) -> bool {
        self.0 & 0x40 != 0
    }

    pub fn pass_enabled(&self) -> bool {
        self.0 & 0x08 != 0
    }

    pub fn pass_requested(&self) -> bool {
        self.0 & 0x04 != 0
    }
}

impl ApplicationCapabilities {
    pub fn vas_support(&self) -> bool {
        self.0 & 0x02 != 0
    }

    pub fn skip_second_select(&self) -> bool {
        self.0 & 0x01 != 0
    }
}

impl core::fmt::Debug for TransactionMode {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("TransactionMode")
            .field("payment_enabled", &self.payment_enabled())
            .field("payment_requested", &self.payment_requested())
            .field("pass_enabled", &self.pass_enabled())
            .field("pass_requested", &self.pass_requested())
            .finish()
    }
}

impl core::fmt::Debug for ApplicationCapabilities {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("ApplicationCapabilities")
            .field("vas_support", &self.vas_support())
            .field("skip_second_select", &self.skip_second_select())
            .finish()
    }
}


impl FCI {
    pub fn parse(fci: iso7816_tlv::ber::Tlv) -> Result<Self, VasError> {
        let version = find_tlv_tag(&fci, &VERSION)
            .map(get_tlv_primitive_value)
            .ok_or(VasError::CommunicationError("Missing version tag"))?;
        let transaction_details = find_tlv_tag(&fci, &TRANSACTION_DETAILS)
            .map(get_tlv_primitive_value)
            .ok_or(VasError::CommunicationError(
                "Missing transaction details tag",
            ))?;

        if version.len() != 2 {
            return Err(VasError::CommunicationError("Version tag wrong length"));
        }
        if transaction_details.len() != 8 {
            return Err(VasError::CommunicationError(
                "Transaction details tag wrong length",
            ));
        }

        let encryption_type = match transaction_details[6] >> 4 {
            0x08 => EncryptionType::P256,
            _ => return Err(VasError::CommunicationError("Unknown encryption type")),
        };
        let authentication_type = match transaction_details[7] >> 4 {
            0x08 => AuthenticationType::GenericKeyAuthentication,
            _ => return Err(VasError::CommunicationError("Unknown authentication type")),
        };

        let default_device_nonce = match find_tlv_tag(&fci, &DEFAULT_DEVICE_NONCE).map(get_tlv_primitive_value) {
            Some(value) => {
                if value.len() != 32 {
                    return Err(VasError::CommunicationError(
                        "Default device nonce wrong length",
                    ));
                }
                Some(<[u8; 32]>::try_from(value.as_slice()).unwrap())
            }
            None => None,
        };
        let default_device_ephemeral_key = match find_tlv_tag(&fci, &DEFAULT_DEVICE_PUBLIC_KEY)
            .map(get_tlv_primitive_value)
        {
            Some(value) => {
                if value.len() != 33 {
                    return Err(VasError::CommunicationError(
                        "Default device ephemeral public wrong length",
                    ));
                }
                Some(crate::ecc::PublicKey::from_compressed_point(value.as_slice().try_into().unwrap()))
            }
            None => None,
        };

        let mut directory = vec![];

        if let Some(fci_proprietary) = find_tlv_tag(&fci, &FCI_PROPRIATERY) {
            if let Some(ppse_data) = find_tlv_tag(&fci_proprietary, &PPSE_DATA) {
                for dir in find_tlv_tag_all(&ppse_data, &DIRECTORY_ENTRY) {
                    let aid = find_tlv_tag(&dir, &AID)
                        .map(get_tlv_primitive_value)
                        .ok_or(VasError::CommunicationError("Missing aid tag"))?;
                    let priority = find_tlv_tag(&dir, &PRIORITY)
                        .map(get_tlv_primitive_value)
                        .ok_or(VasError::CommunicationError("Missing priority tag"))?;
                    let discretionary = find_tlv_tag(&dir, &DISCRETIONARY);

                    if priority.len() != 1 {
                        return Err(VasError::CommunicationError("Invalid priority length"))
                    }

                    let device_nonce = discretionary
                        .and_then(|d| find_tlv_tag(d, &DEVICE_NONCE))
                        .map(get_tlv_primitive_value)
                        .map(|v| {
                            if v.len() != 32 {
                                return Err(VasError::CommunicationError("Invalid devicenonce length"))
                            }
                            Ok(<[u8; 32]>::try_from(v.as_slice()).unwrap())
                        })
                        .transpose()?;
                    let device_ephemeral_key = discretionary
                        .and_then(|d| find_tlv_tag(d, &DEVICE_PUBLIC_KEY))
                        .map(get_tlv_primitive_value)
                        .map(|v| {
                            if v.len() != 33 {
                                return Err(VasError::CommunicationError("Invalid device ephemeral public key length"))
                            }
                            let k = crate::ecc::PublicKey::from_compressed_point(v.as_slice().try_into().unwrap());
                            Ok(k)
                        })
                        .transpose()?;
                    let min_version = discretionary
                        .and_then(|d| find_tlv_tag(d, &MIN_VERSION))
                        .map(get_tlv_primitive_value)
                        .map(|v| {
                            if v.len() != 2 {
                                return Err(VasError::CommunicationError("Invalid minimum version length"))
                            }
                            Ok(u16::from_be_bytes(v.as_slice().try_into().unwrap()))
                        })
                        .transpose()?;
                    let max_version = discretionary
                        .and_then(|d| find_tlv_tag(d, &MAX_VERSION))
                        .map(get_tlv_primitive_value)
                        .map(|v| {
                            if v.len() != 2 {
                                return Err(VasError::CommunicationError("Invalid maximum version length"))
                            }
                            Ok(u16::from_be_bytes(v.as_slice().try_into().unwrap()))
                        })
                        .transpose()?;
                    let capabilities = discretionary
                        .and_then(|d| find_tlv_tag(d, &CAPABILITIES))
                        .map(get_tlv_primitive_value)
                        .map(|v| {
                            if v.len() != 1 {
                                return Err(VasError::CommunicationError("Invalid capabilities length"))
                            }
                            Ok(ApplicationCapabilities(v[0]))
                        })
                        .transpose()?;

                    directory.push(ApplicationDirectoryEntry {
                        aid: aid.to_vec(),
                        priority: priority[0] as usize,
                        device_nonce: device_nonce.or(default_device_nonce),
                        device_ephemeral_key: device_ephemeral_key.or(default_device_ephemeral_key),
                        min_version,
                        max_version,
                        capabilities,
                    });
                }
            }
        }

        Ok(Self {
            version: u16::from_be_bytes(version.as_slice().try_into().unwrap()),
            transaction_mode: TransactionMode(transaction_details[0]),
            encryption_type,
            authentication_type,
            default_device_nonce,
            default_device_ephemeral_key,
            directory,
        })
    }
}
