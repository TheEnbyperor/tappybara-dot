mod fci;
mod commands;

pub use fci::FCI;
use crate::vas::VasError;

#[derive(Debug)]
pub struct TerminalConfig {
    pub passes: alloc::vec::Vec<PassConfig>
}

#[derive(Debug)]
pub struct PassConfig {
    pub pass_id: alloc::string::String,
    pub pass_id_hash: [u8; 32],
    pub keys: alloc::sync::Arc<alloc::vec::Vec<Key>>,
}

#[derive(Debug)]
pub struct Key {
    pub key_id: [u8; 4],
    pub key: crate::ecc::PrivateKey,
}

#[derive(Debug)]
pub struct ResultData {
    pub results: alloc::vec::Vec<VASResult>,
}

#[derive(Debug)]
pub struct VASResult {
    pub pass_id: alloc::string::String,
    pub result: VASResultType
}

#[derive(Debug)]
pub enum VASResultType {
    WaitingForActivation,
    WaitingForInteraction,
    NoPassesAvailable,
    Success(SuccessResult),
}

#[derive(Debug)]
pub struct SuccessResult {
    pub device_key_id: [u8; 4],
    pub device_public_key: crate::ecc::PublicKey,
    pub encrypted_data: alloc::vec::Vec<u8>,
    pass_id_hash: [u8; 32],
    keys: alloc::sync::Arc<alloc::vec::Vec<Key>>,
}

#[derive(Debug)]
pub struct DeviceData {
    pub timestamp: u64,
    pub payload: alloc::vec::Vec<u8>,
}

pub struct Client<'a, T: super::Target> {
    target: &'a mut T,
    fci: FCI,
    config: alloc::sync::Arc<TerminalConfig>,
}

impl<'a, T: super::Target>  Client<'a, T> {
    pub fn new(target: &'a mut T, fci: FCI, config: alloc::sync::Arc<TerminalConfig>) -> Self {
        Self {
            target,
            fci,
            config,
        }
    }

    pub async fn do_exchange(&mut self) -> Result<ResultData, VasError> {
        let mut out = vec![];

        for (i, pass) in self.config.passes.iter().enumerate() {
            let get_data_command = commands::GetData {
                version: (1, 0),
                pass_hash: pass.pass_id_hash,
                capabilities: commands::TerminalCapabilities::VasOnly,
                final_command: i + 1 == self.config.passes.len(),
            };
            let res = self.target.transmit(super::apdu::RequestAPDU {
                instruction_class: 0x80,
                instruction: 0xCA,
                p1: 0x01,
                p2: 0x01,
                data: get_data_command.encode().into(),
                expected_response_length: 256
            }).await?;
            if res.sw1 == 0x62 && res.sw2 == 0x87 {
                out.push(VASResult {
                    pass_id: pass.pass_id.clone(),
                    result: VASResultType::WaitingForActivation
                });
            } else if res.sw1 == 0x69 && res.sw2 == 0x84 {
                out.push(VASResult {
                    pass_id: pass.pass_id.clone(),
                    result: VASResultType::WaitingForInteraction
                });
            } else if res.sw1 == 0x6A && res.sw2 == 0x83 {
                out.push(VASResult {
                    pass_id: pass.pass_id.clone(),
                    result: VASResultType::NoPassesAvailable
                });
            } else if res.sw1 == 0x90 && res.sw2 == 0x00 {
                let res = commands::GetDataResponse::parse(&res.data)?;
                out.push(VASResult {
                    pass_id: pass.pass_id.clone(),
                    result: VASResultType::Success(SuccessResult {
                        device_key_id: res.device_key_id,
                        device_public_key: res.device_public_key,
                        encrypted_data: res.encrypted_data,
                        pass_id_hash: pass.pass_id_hash,
                        keys: pass.keys.clone(),
                    })
                });
            } else {
                return Err(VasError::CommunicationError("Unexpected response code"));
            }
        }

        Ok(ResultData {
            results: out
        })
    }
}

impl SuccessResult {
    fn create_shared_data(&self, version: usize) -> alloc::vec::Vec<u8> {
        match version {
            2 => b"ApplePay encrypted VAS data".to_vec(),
            1 => {
                let mut out = vec![];
                out.extend_from_slice(b"\x0did-aes256-GCMApplePay encrypted VAS data");
                out.extend_from_slice(&self.pass_id_hash);
                out
            },
            _ => unimplemented!()
        }
    }

    fn create_additional_authentication_data(&self, version: usize) -> alloc::vec::Vec<u8> {
        match version {
            2 => self.pass_id_hash.to_vec(),
            1 => b"".to_vec(),
            _ => unimplemented!()
        }
    }

    pub async fn try_decrypt(&self) -> Option<DeviceData> {
        let possible_keys = self.keys.iter()
            .filter(|k| k.key_id == self.device_key_id)
            .collect::<alloc::vec::Vec<_>>();
        if possible_keys.is_empty() {
            return None;
        }

        for possible_key in possible_keys {
            let shared_secret = possible_key.key.shared_secret(&self.device_public_key);
            for version in [2, 1] {
                let derived_key: [u8; 32] = crate::crypto::x963_kdf_sha256(
                    &shared_secret,
                    &self.create_shared_data(version),
                    32
                ).await.try_into().unwrap();
                let mut data = self.encrypted_data.clone();
                if crate::crypto::aes_256_gcm_decrypt(
                    &mut data, derived_key, &[0u8; 16],
                    &self.create_additional_authentication_data(version)
                ).await {
                    let data = &data[..data.len() - 16];
                    if data.len() >= 4 {
                        let timestamp = (u32::from_be_bytes(data[0..4].try_into().unwrap()) as u64) + 978307200; // Change from Jan 1st 2001 epoch to Jan 1st 1970 epoch
                        return Some(DeviceData {
                            timestamp,
                            payload: data[4..].to_vec(),
                        })
                    }
                }
            }
        }

        None
    }
}