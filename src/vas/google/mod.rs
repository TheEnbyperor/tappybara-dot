mod fci;
mod data;
mod session;
mod crypto;

pub use fci::FCI;
pub use data::{ServiceValue};
use crate::vas::VasError;

static VERSION: u16 = 1;

pub struct TerminalConfig {
    pub collector_id: u32,
    pub key_version: u32,
    pub private_key: crate::ecc::PrivateKey,
    pub services: alloc::vec::Vec<u8>,
    pub store_location_id: Option<u64>,
    pub merchant_name: Option<alloc::string::String>,
    pub merchant_category_code: Option<u16>,
}

#[derive(Debug)]
pub enum SmartTapResult {
    UnknownCollector,
    UnlockRequired,
    NoPassesAvailable,
    WaitingForSelection,
    Success {
        ready_for_payment: bool,
        has_pases: bool,
        pre_signed_auth: bool,
        values: alloc::vec::Vec<ServiceValue>
    }
}

pub struct Client<'a, T: super::Target> {
    target: &'a mut T,
    fci: FCI,
    session: session::Session,
    config: &'a TerminalConfig,
}

impl<'a, T: super::Target> Client<'a, T> {
    pub async fn new(target: &'a mut T, fci: FCI, config: &'a TerminalConfig) -> Self {
        Self {
            target,
            fci,
            session: session::Session::new().await,
            config,
        }
    }

    pub async fn do_exchange(&mut self, reader_ephemeral_key: crate::ecc::PrivateKey) -> Result<SmartTapResult, VasError> {
        let mut application: &[u8] = &[0xA0, 0x00, 0x00, 0x04, 0x76, 0xD0, 0x00, 0x01, 0x11];
        let mut device_nonce: &[u8] = &[];
        let mut skip_second_select: bool = false;

        if self.fci.directory.is_empty() {
            if self.fci.version != VERSION {
                return Err(VasError::CommunicationError("Unsupported Smart Tap version"));
            }
        } else {
            let mut applications = self.fci.directory.iter()
                .filter(|a| a.min_version.map(|v| v <= VERSION).unwrap_or(false))
                .filter(|a| a.max_version.map(|v| v >= VERSION).unwrap_or(false))
                .collect::<alloc::vec::Vec<_>>();
            if applications.is_empty() {
                return Err(VasError::CommunicationError("No compatible Smart Tap applications found"));
            }
            applications.sort_by_key(|a| a.priority);
            let application_entry = *applications.first().unwrap();
            application = application_entry.aid.as_slice();
            if let Some(caps) = &application_entry.capabilities {
                if !caps.vas_support() {
                    return Err(VasError::CommunicationError("VAS not supported by application"));
                }
                if caps.skip_second_select() {
                    device_nonce = application_entry.device_nonce.as_ref().map_or(&[], |v| v);
                    skip_second_select = true;
                }
            }
        }

        if !skip_second_select {
            unimplemented!();
        }

        if device_nonce.len() != 32 {
            return Err(VasError::CommunicationError("Invalid device nonce length"));
        }
        let device_nonce: [u8; 32] = device_nonce.try_into().unwrap();

        let mut crypto_session = crypto::Session::new(device_nonce, reader_ephemeral_key, &self.config).await;

        let ngr = ndef_rs::NdefMessage::from(&[
            data::NegotiateSecureChannelRequest {
                version: 1,
                session: alloc::borrow::Cow::Owned(self.session.next_request()),
                crypto_params: alloc::borrow::Cow::Owned(crypto_session.generate_crypto_params().await)
            }.to_record()
        ]).to_buffer().unwrap();
        let res = loop {
            let res = self.target.transmit(super::apdu::RequestAPDU {
                instruction_class: 0x90,
                instruction: 0x53,
                p1: 0x00,
                p2: 0x00,
                data: alloc::borrow::Cow::Borrowed(&ngr),
                expected_response_length: 256
            }).await?;

            match (res.sw1, res.sw2) {
                (0x90, _) => break res.data,
                (0x92, _) => {
                    warn!("Target reported a transient failure, retrying");
                    continue;
                },
                (0x93, 0x00) => return Ok(SmartTapResult::UnlockRequired),
                (0x93, 0x01) => return Ok(SmartTapResult::NoPassesAvailable),
                (0x93, 0x02) => return Ok(SmartTapResult::WaitingForSelection),
                (0x94, _) => return Err(VasError::CommunicationError("Target reported invalid terminal data")),
                (0x95, 0x00) => return Err(VasError::CommunicationError("Target rejected the authentication")),
                (0x95, 0x02) => return Err(VasError::CommunicationError("Target reported an unsupported version")),
                _ => return Err(VasError::CommunicationError("Unknown error received")),
            }
        };

        let ngr_resp = data::NegotiateSecureChannelResponse::decode(&res)?;
        debug!("Received negotiate response: {:?}", ngr_resp);
        self.session.validate_response(&ngr_resp.session)?;

        let srq = ndef_rs::NdefMessage::from(&[
            data::ServiceRequest {
                version: 1,
                session: alloc::borrow::Cow::Owned(self.session.next_request()),
                merchant: alloc::borrow::Cow::Owned(data::Merchant {
                    collector_id: self.config.collector_id,
                    store_location_id: self.config.store_location_id,
                    terminal_id: None,
                    merchant_name: self.config.merchant_name.clone(),
                    merchant_category_code: self.config.merchant_category_code,
                }),
                service_list: alloc::borrow::Cow::Owned(data::ServiceList {
                    object_types: self.config.services.clone(),
                })
            }.to_record()
        ]).to_buffer().unwrap();
        let (res, more_data) = loop {
            let res = self.target.transmit(super::apdu::RequestAPDU {
                instruction_class: 0x90,
                instruction: 0x50,
                p1: 0x00,
                p2: 0x00,
                data: alloc::borrow::Cow::Borrowed(&srq),
                expected_response_length: 256
            }).await?;

            match (res.sw1, res.sw2) {
                (0x90, _) => break (res.data, false),
                (0x91, 0x00) => break (res.data, true),
                (0x91, _) => break (res.data, false),
                (0x92, _) => {
                    warn!("Target reported a transient failure, retrying");
                    continue;
                },
                (0x93, 0x00) => return Ok(SmartTapResult::UnlockRequired),
                (0x93, 0x01) => return Ok(SmartTapResult::NoPassesAvailable),
                (0x93, 0x02) => return Ok(SmartTapResult::WaitingForSelection),
                (0x94, _) => return Err(VasError::CommunicationError("Target reported invalid terminal data")),
                (0x95, 0x00) => return Err(VasError::CommunicationError("Target rejected the authentication")),
                (0x95, 0x02) => return Err(VasError::CommunicationError("Target reported an unsupported version")),
                _ => return Err(VasError::CommunicationError("Unknown error received")),
            }
        };

        debug!("Received data response: {:?}", res);

        Ok(SmartTapResult::NoPassesAvailable)
    }
}