use crate::vas::VasError;

#[derive(Debug)]
pub struct ServiceValue {
    issuer_id: Issuer,
    objects: alloc::vec::Vec<Object>,
}

#[derive(Debug)]
pub enum IssuerType {
    Unspecified,
    Merchant,
    Wallet,
    Manufacturer,
}

#[derive(Debug)]
pub struct Issuer {
    issuer_type: IssuerType,
    issuer_id: u64,
}

#[derive(Debug)]
pub enum Object {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SmartTapStatus {
    Unknown = 0,
    Ok = 1,
    NdefFormatInvalid = 2,
    UnsupportedVersion = 3,
    InvalidSequenceNumber = 4,
    UnknownMerchant = 5,
    MerchantInfoMissing = 6,
    ServiceDataMissing = 7,
    ResendRequest = 8,
    DataNotAvailableYet = 9,
}

impl SmartTapStatus {
    fn from_u8(value: u8) -> Result<Self, VasError> {
        match value {
            0 => Ok(SmartTapStatus::Unknown),
            1 => Ok(SmartTapStatus::Ok),
            2 => Ok(SmartTapStatus::NdefFormatInvalid),
            3 => Ok(SmartTapStatus::UnsupportedVersion),
            4 => Ok(SmartTapStatus::InvalidSequenceNumber),
            5 => Ok(SmartTapStatus::UnknownMerchant),
            6 => Ok(SmartTapStatus::MerchantInfoMissing),
            7 => Ok(SmartTapStatus::ServiceDataMissing),
            8 => Ok(SmartTapStatus::ResendRequest),
            9 => Ok(SmartTapStatus::DataNotAvailableYet),
            _ => Err(VasError::CommunicationError("Invalid status number")),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Session {
    pub session_id: [u8; 8],
    pub sequence: u8,
    pub status: SmartTapStatus,
}

impl Session {
    fn to_record(&self) -> ndef_rs::NdefRecord {
        let mut data = vec![];
        data.extend(self.session_id);
        data.push(self.sequence);
        data.push(self.status as u8);
        ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(b"ses", data))
            .build()
            .unwrap()
    }

    fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid session record"));
        }
        if record.record_type() != b"ses" {
            return Err(VasError::CommunicationError("Invalid session record"));
        }
        let p = record.payload();
        if p.len() != 10 {
            return Err(VasError::CommunicationError("Invalid session record"));
        }
        Ok(Self {
            session_id: (&p[0..8]).try_into().unwrap(),
            sequence: p[8],
            status: SmartTapStatus::from_u8(p[9])?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CryptoParams {
    pub reader_nonce: [u8; 32],
    pub auth_flag: u8,
    pub reader_ephemeral_public_key: crate::ecc::PublicKey,
    pub key_version: u32,
    pub collector_id: u32,
    pub reader_signature: alloc::vec::Vec<u8>,
}

impl CryptoParams {
    pub fn to_record(&self) -> ndef_rs::NdefRecord {
        let mut data = vec![];
        data.extend(self.reader_nonce);
        data.push(self.auth_flag);
        data.extend(self.reader_ephemeral_public_key.public_compressed_point());
        data.extend(self.key_version.to_be_bytes());
        let mut sig = vec![0x04];
        sig.extend_from_slice(&self.reader_signature);
        let mut cld = vec![0x04];
        cld.extend(self.collector_id.to_be_bytes());
        data.extend(
            ndef_rs::NdefMessage::from(&[
                ndef_rs::NdefRecord::builder()
                    .tnf(ndef_rs::TNF::External)
                    .payload(&ndef_rs::payload::ExternalPayload::from_raw(b"sig", sig))
                    .build()
                    .unwrap(),
                ndef_rs::NdefRecord::builder()
                    .tnf(ndef_rs::TNF::External)
                    .payload(&ndef_rs::payload::ExternalPayload::from_raw(b"cld", cld))
                    .build()
                    .unwrap(),
            ])
            .to_buffer()
            .unwrap(),
        );
        ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(b"cpr", data))
            .build()
            .unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct Merchant {
    pub collector_id: u32,
    pub store_location_id: Option<u64>,
    pub terminal_id: Option<u64>,
    pub merchant_name: Option<alloc::string::String>,
    pub merchant_category_code: Option<u16>,
}

impl Merchant {
    pub fn to_record(&self) -> ndef_rs::NdefRecord {
        let mut cld_data = vec![0x04];
        cld_data.extend(self.collector_id.to_be_bytes());
        let cld = ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                b"cld", cld_data,
            ))
            .build()
            .unwrap();

        let mut merchant_records = vec![cld];

        if let Some(store_location_id) = self.store_location_id {
            let mut lid_data = vec![0x04];
            lid_data.extend(store_location_id.to_be_bytes());
            merchant_records.push(ndef_rs::NdefRecord::builder()
                .tnf(ndef_rs::TNF::External)
                .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                    b"lid", lid_data,
                ))
                .build()
                .unwrap())
        }

        if let Some(terminal_id) = self.terminal_id {
            let mut tid_data = vec![0x04];
            tid_data.extend(terminal_id.to_be_bytes());
            merchant_records.push(ndef_rs::NdefRecord::builder()
                .tnf(ndef_rs::TNF::External)
                .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                    b"tid", tid_data,
                ))
                .build()
                .unwrap())
        }

        if let Some(merchant_name) = self.merchant_name.as_deref() {
            merchant_records.push(ndef_rs::NdefRecord::builder()
                .tnf(ndef_rs::TNF::WellKnown)
                .id(b"mnr".into())
                .payload(&ndef_rs::payload::TextPayload::from_string(merchant_name))
                .build()
                .unwrap())
        }

        if let Some(mcc) = self.merchant_category_code {
            let mut mcr_data = vec![0x04];
            mcr_data.extend(mcc.to_be_bytes());
            merchant_records.push(ndef_rs::NdefRecord::builder()
                .tnf(ndef_rs::TNF::External)
                .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                    b"mcr", mcr_data,
                ))
                .build()
                .unwrap())
        }

        ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                b"mer",
                ndef_rs::NdefMessage::from(&merchant_records).to_buffer().unwrap(),
            ))
            .build()
            .unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct ServiceList {
    pub object_types: alloc::vec::Vec<u8>,
}

impl ServiceList {
    pub fn to_record(&self) -> ndef_rs::NdefRecord {
        let mut records = vec![];
        for t in &self.object_types {
            records.push(
                ndef_rs::NdefRecord::builder()
                    .tnf(ndef_rs::TNF::External)
                    .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                        b"str",
                        &[*t],
                    ))
                    .build()
                    .unwrap(),
            )
        }
        ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                b"slr",
                ndef_rs::NdefMessage::from(records).to_buffer().unwrap(),
            ))
            .build()
            .unwrap()
    }
}

pub struct NegotiateSecureChannelRequest<'a> {
    pub version: u16,
    pub session: alloc::borrow::Cow<'a, Session>,
    pub crypto_params: alloc::borrow::Cow<'a, CryptoParams>,
}

impl NegotiateSecureChannelRequest<'_> {
    pub fn to_record(&self) -> ndef_rs::NdefRecord {
        let mut data = vec![];
        data.extend(self.version.to_be_bytes());
        data.extend(
            ndef_rs::NdefMessage::from(&[self.session.to_record(), self.crypto_params.to_record()])
                .to_buffer()
                .unwrap(),
        );
        ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(b"ngr", data))
            .build()
            .unwrap()
    }
}

#[derive(Debug)]
pub struct NegotiateSecureChannelResponse<'a> {
    pub session: alloc::borrow::Cow<'a, Session>,
    pub handset_ephemeral_public_key: crate::ecc::PublicKey,
}

impl NegotiateSecureChannelResponse<'_> {
    pub fn decode(data: &[u8]) -> Result<Self, VasError> {
        let m = ndef_rs::NdefMessage::decode(data)
            .map_err(|_| VasError::CommunicationError("Invalid NDEF message"))?;
        if m.records().len() != 1 {
            return Err(VasError::CommunicationError(
                "Invalid negotiate secure channel response",
            ));
        }
        let r = &m.records()[0];
        if r.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError(
                "Invalid negotiate secure channel response",
            ));
        }
        if r.record_type() != b"nrs" {
            return Err(VasError::CommunicationError(
                "Invalid negotiate secure channel response",
            ));
        }
        let m = ndef_rs::NdefMessage::decode(r.payload())
            .map_err(|_| VasError::CommunicationError("Invalid NDEF message"))?;
        if m.records().len() != 2 {
            return Err(VasError::CommunicationError(
                "Invalid negotiate secure channel response",
            ));
        }
        let session = Session::from_record(&m.records()[0])?;
        let dpk = &m.records()[1];
        if dpk.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError(
                "Invalid device ephemeral public key",
            ));
        }
        if dpk.record_type() != b"dpk" {
            return Err(VasError::CommunicationError(
                "Invalid device ephemeral public key",
            ));
        }
        if dpk.payload().len() != 33 {
            return Err(VasError::CommunicationError(
                "Invalid device ephemeral public key",
            ));
        }
        let dpk = crate::ecc::PublicKey::from_compressed_point(dpk.payload().try_into().unwrap());
        Ok(Self {
            session: alloc::borrow::Cow::Owned(session),
            handset_ephemeral_public_key: dpk,
        })
    }
}

pub struct ServiceRequest<'a> {
    pub version: u16,
    pub session: alloc::borrow::Cow<'a, Session>,
    pub merchant: alloc::borrow::Cow<'a, Merchant>,
    pub service_list: alloc::borrow::Cow<'a, ServiceList>,
    // TODO: POS capabilities
}

impl ServiceRequest<'_> {
    pub fn to_record(&self) -> ndef_rs::NdefRecord {
        let mut data = vec![];
        data.extend(self.version.to_be_bytes());
        data.extend(
            ndef_rs::NdefMessage::from(&[
                self.session.as_ref().to_record(),
                self.merchant.as_ref().to_record(),
                self.service_list.as_ref().to_record(),
            ])
            .to_buffer()
            .unwrap(),
        );
        ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(b"srq", data))
            .build()
            .unwrap()
    }
}
