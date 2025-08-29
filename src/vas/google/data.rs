use alloc::string::ToString;
use crate::vas::VasError;

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

#[derive(Debug, Clone)]
pub struct POSCapabilities {
    pub system: u8,
    pub ui: u8,
    pub checkout: u8,
    pub cvm: u8,
    pub tap: u8,
}

impl POSCapabilities {
    pub fn to_record(&self) -> ndef_rs::NdefRecord {
        let data = [self.system, self.ui, self.checkout, self.cvm, self.tap];
        ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::External)
            .payload(&ndef_rs::payload::ExternalPayload::from_raw(
                b"pcr",
                data,
            ))
            .build()
            .unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct RecordBundle<'a> {
    pub status: u8,
    pub data: alloc::borrow::Cow<'a, [u8]>,
}

impl RecordBundle<'_> {
    pub fn is_encrypted(&self) -> bool {
        self.status & 0x01 != 0
    }

    pub fn is_compressed(&self) -> bool {
        self.status & 0x02 != 0
    }

    fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid record bundle"));
        }
        if record.record_type() != b"reb" {
            return Err(VasError::CommunicationError("Invalid record bundle"));
        }
        let p = record.payload();
        if p.len() < 2 {
            return Err(VasError::CommunicationError("Invalid record bundle"));
        }
        Ok(Self {
            status: p[0],
            data: alloc::borrow::Cow::Owned((&p[1..]).to_vec()),
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub enum IssuerType {
    Unspecified,
    Merchant,
    Wallet,
    Manufacturer,
}

#[derive(Debug, Copy, Clone)]
pub struct Issuer {
    pub issuer_type: IssuerType,
    pub issuer_id: u64,
}

impl Issuer {
    fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid issuer ID"));
        }
        if record.record_type() != b"i" {
            return Err(VasError::CommunicationError("Invalid issuer ID"));
        }
        let p = record.payload();
        if p.len() < 3 {
            return Err(VasError::CommunicationError("Invalid issuer ID"));
        }
        if p[0] != 0x04 {
            return Err(VasError::CommunicationError("Invalid issuer ID"));
        }
        let issuer_type = match p[1] {
            0x00 => IssuerType::Unspecified,
            0x01 => IssuerType::Merchant,
            0x02 => IssuerType::Wallet,
            0x03 => IssuerType::Manufacturer,
            _ => return Err(VasError::CommunicationError("Invalid issuer type")),
        };
        let mut issuer_id_b = [0u8; 8];
        let offset = 8 - (p.len() - 2);
        for (i, v) in (&p[2..]).iter().enumerate() {
            issuer_id_b[i + offset] = *v;
        }
        let issuer_id = u64::from_be_bytes(issuer_id_b);
        Ok(Self {
            issuer_type,
            issuer_id,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Object<'a> {
    Customer(CustomerRecord<'a>),
    Loyalty(LoyaltyRecord<'a>),
    Offer(ObjectRecord<'a>),
    GiftCard(GiftCardRecord<'a>),
    PLC(PrivateLabelCardRecord<'a>),
    EventTicket(ObjectRecord<'a>),
    Flight(ObjectRecord<'a>),
    Transit(ObjectRecord<'a>),
    Generic(ObjectRecord<'a>),
    GenericPrivate(ObjectRecord<'a>),
}

#[derive(Debug, Clone)]
pub struct CustomerRecord<'a> {
    pub customer_id: alloc::borrow::Cow<'a, [u8]>,
    pub preferred_language_code: Option<alloc::borrow::Cow<'a, str>>,
    pub unique_tap_id: Option<alloc::borrow::Cow<'a, [u8]>>,
    pub unique_device_id: Option<alloc::borrow::Cow<'a, [u8]>>,
}

#[derive(Debug, Clone)]
pub struct ObjectRecord<'a> {
    pub object_id: alloc::borrow::Cow<'a, [u8]>,
    pub redemption_data: alloc::borrow::Cow<'a, [u8]>,
}

#[derive(Debug, Clone)]
pub struct LoyaltyRecord<'a> {
    pub object_id: alloc::borrow::Cow<'a, [u8]>,
    pub redemption_data: alloc::borrow::Cow<'a, [u8]>,
    pub track1: Option<alloc::borrow::Cow<'a, [u8]>>,
    pub track2: Option<alloc::borrow::Cow<'a, [u8]>>,
}

#[derive(Debug, Clone)]
pub struct GiftCardRecord<'a> {
    pub object_id: alloc::borrow::Cow<'a, [u8]>,
    pub redemption_data: alloc::borrow::Cow<'a, [u8]>,
    pub pin: Option<alloc::borrow::Cow<'a, [u8]>>,
    pub track1: Option<alloc::borrow::Cow<'a, [u8]>>,
    pub track2: Option<alloc::borrow::Cow<'a, [u8]>>,
}

#[derive(Debug, Clone)]
pub struct PrivateLabelCardRecord<'a> {
    pub object_id: alloc::borrow::Cow<'a, [u8]>,
    pub pan: alloc::borrow::Cow<'a, [u8]>,
    pub expiration: Option<alloc::borrow::Cow<'a, [u8]>>,
    pub cvc1: Option<alloc::borrow::Cow<'a, [u8]>>,
    pub track1: Option<alloc::borrow::Cow<'a, [u8]>>,
    pub track2: Option<alloc::borrow::Cow<'a, [u8]>>,
}


impl CustomerRecord<'_> {
    pub fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid customer record"));
        }
        if record.record_type() != b"cus" {
            return Err(VasError::CommunicationError("Invalid customer record"));
        }
        let m = ndef_rs::NdefMessage::decode(record.payload())
            .map_err(|_| VasError::CommunicationError("Invalid customer record"))?;
        if m.records().len() < 2 {
            return Err(VasError::CommunicationError("Invalid customer record"));
        }
        let cid_r = &m.records()[0];
        if cid_r.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid customer ID"));
        }
        if cid_r.record_type() != b"cid" {
            return Err(VasError::CommunicationError("Invalid customer ID"));
        }
        if cid_r.payload()[0] != 0x04 {
            return Err(VasError::CommunicationError("Invalid customer ID"));
        }
        let cid = (&cid_r.payload()[1..]).to_vec();
        let mut out = CustomerRecord {
            customer_id: alloc::borrow::Cow::Owned(cid),
            preferred_language_code: None,
            unique_tap_id: None,
            unique_device_id: None,
        };
        let mut i = 1;
        if i < m.records().len() && m.records()[i].id() == Some(b"cpl") {
            if let Ok(r) = ndef_rs::payload::TextPayload::try_from(&m.records()[i]) {
                out.preferred_language_code = Some(alloc::borrow::Cow::Owned(r.text().to_string()));
                i += 1;
            }
        }
        if i < m.records().len() && m.records()[i].tnf() == ndef_rs::TNF::External && m.records()[i].record_type() == b"cut" {
            let p = m.records()[i].payload();
            if p[0] != 0x04 {
                return Err(VasError::CommunicationError("Invalid unique tap ID"));
            }
            out.unique_tap_id = Some(alloc::borrow::Cow::Owned(p[1..].to_vec()));
            i += 1;
        }
        if i < m.records().len() && m.records()[i].tnf() == ndef_rs::TNF::External && m.records()[i].record_type() == b"cud" {
            out.unique_device_id = Some(alloc::borrow::Cow::Owned(m.records()[i].payload().to_vec()));
        }
        Ok(out)
    }
}

fn parse_object_id(record: &ndef_rs::NdefRecord) -> Result<alloc::vec::Vec<u8>, VasError> {
    if record.tnf() != ndef_rs::TNF::External {
        return Err(VasError::CommunicationError("Invalid object ID"));
    }
    if record.record_type() != b"oid" {
        return Err(VasError::CommunicationError("Invalid object ID"));
    }
    if record.payload().len() < 2 {
        return Err(VasError::CommunicationError("Invalid object ID"));
    }
    if record.payload()[0] != 0x04 {
        return Err(VasError::CommunicationError("Invalid object ID"));
    }
    Ok((&record.payload()[1..]).to_vec())
}

fn parse_object_data(record: &ndef_rs::NdefRecord, id: &[u8]) -> Result<alloc::vec::Vec<u8>, VasError> {
    match (record.tnf(), record.record_type(), record.id()) {
        (ndef_rs::TNF::External, t, None) if t == id => {
            if record.payload().len() < 2 {
                return Err(VasError::CommunicationError("Invalid object data"));
            }
            if record.payload()[0] != 0x04 {
                return Err(VasError::CommunicationError("Invalid object data"));
            }
            Ok((&record.payload()[1..]).to_vec())
        },
        (ndef_rs::TNF::WellKnown, _, Some(n)) if n == id => {
            if let Ok(r) = ndef_rs::payload::TextPayload::try_from(record) {
                Ok(r.text().as_bytes().to_vec())
            } else {
                Err(VasError::CommunicationError("Invalid object data"))
            }
        },
        _ => Err(VasError::CommunicationError("Invalid object data")),
    }
}

impl ObjectRecord<'_> {
    pub fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid object record"));
        }
        let m = ndef_rs::NdefMessage::decode(record.payload())
            .map_err(|_| VasError::CommunicationError("Invalid object record"))?;
        if m.records().len() != 2 {
            return Err(VasError::CommunicationError("Invalid object record"));
        }
        let object_id = parse_object_id(&m.records()[0])?;
        let redemption_data = parse_object_data(&m.records()[1], b"n")?;
        Ok(Self {
            object_id: alloc::borrow::Cow::Owned(object_id),
            redemption_data: alloc::borrow::Cow::Owned(redemption_data),
        })
    }
}

impl LoyaltyRecord<'_> {
    pub fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid loyalty record"));
        }
        if record.record_type() != b"ly" {
            return Err(VasError::CommunicationError("Invalid loyalty record"));
        }
        let m = ndef_rs::NdefMessage::decode(record.payload())
            .map_err(|_| VasError::CommunicationError("Invalid loyalty record"))?;
        if m.records().len() != 2 {
            return Err(VasError::CommunicationError("Invalid loyalty record"));
        }
        let object_id = parse_object_id(&m.records()[0])?;
        let redemption_data = parse_object_data(&m.records()[1], b"n")?;
        let mut i = 2;
        let track1 = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"tr1")?)
        } else {
            None
        };
        i += 1;
        let track2 = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"tr2")?)
        } else {
            None
        };
        Ok(Self {
            object_id: alloc::borrow::Cow::Owned(object_id),
            redemption_data: alloc::borrow::Cow::Owned(redemption_data),
            track1: track1.map(alloc::borrow::Cow::Owned),
            track2: track2.map(alloc::borrow::Cow::Owned),
        })
    }
}

impl GiftCardRecord<'_> {
    pub fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid gift card record"));
        }
        if record.record_type() != b"gc" {
            return Err(VasError::CommunicationError("Invalid gift card record"));
        }
        let m = ndef_rs::NdefMessage::decode(record.payload())
            .map_err(|_| VasError::CommunicationError("Invalid gift card record"))?;
        if m.records().len() != 2 {
            return Err(VasError::CommunicationError("Invalid gift card record"));
        }
        let object_id = parse_object_id(&m.records()[0])?;
        let redemption_data = parse_object_data(&m.records()[1], b"n")?;
        let mut i = 2;
        let pin = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"p")?)
        } else {
            None
        };
        i += 1;
        let track1 = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"tr1")?)
        } else {
            None
        };
        i += 1;
        let track2 = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"tr2")?)
        } else {
            None
        };
        Ok(Self {
            object_id: alloc::borrow::Cow::Owned(object_id),
            redemption_data: alloc::borrow::Cow::Owned(redemption_data),
            pin: pin.map(alloc::borrow::Cow::Owned),
            track1: track1.map(alloc::borrow::Cow::Owned),
            track2: track2.map(alloc::borrow::Cow::Owned),
        })
    }
}

impl PrivateLabelCardRecord<'_> {
    pub fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid private label card record"));
        }
        if record.record_type() != b"gc" {
            return Err(VasError::CommunicationError("Invalid private label card record"));
        }
        let m = ndef_rs::NdefMessage::decode(record.payload())
            .map_err(|_| VasError::CommunicationError("Invalid private label card record"))?;
        if m.records().len() != 2 {
            return Err(VasError::CommunicationError("Invalid private label card record"));
        }
        let object_id = parse_object_id(&m.records()[0])?;
        let pan = parse_object_data(&m.records()[1], b"n")?;
        let mut i = 2;
        let expiry = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"ex")?)
        } else {
            None
        };
        i += 1;
        let cvc = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"c1")?)
        } else {
            None
        };
        i += 1;
        let track1 = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"tr1")?)
        } else {
            None
        };
        i += 1;
        let track2 = if i < m.records().len() {
            Some(parse_object_data(&m.records()[i], b"tr2")?)
        } else {
            None
        };
        Ok(Self {
            object_id: alloc::borrow::Cow::Owned(object_id),
            pan: alloc::borrow::Cow::Owned(pan),
            expiration: expiry.map(alloc::borrow::Cow::Owned),
            cvc1: cvc.map(alloc::borrow::Cow::Owned),
            track1: track1.map(alloc::borrow::Cow::Owned),
            track2: track2.map(alloc::borrow::Cow::Owned),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServiceRecord<'a> {
    pub issuer: Issuer,
    pub objects: alloc::borrow::Cow<'a, [Object<'a>]>
}

impl ServiceRecord<'_> {
    fn from_record(record: &ndef_rs::NdefRecord) -> Result<Self, VasError> {
        if record.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError("Invalid service record"));
        }
        if record.record_type() != b"asv" {
            return Err(VasError::CommunicationError("Invalid service record"));
        }
        let m = ndef_rs::NdefMessage::decode(record.payload())
            .map_err(|_| VasError::CommunicationError("Invalid service record"))?;
        if m.records().len() < 2 {
            return Err(VasError::CommunicationError("Invalid service record"));
        }
        let issuer = Issuer::from_record(&m.records()[0])?;
        let mut objects = vec![];
        for r in &m.records()[1..] {
            if r.tnf() != ndef_rs::TNF::External {
                return Err(VasError::CommunicationError("Invalid service object"));
            }
            let o = match r.record_type() {
                b"cus" => Object::Customer(CustomerRecord::from_record(r)?),
                b"ly" => Object::Loyalty(LoyaltyRecord::from_record(r)?),
                b"of" => Object::Offer(ObjectRecord::from_record(r)?),
                b"gc" => Object::GiftCard(GiftCardRecord::from_record(r)?),
                b"pl" => Object::PLC(PrivateLabelCardRecord::from_record(r)?),
                b"et" => Object::EventTicket(ObjectRecord::from_record(r)?),
                b"fl" => Object::Flight(ObjectRecord::from_record(r)?),
                b"tr" => Object::Transit(ObjectRecord::from_record(r)?),
                b"gr" => Object::Generic(ObjectRecord::from_record(r)?),
                b"grp" => Object::GenericPrivate(ObjectRecord::from_record(r)?),
                _ => return Err(VasError::CommunicationError("Unknown service object type")),
            };
            objects.push(o);
        }
        Ok(Self {
            issuer,
            objects: alloc::borrow::Cow::Owned(objects),
        })
    }
}

#[derive(Debug, Clone)]
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
    pub pos_capabilities: Option<alloc::borrow::Cow<'a, POSCapabilities>>,
}

impl ServiceRequest<'_> {
    pub fn to_record(&self) -> ndef_rs::NdefRecord {
        let mut data = vec![];
        data.extend(self.version.to_be_bytes());
        let mut records = vec![
            self.session.as_ref().to_record(),
            self.merchant.as_ref().to_record(),
            self.service_list.as_ref().to_record(),
        ];
        if let Some(caps) = &self.pos_capabilities {
            records.push(caps.as_ref().to_record());
        }
        data.extend(
            ndef_rs::NdefMessage::from(&records)
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

#[derive(Debug)]
pub struct ServiceResponse<'a> {
    pub session: alloc::borrow::Cow<'a, Session>,
    pub record_bundle: RecordBundle<'a>
}

impl ServiceResponse<'_> {
    pub fn decode(data: &[u8]) -> Result<Self, VasError> {
        let m = ndef_rs::NdefMessage::decode(data)
            .map_err(|_| VasError::CommunicationError("Invalid NDEF message"))?;
        if m.records().len() != 1 {
            return Err(VasError::CommunicationError(
                "Invalid service response",
            ));
        }
        let r = &m.records()[0];
        if r.tnf() != ndef_rs::TNF::External {
            return Err(VasError::CommunicationError(
                "Invalid service response",
            ));
        }
        if r.record_type() != b"srs" {
            return Err(VasError::CommunicationError(
                "Invalid service response",
            ));
        }
        let m = ndef_rs::NdefMessage::decode(r.payload())
            .map_err(|_| VasError::CommunicationError("Invalid NDEF message"))?;
        if m.records().len() != 2 {
            return Err(VasError::CommunicationError(
                "Invalid service response response",
            ));
        }
        let session = Session::from_record(&m.records()[0])?;
        let record_bundle = RecordBundle::from_record(&m.records()[1])?;
        Ok(Self {
            session: alloc::borrow::Cow::Owned(session),
            record_bundle,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServiceData<'a> {
    pub records: alloc::borrow::Cow<'a, [ServiceRecord<'a>]>,
}

impl ServiceData<'_> {
    pub fn decode(data: &[u8]) -> Result<Self, VasError> {
        let m = ndef_rs::NdefMessage::decode(data)
            .map_err(|_| VasError::CommunicationError("Invalid NDEF message"))?;
        let mut out = vec![];
        for record in m.records() {
            let service_record = ServiceRecord::from_record(record)?;
            out.push(service_record);
        };
        Ok(Self {
            records: alloc::borrow::Cow::Owned(out),
        })
    }
}