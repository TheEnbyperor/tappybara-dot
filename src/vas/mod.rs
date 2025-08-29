use alloc::boxed::Box;
use alloc::string::ToString;
use core::ops::Deref;

pub mod apdu;
pub mod apple;
pub mod google;

lazy_static::lazy_static! {
    static ref FCI: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x6F).unwrap();
    static ref IMPLEMENTATION_TAG: iso7816_tlv::ber::Tag = iso7816_tlv::ber::Tag::try_from(0x50).unwrap();
}

pub trait Target {
    async fn transmit(&mut self, request: apdu::RequestAPDU<'_>) -> Result<apdu::ResponseAPDU, VasError>;
}

pub struct VasClient<'a, T> {
    target: &'a mut T,
}

#[derive(Debug)]
pub enum VasError {
    CommunicationError(&'static str),
    TlvError(iso7816_tlv::TlvError),
    UnsupportedImplementation(alloc::string::String),
    TargetError(Box<dyn core::fmt::Debug>),
}

#[derive(Debug)]
pub enum Implementation {
    Apple(apple::FCI),
    Google(google::FCI),
}

#[derive(Debug)]
pub enum ResultData {
    Apple(apple::ResultData),
    Google(google::SmartTapResultData),
}

impl<'a, T: Target> VasClient<'a, T> {
    pub fn new(target: &'a mut T) -> Self {
        Self {
            target,
        }
    }

    pub async fn get_client(&mut self) -> Result<Implementation, VasError> {
        let resp = self.target.transmit(apdu::RequestAPDU {
            instruction_class: 0x00,
            instruction: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data: b"OSE.VAS.01".into(),
            expected_response_length: 256,
        }).await?;
        if !resp.is_success() {
            return Err(VasError::CommunicationError("Failed to select applet"));
        }

        let (fci, left) = iso7816_tlv::ber::Tlv::parse(&resp.data);
        let fci = fci.map_err(VasError::TlvError)?;
        if !fci.tag().eq(&FCI) {
            return Err(VasError::CommunicationError("Wrong tag for FCI"));
        }
        if !left.is_empty() {
            return Err(VasError::CommunicationError("Extra data after FCI"));
        }

        let implementation = find_tlv_tag(&fci, &IMPLEMENTATION_TAG)
            .map(get_tlv_primitive_value)
            .ok_or(VasError::CommunicationError("Missing implementation tag"))?;

        match implementation.deref() {
            b"ApplePay" => Ok(Implementation::Apple(apple::FCI::parse(fci)?)),
            b"AndroidPay" => Ok(Implementation::Google(google::FCI::parse(fci)?)),
            o => Err(VasError::UnsupportedImplementation(alloc::string::String::from_utf8_lossy(o).to_string()))
        }
    }
}

fn find_tlv_tag<'a>(tlv: &'a iso7816_tlv::ber::Tlv, tag: &iso7816_tlv::ber::Tag) -> Option<&'a iso7816_tlv::ber::Tlv> {
    match &tlv.value() {
        iso7816_tlv::ber::Value::Primitive(_) => {
            if tlv.tag() == tag {
                Some(tlv)
            } else {
                None
            }
        }
        iso7816_tlv::ber::Value::Constructed(e) => {
            for x in e {
                if x.tag() == tag {
                    return Some(x);
                }
            }
            None
        }
    }
}

fn find_tlv_tag_all<'a>(tlv: &'a iso7816_tlv::ber::Tlv, tag: &iso7816_tlv::ber::Tag) -> alloc::vec::Vec<&'a iso7816_tlv::ber::Tlv> {
    let mut ret: alloc::vec::Vec<&iso7816_tlv::ber::Tlv> = alloc::vec::Vec::new();
    match &tlv.value() {
        iso7816_tlv::ber::Value::Primitive(_) => {
            if tlv.tag() == tag {
                ret.push(tlv);
            }
        }
        iso7816_tlv::ber::Value::Constructed(e) => {
            for x in e {
                if x.tag() == tag {
                    ret.push(x);
                }
            }
        }
    }
    ret
}

fn get_tlv_primitive_value(tlv: &iso7816_tlv::ber::Tlv) -> &alloc::vec::Vec<u8> {
    match tlv.value() {
        iso7816_tlv::ber::Value::Primitive(v) => v,
        _ => unreachable!(),
    }
}