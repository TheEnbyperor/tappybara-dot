#[derive(Debug)]
pub enum Pn532Packet {
    Ack,
    Nack,
    Data(Pn532Command),
}

#[derive(Debug)]
pub struct Pn532Command {
    pub command: u8,
    pub data: alloc::vec::Vec<u8>,
}

pub struct Pn532FirmwareVersion {
    pub ic: u8,
    pub major: u8,
    pub minor: u8,
    pub features: u8,
}

impl Pn532FirmwareVersion {
    fn supports_14443_type_a(&self) -> bool {
        (self.features & 0x01) != 0
    }

    fn supports_14443_type_b(&self) -> bool {
        (self.features & 0x02) != 0
    }

    fn supports_18092(&self) -> bool {
        (self.features & 0x04) != 0
    }
}

impl alloc::fmt::Debug for Pn532FirmwareVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pn532FirmwareVersion")
            .field("ic", &self.ic)
            .field("major", &self.major)
            .field("minor", &self.minor)
            .field("supports_14443_type_a", &self.supports_14443_type_a())
            .field("supports_14443_type_b", &self.supports_14443_type_b())
            .field("supports_18092", &self.supports_18092())
            .finish()
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub enum Iso14443TypeBPollingMethod {
    #[default]
    Timeslot,
    Probabilistic,
}

#[derive(Debug, Copy, Clone)]
pub enum Pn532PollType {
    Iso14443TypeA,
    Iso14443TypeB {
        afi: u8,
        polling_method: Iso14443TypeBPollingMethod,
    },
    FeliCa212 {
        payload: [u8; 5],
    },
    FeliCa424 {
        payload: [u8; 5],
    },
    Jewel,
}

#[derive(Debug)]
#[repr(u8)]
pub enum Pn532SamMode {
    Normal = 0x01,
    VirtualCard = 0x02,
    WiredCard = 0x03,
    DualCard = 0x04,
}

#[derive(Debug)]
pub struct Pn532Parameters {
    pub nad_used: bool,
    pub did_used: bool,
    pub automatic_atr_res: bool,
    pub automatic_rats: bool,
    pub picc: bool,
    pub remove_pre_post_amble: bool
}

#[derive(Debug)]
pub enum Pn532RfConfig {
    RfField {
        auto_rfca: bool,
        rf_on: bool,
    },
    Timings {
        atr_timeout: u8,
        retry_timout: u8,
    },
    MaxRetryCommunicate(u8),
    MaxRetries {
        atr_count: u8,
        psl_count: u8,
        passive_activation_count: u8,
    },
}

#[derive(Debug)]
pub struct Pn532RegisterWrite {
    pub register: u16,
    pub value: u8,
}

#[derive(Debug)]
pub(super) struct Pn532Status {
    pub nad_present: bool,
    pub more_information: bool,
    pub status: u8,
}

impl From<u8> for Pn532Status {
    fn from(value: u8) -> Self {
        Self {
            nad_present: (value & 0x80) != 0,
            more_information: (value & 0x40) != 0,
            status: value & 0x3f,
        }
    }
}

#[derive(Debug)]
pub struct Pn532Target {
    pub target_id: u8,
    pub target: Pn532TargetType,
}

#[derive(Debug)]
pub enum Pn532TargetType {
    Iso14443TypeA(Iso14443TypeATarget),
    Iso14443TypeB(Iso14443TypeBTarget),
    FeliCa(FeliCaTarget),
    Jewel(JewelTarget),
}

#[derive(Debug)]
pub struct Iso14443TypeATarget {
    pub sense_response: u16,
    pub select_response: u8,
    pub nfc_id: alloc::vec::Vec<u8>,
    pub ats: alloc::vec::Vec<u8>,
}

#[derive(Debug)]
pub struct Iso14443TypeBTarget {
    pub atqb: [u8; 12],
    pub attribute_response: alloc::vec::Vec<u8>,
}

#[derive(Debug)]
pub struct FeliCaTarget {
    pub nfc_id: [u8; 8],
    pub system_code: Option<u16>,
}

#[derive(Debug)]
pub struct JewelTarget {
    pub sense_response: u16,
    pub jewel_id: [u8; 4],
}