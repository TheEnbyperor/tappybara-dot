use crate::vas::VasError;
use rand_chacha::rand_core::RngCore;

pub struct Session {
    session_id: [u8; 8],
    sequence: u8,
}

impl Session {
    pub async fn new() -> Self {
        let mut sid = [0u8; 8];
        unsafe { crate::RAND.lock().await.assume_init_mut() }.fill_bytes(&mut sid);
        Self {
            session_id: sid,
            sequence: 0,
        }
    }

    pub fn next_request(&mut self) -> super::data::Session {
        self.sequence += 1;
        super::data::Session {
            session_id: self.session_id,
            sequence: self.sequence,
            status: super::data::SmartTapStatus::Ok
        }
    }

    pub fn validate_response(&mut self, response: &super::data::Session) -> Result<(), VasError> {
        self.sequence += 1;
        if response.session_id != self.session_id {
            return Err(VasError::CommunicationError("Response from wrong session"));
        }
        if response.sequence != self.sequence {
            return Err(VasError::CommunicationError("Response out of order"));
        }
        if response.status != super::data::SmartTapStatus::Ok {
            return Err(VasError::CommunicationError("Unexpected response code"));
        }
        Ok(())
    }
}