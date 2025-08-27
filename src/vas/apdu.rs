use core::ops::Deref;

#[derive(Debug)]
pub struct RequestAPDU<'a> {
    pub instruction_class: u8,
    pub instruction: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: alloc::borrow::Cow<'a, [u8]>,
    pub expected_response_length: u32
}

#[derive(Debug)]
pub struct ResponseAPDU {
    pub data: alloc::vec::Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl RequestAPDU<'_> {
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let data_len = self.data.len();

        if self.expected_response_length == 0 && data_len == 0 {
            unreachable!("Expected response length cannot be 0 with no command data")
        }

        let mut out = vec![
            self.instruction_class,
            self.instruction,
            self.p1,
            self.p2,
        ];

        match data_len {
            0 => {},
            i if i < 256 => {
                out.push(i as u8);
            },
            i if i < 65536 => {
                out.push(0);
                out.extend((i as u16).to_le_bytes());
            }
            _ => {
                unreachable!("Data length too long")
            }
        }

        out.extend(self.data.deref());

        match self.expected_response_length {
            0 => {},
            65536 if data_len >= 256 => {
                out.push(0);
                out.push(0);
            }
            i if i < 65536 && data_len >= 256 => {
                out.extend((i as u16).to_le_bytes());
            }
            _ if data_len >= 256 => {
                unreachable!("Expected response length too long")
            }
            256 => {
                out.push(0);
            }
            65536 => {
                out.push(0);
                out.push(0);
                out.push(0);
            }
            i if i < 256 => {
                out.push(i as u8);
            }
            i if i < 65536 => {
                out.push(0);
                out.extend((i as u16).to_le_bytes());
            }
            _ => {
                unreachable!("Expected response length too long")
            }
        }

        out
    }
}

impl ResponseAPDU {
    pub fn decode(data: &[u8]) -> Self {
        Self {
            data: data[0..data.len() - 2].to_vec(),
            sw1: data[data.len() - 2],
            sw2: data[data.len() - 1],
        }
    }

    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }
}