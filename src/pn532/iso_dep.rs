pub struct IsoDep {
    cid: u8,
    pni: u8,
    miu: usize,
    fwt: f64,
}

impl IsoDep {
    pub fn new(cid: u8, mut fsci: u8, mut fwti: u8) -> Self {
        if fsci > 8 {
            warn!("FSCI with RFU value in SENSB_RES");
            fsci = 8;
        }
        if fwti > 14 {
            warn!("FWI with RFU value in SENSB_RES");
            fwti = 4
        }
        let mut fsc = [16, 24, 32, 40, 48, 64, 96, 128, 256][fsci as usize];
        let fwt = 4096.0 / 13.56E6 * (1 << fwti) as f64;
        if fsc > 262 {
            fsc = 262;
        }
        Self {
            cid,
            pni: 0,
            miu: fsc - 3,
            fwt,
        }
    }

    fn timeout(secs: f64) -> embassy_time::Duration {
        let secs = secs + 0.05;
        trace!("timeout={}, millis={}", secs, (secs * 1000f64) as u64);
        embassy_time::Duration::from_millis((secs * 1000f64) as u64)
    }

    async fn exchange(&mut self, command: &[u8]) -> Result<alloc::vec::Vec<u8>, crate::pn532::Pn532Error> {
        let timeout = self.fwt + (49152f64 / 13.56E6);
        let send_max = core::cmp::min(self.miu, 20); // Need to limit size of data due to ESP32 I2C FIFO buffer size
        let parts = (command.len() / send_max) + 1;

        let mut i = 0;
        let (resp, more_data) = loop {
            let more = i + 1 < parts;
            let pfb = if more {
                0x12
            } else {
                0x02
            } | self.pni | if self.cid != 0 {
                0x08
            } else {
                0x00
            };
            let mut data = vec![pfb];
            if self.cid != 0 {
                data.push(self.cid);
            }
            let mut resp = loop {
                let offset = i * send_max;
                data.extend(&command[offset..core::cmp::min(offset + send_max, command.len())]);
                let resp = crate::pn532::in_communicate_through(&data, Self::timeout(timeout)).await?;
                if resp.len() == 0 {
                    return Err(crate::pn532::Pn532Error::Protocol);
                }
                if resp[0] == 0xA2 | (!self.pni & 1) {
                    continue;
                }
                break resp;
            };

            while resp[0] & 0b11111110 == 0b11110010 {
                debug!("ISO-DEP waiting time extension");
                embassy_time::Timer::after_millis(100).await;
                resp = crate::pn532::in_communicate_through(&resp, Self::timeout((resp[1] & 0x3F) as f64 * self.fwt)).await?;
            }

            if resp[0] & 0x01 != self.pni {
                warn!("ISO-DEP protocol error: block number");
                return Err(crate::pn532::Pn532Error::Protocol);
            }

            if more {
                if resp[0] & 0b11111110 == 0b10100010 {
                    self.pni = (self.pni + 1) % 2;
                } else {
                    warn!("ISO-DEP protocol error: expected ack");
                    return Err(crate::pn532::Pn532Error::Protocol);
                }
            } else {
                if resp[0] & 0b11101110 == 0x02 {
                    self.pni = (self.pni + 1) % 2;
                    break (resp[1..].to_vec(), resp[0] & 0b00010000 != 0);
                } else {
                    warn!("ISO-DEP protocol error: expected inf");
                    return Err(crate::pn532::Pn532Error::Protocol);
                }
            }
            i += 1;
        };

        while more_data {
            unimplemented!("ISO-DEP additional response data");
        }

        Ok(resp)
    }

    pub async fn deselect(&mut self) -> Result<(), crate::pn532::Pn532Error> {
        crate::pn532::in_communicate_through(&[0xC2], embassy_time::Duration::from_secs(1)).await?;
        Ok(())
    }

    pub async fn new_type_a() -> Result<Self, crate::pn532::Pn532Error> {
        crate::pn532::write_register(&[crate::pn532::types::Pn532RegisterWrite {
            register: 0x6302,
            value: 0x80,
        }, crate::pn532::types::Pn532RegisterWrite {
            register: 0x6303,
            value: 0x80,
        }, crate::pn532::types::Pn532RegisterWrite {
            register: 0x6305,
            value: 0x4b
        }]).await?;
        crate::pn532::rf_config(crate::pn532::types::Pn532RfConfig::Timings {
            atr_timeout: 0x0B,
            retry_timout: 0x0A,
        }).await?;

        let rats_res = crate::pn532::in_communicate_through(&[0xE0, 0x80], embassy_time::Duration::from_secs(1)).await?;
        let (fsci, fwti) = (rats_res[1] & 0x0F, rats_res[3] >> 4);

        Ok(Self::new(0, fsci, fwti))
    }
}

impl crate::vas::Target for IsoDep {
    async fn transmit(&mut self, request: crate::vas::apdu::RequestAPDU<'_>) -> Result<crate::vas::apdu::ResponseAPDU, crate::vas::VasError> {
        debug!("request APDU: {:02X?}", request);
        let resp = self.exchange(&request.encode()).await?;
        let resp = crate::vas::apdu::ResponseAPDU::decode(&resp);
        debug!("response APDU: {:02X?}", resp);
        Ok(resp)
    }
}