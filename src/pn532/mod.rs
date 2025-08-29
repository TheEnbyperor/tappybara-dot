use types::Pn532Command;

pub mod types;
mod io;
pub mod iso_dep;

pub use io::io;

#[derive(Debug)]
pub enum Pn532Error {
    IOError(esp_hal::i2c::master::Error),
    Protocol,
    Timeout,
    AckTimeout,
    Ack,
    Status(u8),
}

impl From<esp_hal::i2c::master::Error> for Pn532Error {
    fn from(error: esp_hal::i2c::master::Error) -> Self {
        Pn532Error::IOError(error)
    }
}

fn crc16a(data: &[u8]) -> [u8; 2] {
    use core::ops::{BitXor, BitXorAssign};
    let mut w_crc: u16 = 0x6363;
    for byte in data {
        let mut byte = *byte;
        byte.bitxor_assign((w_crc & 0x00FF) as u8);
        byte.bitxor_assign((byte << 4) & 0xFF);
        w_crc = ((w_crc >> 8)
            .bitxor((byte as u16) << 8)
            .bitxor((byte as u16) << 3)
            .bitxor((byte as u16) >> 4))
            & 0xFFFF;
    }
    w_crc.to_le_bytes()
}

async fn execute_command(command: Pn532Command, timeout: embassy_time::Duration) -> Result<alloc::vec::Vec<u8>, Pn532Error> {
    io::COMMANDS.send(io::Command {
        command,
        timeout,
    }).await;
    io::RESPONSE.receive().await
}

pub async fn get_firmware_version() -> Result<types::Pn532FirmwareVersion, Pn532Error> {
    let data = execute_command(
        Pn532Command {
            command: 0x02,
            data: vec![],
        }, embassy_time::Duration::from_secs(1)).await?;
    if data.len() != 4 {
        return Err(Pn532Error::Protocol);
    }
    Ok(types::Pn532FirmwareVersion {
        ic: data[0],
        major: data[1],
        minor: data[2],
        features: data[3],
    })
}

pub async fn set_parameters(parameters: types::Pn532Parameters) -> Result<(), Pn532Error> {
    let mut out: u8 = 0;
    if parameters.nad_used {
        out |= 0x01;
    }
    if parameters.did_used {
        out |= 0x02;
    }
    if parameters.automatic_atr_res {
        out |= 0x04;
    }
    if parameters.automatic_rats {
        out |= 0x10;
    }
    if parameters.picc {
        out |= 0x20;
    }
    if parameters.remove_pre_post_amble {
        out |= 0x40;
    }
    execute_command(
        Pn532Command {
            command: 0x12,
            data: vec![out],
        },
        embassy_time::Duration::from_secs(1),
    )
        .await?;
    Ok(())
}

pub async fn rf_config(rf_config: types::Pn532RfConfig) -> Result<(), Pn532Error> {
    let data = match rf_config {
        types::Pn532RfConfig::RfField { auto_rfca, rf_on } => {
            vec![
                0x01,
                (if auto_rfca { 0x02 } else { 0x00 }) | (if rf_on { 0x01 } else { 0x00 }),
            ]
        }
        types::Pn532RfConfig::Timings {
            atr_timeout,
            retry_timout,
        } => {
            vec![0x02, 0x00, atr_timeout, retry_timout]
        }
        types::Pn532RfConfig::MaxRetryCommunicate(v) => {
            vec![0x04, v]
        }
        types::Pn532RfConfig::MaxRetries {
            atr_count,
            psl_count,
            passive_activation_count,
        } => {
            vec![0x05, atr_count, psl_count, passive_activation_count]
        }
    };
    execute_command(
        Pn532Command {
            command: 0x32,
            data,
        },
        embassy_time::Duration::from_secs(1),
    )
        .await?;
    Ok(())
}

pub async fn sam_config(sam_mode: types::Pn532SamMode, timeout: u8) -> Result<(), Pn532Error> {
    execute_command(
        Pn532Command {
            command: 0x14,
            data: vec![sam_mode as u8, timeout, 0x01],
        },
        embassy_time::Duration::from_secs(1),
    )
        .await?;
    Ok(())
}

pub async fn read_register(registers: &[u16]) -> Result<alloc::vec::Vec<u8>, Pn532Error> {
    let mut data = vec![];
    for r in registers {
        data.extend(r.to_be_bytes());
    }
    let data = execute_command(
        Pn532Command {
            command: 0x06,
            data,
        },
        embassy_time::Duration::from_secs(1),
    )
        .await?;
    Ok(data)
}

pub async fn write_register(writes: &[types::Pn532RegisterWrite]) -> Result<(), Pn532Error> {
    let mut data = vec![];
    for write in writes {
        data.extend(write.register.to_be_bytes());
        data.push(write.value);
    }
    execute_command(
        Pn532Command {
            command: 0x08,
            data,
        },
        embassy_time::Duration::from_secs(1),
    )
        .await?;
    Ok(())
}

pub async fn list_passive_targets(
    max_targets: u8,
    poll_type: types::Pn532PollType,
    timeout: embassy_time::Duration,
) -> Result<alloc::vec::Vec<types::Pn532Target>, Pn532Error> {
    let device_type = match poll_type {
        types::Pn532PollType::Iso14443TypeA => 0x00,
        types::Pn532PollType::Iso14443TypeB { .. } => 0x03,
        types::Pn532PollType::FeliCa212 { .. } => 0x01,
        types::Pn532PollType::FeliCa424 { .. } => 0x02,
        types::Pn532PollType::Jewel { .. } => 0x04,
    };
    let mut req_data = vec![max_targets, device_type];
    match poll_type {
        types::Pn532PollType::Iso14443TypeB {
            afi,
            polling_method,
        } => {
            req_data.push(afi);
            req_data.push(match polling_method {
                types::Iso14443TypeBPollingMethod::Timeslot => 0x00,
                types::Iso14443TypeBPollingMethod::Probabilistic => 0x01,
            })
        }
        types::Pn532PollType::FeliCa212 { payload } | types::Pn532PollType::FeliCa424 { payload } => {
            req_data.extend(payload);
        }
        _ => {}
    }
    assert!(max_targets <= 2);
    let resp_data = match execute_command(
            Pn532Command {
                command: 0x4A,
                data: req_data,
            },
            timeout,
        )
        .await
    {
        Ok(data) => data,
        Err(Pn532Error::Timeout) => return Ok(alloc::vec::Vec::new()),
        Err(e) => return Err(e),
    };
    if resp_data.len() < 1 {
        return Err(Pn532Error::Protocol);
    }
    let num_targets = resp_data[0];
    let mut i = 1;
    let mut out = vec![];
    for _ in 0..num_targets {
        let target_id = resp_data[i];
        i += 1;
        let t = match poll_type {
            types::Pn532PollType::Iso14443TypeA => {
                let sens_res = &resp_data[i..i + 2];
                let sel_res = resp_data[i + 2];
                let nfc_id_length = resp_data[i + 3];
                let nfc_id = &resp_data[i + 4..i + 4 + nfc_id_length as usize];
                i += 4 + nfc_id_length as usize;
                let ats = if i == resp_data.len() {
                    &[]
                } else {
                    let ats_length = resp_data[i];
                    let ats = &resp_data[i..i + ats_length as usize];
                    i += ats_length as usize;
                    ats
                };

                types::Pn532TargetType::Iso14443TypeA(types::Iso14443TypeATarget {
                    sense_response: u16::from_le_bytes([sens_res[0], sens_res[1]]),
                    select_response: sel_res,
                    nfc_id: nfc_id.to_vec(),
                    ats: ats.to_vec(),
                })
            }
            types::Pn532PollType::Iso14443TypeB { .. } => {
                let atqb = &resp_data[i..i + 12];
                let attr_len = resp_data[i + 12];
                let attr = &resp_data[i + 13..i + 13 + attr_len as usize];
                i += 13 + attr_len as usize;

                types::Pn532TargetType::Iso14443TypeB(types::Iso14443TypeBTarget {
                    atqb: atqb.try_into().unwrap(),
                    attribute_response: attr.to_vec(),
                })
            }
            types::Pn532PollType::FeliCa212 { .. } | types::Pn532PollType::FeliCa424 { .. } => {
                let len = resp_data[i];
                let nfc_id = &resp_data[i + 2..i + 10];
                let sys_code = if len == 20 {
                    Some(u16::from_be_bytes([resp_data[i + 18], resp_data[i + 19]]))
                } else {
                    None
                };
                i += len as usize;

                types::Pn532TargetType::FeliCa(types::FeliCaTarget {
                    nfc_id: nfc_id.try_into().unwrap(),
                    system_code: sys_code,
                })
            }
            types::Pn532PollType::Jewel { .. } => {
                let sens_res = &resp_data[i..i + 2];
                let jewel_id = &resp_data[i + 2..i + 6];
                i += 6;

                types::Pn532TargetType::Jewel(types::JewelTarget {
                    sense_response: u16::from_le_bytes([sens_res[0], sens_res[1]]),
                    jewel_id: jewel_id.try_into().unwrap(),
                })
            }
        };
        out.push(types::Pn532Target {
            target_id,
            target: t,
        })
    }
    Ok(out)
}

pub async fn in_communicate_through(
    data: &[u8],
    timeout: embassy_time::Duration,
) -> Result<alloc::vec::Vec<u8>, Pn532Error> {
    let data = execute_command(
            Pn532Command {
                command: 0x42,
                data: data.to_vec(),
            },
            timeout,
        ).await?;
    if data.len() < 1 {
        return Err(Pn532Error::Protocol);
    }
    let status = types::Pn532Status::from(data[0]);
    if status.status == 0x00 {
        Ok(data[1..].to_vec())
    } else {
        Err(Pn532Error::Status(status.status))
    }
}

pub async fn poll_target(
    targets: &[types::Pn532PollType],
    ecp: Option<&[u8]>,
) -> Result<Option<types::Pn532Target>, Pn532Error> {
    for target in targets {
        let mut targets = list_passive_targets(1, *target, embassy_time::Duration::from_millis(250)).await?;
        if !targets.is_empty() {
            return Ok(Some(targets.remove(0)));
        }
        if let Some(ecp) = ecp {
            let data = match target {
                types::Pn532PollType::Iso14443TypeA => {
                    let mut type_a_ecp = ecp.to_vec();
                    type_a_ecp.extend_from_slice(&crc16a(ecp));
                    alloc::borrow::Cow::Owned(type_a_ecp)
                }
                types::Pn532PollType::Iso14443TypeB { .. } => alloc::borrow::Cow::Borrowed(ecp),
                _ => continue,
            };
            rf_config(types::Pn532RfConfig::MaxRetries {
                atr_count: 0xFF,
                psl_count: 0x01,
                passive_activation_count: 0x00,
            }).await?;
            write_register(&[types::Pn532RegisterWrite {
                register: 0x633D,
                value: 0x00,
            }]).await?;
            match in_communicate_through(&data, embassy_time::Duration::from_millis(250))
                .await
            {
                Ok(_) => {}
                Err(Pn532Error::Status(0x01)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(None)
}

pub async fn poll_target_loop(
    targets: &[types::Pn532PollType],
    ecp: Option<&[u8]>,
) -> Result<types::Pn532Target, Pn532Error> {
    loop {
        if let Some(target) = poll_target(targets, ecp).await? {
            return Ok(target);
        }
        embassy_time::Timer::after_millis(250).await;
    }
}

pub async fn data_exchange(target: u8, data: &[u8], ) -> Result<alloc::vec::Vec<u8>, Pn532Error> {
    let parts = (data.len() / 262) + 1;
    let mut out = vec![];
    for i in 0..parts {
        let mut req = vec![
            target | (if i + 1 == parts { 0x00 } else { 0x40 }),
        ];
        req.extend(&data[i * 262..core::cmp::min((i + 1) * 262, data.len())]);
        let resp = execute_command(Pn532Command {
                    command: 0x40,
                    data: req,
                }, embassy_time::Duration::from_secs(1)).await?;
        if resp.len() < 1 {
            return Err(Pn532Error::Protocol);
        }
        let status = types::Pn532Status::from(resp[0]);
        if status.status != 0x00 {
            return Err(Pn532Error::Status(status.status));
        }
        out.extend(&resp[1..]);
    }
    Ok(out)
}