use alloc::string::ToString;
use crate::LT_IDENTITY;

struct ImprovPacket {
    packet_type: PacketType,
    data: alloc::vec::Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
enum PacketType {
    CurrentState = 0x01,
    Error = 0x02,
    Command = 0x03,
    Result = 0x04,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
enum CurrentState {
    Ready = 0x02,
    Provisioning = 0x03,
    Provisioned = 0x04,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum ErrorState {
    NoError = 0x00,
    InvalidPacket = 0x01,
    UnknownCommand = 0x02,
    UnableToConnect = 0x03,
    UnknownError = 0xFF,
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct SendWifiSettingCommand {
    ssid: alloc::string::String,
    password: alloc::string::String,
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct CommandResult {
    command: u8,
    data: alloc::vec::Vec<alloc::string::String>,
}

struct State<'a> {
    config_sender: embassy_sync::watch::DynSender<'a, crate::asn::tappybara_config::ConnectionConfig>
}

#[embassy_executor::task]
pub async fn improv(uart: &'static mut esp_hal::uart::UartRx<'static, esp_hal::Async>) {
    let state = State {
        config_sender: crate::CONNECTION_CONFIG.dyn_sender(),
    };

    const MARKER: &[u8] = b"IMPROV";
    loop {
        let mut buf = [0u8; MARKER.len()];
        let mut i = 0;
        'marker: loop {
            uart.read_exact_async(&mut buf[i..i + 1]).await.unwrap();
            i = (i + 1) % MARKER.len();
            for (j, v) in MARKER.iter().enumerate() {
                if buf[(i + j) % MARKER.len()] != *v {
                    continue 'marker;
                }
            }
            break;
        }
        info!("Got IMPROV header");

        let mut header: [u8; 3] = [0u8; 3];
        uart.read_exact_async(&mut header).await.unwrap();
        let (version, packet_type, length) = (header[0], header[1], header[2]);
        if version != 1 {
            continue;
        }

        let mut own_checksum: u8 = 221; // Sum of b"IMPROV"
        for b in header {
            own_checksum = own_checksum.wrapping_add(b);
        }

        let mut command_data = vec![0u8; length as usize];
        uart.read_exact_async(&mut command_data).await.unwrap();

        for b in &command_data {
            own_checksum = own_checksum.wrapping_add(*b);
        }

        let mut remote_checksum = [0u8; 1];
        uart.read_exact_async(&mut remote_checksum).await.unwrap();

        if own_checksum != remote_checksum[0] {
            send_error(ErrorState::InvalidPacket);
            continue;
        }

        let packet_type = match packet_type {
            0x01 => PacketType::CurrentState,
            0x02 => PacketType::Error,
            0x03 => PacketType::Command,
            0x04 => PacketType::Result,
            _ => {
                send_error(ErrorState::InvalidPacket);
                continue;
            }
        };

        let packet = ImprovPacket {
            packet_type,
            data: command_data,
        };
        process_improv(&state, packet).await;
    }
}

fn send_packet(packet: ImprovPacket) {
    let mut uart = embassy_futures::block_on(crate::UART_TX.lock());
    let mut checksum: u8 = 222u8;
    let mut out = b"IMPROV\x01".to_vec();
    checksum = checksum.wrapping_add(packet.packet_type as u8);
    out.push(packet.packet_type as u8);
    checksum = checksum.wrapping_add(packet.data.len() as u8);
    out.push(packet.data.len() as u8);
    for b in &packet.data {
        checksum = checksum.wrapping_add(*b);
    }
    out.extend(packet.data);
    out.push(checksum);
    unsafe { uart.assume_init_mut() }.write(&out).unwrap();
    unsafe { uart.assume_init_mut() }.flush().unwrap();
}

fn send_error(error: ErrorState) {
    let error_packet = ImprovPacket {
        packet_type: PacketType::Error,
        data: vec![error as u8],
    };
    send_packet(error_packet);
}

fn send_current_state(state: CurrentState) {
    let state_packet = ImprovPacket {
        packet_type: PacketType::CurrentState,
        data: vec![state as u8],
    };
    send_packet(state_packet);
}

fn send_command_result(command: CommandResult) {
    let data_len = command.data.iter().map(|b| b.len() + 1).sum::<usize>();
    let mut data = vec![command.command, data_len as u8];
    for s in &command.data {
        data.push(s.len() as u8);
        data.extend(s.as_bytes());
    }
    let response_packet = ImprovPacket {
        packet_type: PacketType::Result,
        data
    };
    send_packet(response_packet);
}

async fn process_improv(state: &State<'_>, packet: ImprovPacket) {
    match packet.packet_type {
        PacketType::Command => {
            if packet.data.len() < 2 {
                send_error(ErrorState::InvalidPacket);
                return;
            }
            let command = packet.data[0];
            let data_len = packet.data[1] as usize;
            if data_len > packet.data.len() - 2 {
                send_error(ErrorState::InvalidPacket);
                return;
            }
            let data = &packet.data[2..data_len+2];

            match command {
                0x01 => send_wifi_settings(state, data).await,
                0x02 => request_current_state().await,
                0x03 => request_device_information().await,
                0x04 => request_scanned_networks().await,
                _ => send_error(ErrorState::UnknownCommand),
            };
        },
        _ => send_error(ErrorState::InvalidPacket),
    }
}

async fn request_current_state() {
    match crate::WIFI_STATUS.try_get() {
        Some(crate::WifiStatus::Startup) | Some(crate::WifiStatus::WifiConnecting) | None => send_current_state(CurrentState::Ready),
        Some(crate::WifiStatus::WifiConnected) => send_current_state(CurrentState::Provisioned),
    }
}

async fn request_device_information() {
    let lt_identity = LT_IDENTITY.try_get().unwrap();
    let lt_public_asn1 = lt_identity.public_key().public_asn1();
    let mut hash_device = crate::SHA.lock().await;
    let mut hasher = unsafe { hash_device.assume_init_mut().start::<esp_hal::sha::Sha256>() };
    let mut lt_public_asn1_ref = lt_public_asn1.as_slice();
    while !lt_public_asn1_ref.is_empty() {
        lt_public_asn1_ref = hasher.update(&lt_public_asn1_ref).unwrap();
    }
    let mut digest = [0u8; 32];
    hasher.finish(&mut digest).unwrap();
    drop(hash_device);

    let device_name_parts = digest.into_iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<alloc::vec::Vec<_>>();
    let device_name = device_name_parts.join(":");

    send_command_result(CommandResult {
        command: 0x03,
        data: vec![
            env!("CARGO_PKG_NAME").to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            "ESP32".to_string(),
            device_name,
        ]
    })
}

async fn request_scanned_networks() {
    if let Some(scan) = crate::WIFI_SCAN.try_get() {
        for ap in scan {
            send_command_result(CommandResult {
                command: 0x04,
                data: vec![ap.ssid, ap.signal_strength.to_string(), match ap.auth_method {
                    None | Some(esp_wifi::wifi::AuthMethod::None) => "NO".to_string(),
                    _ => "YES".to_string(),
                }]
            })
        }
    }
    send_command_result(CommandResult {
        command: 0x04,
        data: vec![]
    })
}

async fn send_wifi_settings(state: &State<'_>, data: &[u8]) {
    if data.len() < 2 {
        send_error(ErrorState::InvalidPacket);
        return;
    }
    let ssid_len = data[0] as usize;
    if ssid_len >= data.len() - 2 {
        send_error(ErrorState::InvalidPacket);
        return;
    }
    let ssid = &data[1..ssid_len+1];
    let pwd_len = data[ssid_len+1] as usize;
    if pwd_len >= data.len() - ssid_len - 1 {
        send_error(ErrorState::InvalidPacket);
        return;
    }
    let pwd = &data[ssid_len+2..ssid_len+2+pwd_len];
    let ssid = match alloc::str::from_utf8(ssid) {
        Ok(s) => s,
        Err(_) => {
            send_error(ErrorState::InvalidPacket);
            return;
        }
    };
    let pwd = match alloc::str::from_utf8(pwd) {
        Ok(s) => s,
        Err(_) => {
            send_error(ErrorState::InvalidPacket);
            return;
        }
    };
    let mut current_state = crate::CONNECTION_CONFIG.try_get().unwrap_or_else(crate::config::default_connection_config);
    current_state.networks = vec![crate::asn::tappybara_config::WifiNetwork {
        ssid: ssid.to_string(),
        password: if pwd.is_empty() { None } else { Some(pwd.to_string()) },
        auth_method: crate::asn::tappybara_config::WifiAuthMethod::WPA2Personal,
    }];
    state.config_sender.send(current_state);
    crate::config::persist_connection_config().await;
    send_command_result(CommandResult {
        command: 0x01,
        data: vec![],
    })
}