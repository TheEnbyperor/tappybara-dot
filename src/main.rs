#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![feature(asm_experimental_arch)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;

mod config;
mod ecc;
mod improv;
mod init;
mod iso_dep;
mod net;
mod pn532;
mod storage;
mod tls;
mod util;
mod vas;
mod ws2812;
mod coap;
mod mdns;

mod asn {
    include!(concat!(env!("OUT_DIR"), "/asn.rs"));
}

use alloc::string::ToString;
use core::mem::MaybeUninit;
use esp_alloc as _;
use rand_chacha::rand_core::RngCore;

pub static IO_LOCK: embassy_sync::semaphore::FairSemaphore<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    2,
> = embassy_sync::semaphore::FairSemaphore::new(1);

pub static RAND: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    MaybeUninit<rand_chacha::ChaCha12Rng>,
> = embassy_sync::mutex::Mutex::new(MaybeUninit::uninit());

pub static SHA: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    MaybeUninit<esp_hal::sha::Sha>,
> = embassy_sync::mutex::Mutex::new(MaybeUninit::uninit());

pub static UART_TX: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    MaybeUninit<esp_hal::uart::UartTx<esp_hal::Blocking>>,
> = embassy_sync::mutex::Mutex::new(MaybeUninit::uninit());

struct Fs(
    embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        MaybeUninit<
            littlefs2::fs::Filesystem<
                'static,
                storage::LfsFlash<
                    esp_bootloader_esp_idf::partitions::FlashRegion<
                        'static,
                        esp_storage::FlashStorage,
                    >,
                >,
            >,
        >,
    >,
);
unsafe impl Sync for Fs {}
unsafe impl Send for Fs {}

pub static FS: Fs = Fs(embassy_sync::mutex::Mutex::new(MaybeUninit::uninit()));

pub static LT_IDENTITY: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    ecc::PrivateKey,
    0,
> = embassy_sync::watch::Watch::new();

pub static CONNECTION_CONFIG: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    asn::tappybara_config::ConnectionConfig,
    2,
> = embassy_sync::watch::Watch::new();

pub static WIFI_SCAN: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    alloc::vec::Vec<esp_wifi::wifi::AccessPointInfo>,
    1,
> = embassy_sync::watch::Watch::new();

pub static COAP_CLIENT: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    coap::CoAPClient,
    1,
> = embassy_sync::watch::Watch::new();

#[derive(Debug, Copy, Clone)]
pub enum WifiStatus {
    Startup,
    WifiConnecting,
    WifiConnected,
}

#[derive(Debug, Copy, Clone)]
pub enum DTLSStatus {
    Startup,
    DTLSConnecting,
    DTLSConnected,
}

#[derive(Debug, Copy, Clone)]
pub enum VASStatus {
    Startup,
    Polling,
    Communicating,
    Done,
    Error,
}

pub static WIFI_STATUS: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    WifiStatus,
    2,
> = embassy_sync::watch::Watch::new();

pub static DTLS_STATUS: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    DTLSStatus,
    2,
> = embassy_sync::watch::Watch::new();

pub static VAS_STATUS: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    VASStatus,
    2,
> = embassy_sync::watch::Watch::new();

impl From<pn532::Pn532Error> for vas::VasError {
    fn from(err: pn532::Pn532Error) -> Self {
        Self::TargetError(alloc::boxed::Box::new(err))
    }
}

fn parse_config_response(resp: coap_lite::CoapResponse) -> Option<asn::tappybara::ReaderConfig> {
    match resp.get_status() {
        coap_lite::ResponseType::Content => {
            let content_format: coap_lite::option_value::OptionValueU16 = match resp.message.get_first_option_as(coap_lite::CoapOption::ContentFormat) {
                Some(Ok(val)) => val,
                Some(Err(err)) => {
                    error!("Config response invalid content type: {:?}", err);
                    return None;
                }
                None => {
                    error!("Config response missing content type");
                    return None;
                }
            };
            if content_format.0 != 65000 {
                error!("Config response invalid content type: {}", content_format.0);
                return None;
            }
            rasn::uper::decode::<crate::asn::tappybara::ReaderConfig>(&resp.message.payload).or_else(|err| {
                error!("Config response invalid config: {:?}", err);
                Err(())
            }).ok()
        },
        o => {
            error!("Config response invalid response: {:?}", o);
            None
        }
    }
}

struct VASConfig {
    apple_config: Option<()>, // TODO: implement Apple config
    google_config: Option<vas::google::TerminalConfig>
}

fn map_reader_config(config: asn::tappybara::ReaderConfig) -> VASConfig {
    VASConfig {
        apple_config: config.apple_vasconfig.map(|_| ()),
        google_config: config.google_smart_tap_config.map(|c| {
            vas::google::TerminalConfig {
                collector_id: c.collector_id,
                key_version: c.collector_key_version,
                private_key: ecc::PrivateKey::from_bytes(c.collector_private_key.as_ref().try_into().unwrap()),
                services: c.services.0.into_iter().map(|v| v.0).collect(),
                store_location_id: c.store_location_id.and_then(|i| i.try_into().ok()),
                merchant_name: c.merchant_name,
                merchant_category_code: c.mcc,
            }
        })
    }
}

#[embassy_executor::task]
async fn vas() {
    let status_sender = VAS_STATUS.sender();
    let mut coap_receiver = COAP_CLIENT.receiver().unwrap();
    let fw_ver = pn532::get_firmware_version().await.unwrap();
    info!("Connected to reader PN5{:02X}", fw_ver.ic);
    info!("Reader firmware: V{}.{}", fw_ver.major, fw_ver.minor);

    pn532::sam_config(pn532::types::Pn532SamMode::Normal, 0)
        .await
        .unwrap();

    pn532::set_parameters(pn532::types::Pn532Parameters {
        nad_used: false,
        did_used: false,
        automatic_atr_res: false,
        automatic_rats: false,
        picc: false,
        remove_pre_post_amble: false,
    })
    .await
    .unwrap();

    let coap_client = coap_receiver.get().await;

    let mut config_request = coap_lite::CoapRequest::new();
    config_request.set_method(coap_lite::RequestType::Get);
    config_request.set_path("/config");
    config_request.message.add_option_as(coap_lite::CoapOption::Accept, coap_lite::option_value::OptionValueU16(65000));

    let (config_resp, mut config_observe) = match coap_client.send_observe_request(config_request).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Error getting VAS config: {:?}", e);
            status_sender.send(VASStatus::Error);
            return;
        }
    };
    let Some(config) = parse_config_response(config_resp) else {
        status_sender.send(VASStatus::Error);
        return;
    };
    info!("Reader config: {:?}", config);

    let mut reader_config = map_reader_config(config);

    let ecp = &[0x6A, 0x01, 0x00, 0x00, 0x02];
    'main: loop {
        let google_reader_ephemeral_key = ecc::PrivateKey::new();
        status_sender.send(VASStatus::Polling);
        let target = if let Some(observer) = config_observe.as_mut() {
            loop {
                if observer.has_next() {
                    let resp = observer.next().await;
                    match resp {
                        Some(resp) => match parse_config_response(resp) {
                            Some(new_config) => {
                                info!("New reader config: {:?}", new_config);
                                reader_config = map_reader_config(new_config);
                            },
                            None => {
                                status_sender.send(VASStatus::Error);
                                return;
                            }
                        },
                        None => {
                            config_observe = None;
                        }
                    }
                    continue 'main;
                }
                if let Some(target) = pn532::poll_target(&[pn532::types::Pn532PollType::Iso14443TypeA], Some(ecp)).await.transpose() {
                    break target;
                }
                embassy_time::Timer::after_millis(250).await;
            }
        } else {
            pn532::poll_target_loop(&[pn532::types::Pn532PollType::Iso14443TypeA], Some(ecp)).await
        };
        match async {
            let target = target?;
            info!("Got target: {:02X?}", target);
            status_sender.send(VASStatus::Communicating);

            let mut target = match &target.target {
                pn532::types::Pn532TargetType::Iso14443TypeA(_) => {
                    iso_dep::IsoDep::new_type_a().await?
                }
                _ => unreachable!(),
            };

            let res: Result<(), vas::VasError> = (async || {
                let mut client = vas::VasClient::new(&mut target);
                let imp = client.get_client().await?;
                debug!("Implementation: {:02X?}", imp);
                match imp {
                    vas::Implementation::Apple(_) => {}
                    vas::Implementation::Google(fci) => {
                        let Some(google_config) = reader_config.google_config.as_ref() else {
                            return Err(vas::VasError::UnsupportedImplementation("No Google config".to_string()));
                        };
                        let mut google_client =
                            vas::google::Client::new(&mut target, fci, &google_config).await;
                        debug!(
                            "Google result: {:02X?}",
                            google_client
                                .do_exchange(google_reader_ephemeral_key)
                                .await?
                        );
                    }
                }
                Ok(())
            })()
            .await;

            target.deselect().await?;

            res?;
            Ok::<(), vas::VasError>(())
        }
        .await
        {
            Ok(()) => {
                status_sender.send(VASStatus::Done);
            }
            Err(e) => {
                warn!("{:?}", e);
                status_sender.send(VASStatus::Error);
            }
        }
        embassy_time::Timer::after_secs(3).await;
    }
}

#[embassy_executor::task]
async fn lights() {
    let rmt = unsafe { esp_hal::peripherals::RMT::steal() };
    let light_pin = unsafe { esp_hal::peripherals::GPIO32::steal() };
    let mut ws2812 = ws2812::Ws2812Driver::new(rmt, light_pin).unwrap();

    const NUM_LEDS: usize = 24;
    let mut x: usize = 0;
    let mut y: usize = 0;
    let mut leds = [ws2812::Color::default(); NUM_LEDS];

    loop {
        let wifi_status = WIFI_STATUS.try_get().unwrap_or(WifiStatus::Startup);
        let dtls_status = DTLS_STATUS.try_get().unwrap_or(DTLSStatus::Startup);
        let vas_status = VAS_STATUS.try_get().unwrap_or(VASStatus::Startup);
        match wifi_status {
            WifiStatus::Startup => {
                for j in 0..NUM_LEDS {
                    let mul = 2usize.pow(j as u32);
                    let j = NUM_LEDS - j;
                    leds[(x + j) % NUM_LEDS] = ws2812::Color::new(
                        (255usize / mul) as u8,
                        (255usize / mul) as u8,
                        (255usize / mul) as u8,
                    );
                }
                x = (x + 1) % NUM_LEDS;
            }
            WifiStatus::WifiConnecting => {
                for j in 0..NUM_LEDS {
                    let mul = 2usize.pow(j as u32);
                    let j = NUM_LEDS - j;
                    leds[(x + j) % NUM_LEDS] =
                        ws2812::Color::new((255usize / mul) as u8, 0, (255usize / mul) as u8);
                }
                x = (x + 1) % NUM_LEDS;
            }
            WifiStatus::WifiConnected => match dtls_status {
                DTLSStatus::Startup => {
                    for j in 0..NUM_LEDS {
                        let mul = 2usize.pow(j as u32);
                        let j = NUM_LEDS - j;
                        leds[(x + j) % NUM_LEDS] =
                            ws2812::Color::new((255usize / mul) as u8, (255usize / mul) as u8, 0);
                    }
                    x = (x + 1) % NUM_LEDS;
                }
                DTLSStatus::DTLSConnecting => {
                    for j in 0..NUM_LEDS {
                        let mul = 2usize.pow(j as u32);
                        let j = NUM_LEDS - j;
                        leds[(x + j) % NUM_LEDS] =
                            ws2812::Color::new(0, (255usize / mul) as u8, (255usize / mul) as u8);
                    }
                    x = (x + 1) % NUM_LEDS;
                }
                DTLSStatus::DTLSConnected => match vas_status {
                    VASStatus::Startup => {
                        for j in 0..NUM_LEDS {
                            let mul = 2usize.pow(j as u32);
                            let j = NUM_LEDS - j;
                            leds[(x + j) % NUM_LEDS] =
                                ws2812::Color::new(0, 0, (255usize / mul) as u8);
                        }
                        x = (x + 1) % NUM_LEDS;
                    }
                    VASStatus::Polling => {
                        let mut v = (5 * y) % 511;
                        if v > 255 {
                            v = 511 - v;
                        }
                        for j in 0..NUM_LEDS {
                            leds[j] = ws2812::Color::new(0, 0, v as u8);
                        }
                        y = (y + 1) % 102;
                    }
                    VASStatus::Communicating => {
                        for j in 0..NUM_LEDS {
                            let mul = 2usize.pow(j as u32);
                            let j = NUM_LEDS - j;
                            leds[(x + j) % NUM_LEDS] =
                                ws2812::Color::new(0, (255usize / mul) as u8, 0);
                        }
                        x = (x + 1) % NUM_LEDS;
                    }
                    VASStatus::Done => {
                        let mut v = (15 * y) % 511;
                        if v > 255 {
                            v = 511 - v;
                        }
                        for j in 0..NUM_LEDS {
                            leds[j] = ws2812::Color::new(0, v as u8, 0);
                        }
                        y = (y + 1) % 102;
                    }
                    VASStatus::Error => {
                        let mut v = (15 * y) % 511;
                        if v > 255 {
                            v = 511 - v;
                        }
                        for j in 0..NUM_LEDS {
                            leds[j] = ws2812::Color::new(v as u8, 0, 0);
                        }
                        y = (y + 1) % 102;
                    }
                },
            },
        }

        ws2812.write(&leds).await.unwrap();
        embassy_time::Timer::after_millis(40).await;
    }
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
struct Srv {
    priority: u16,
    weight: u16,
    port: u16,
    target: alloc::string::String,
}

#[embassy_executor::task]
async fn net(interfaces: esp_wifi::wifi::Interfaces<'static>) {
    let mut status_sender = DTLS_STATUS.sender();
    let mut client_sender = COAP_CLIENT.sender();
    static STACK_RESOURCES: static_cell::StaticCell<embassy_net::StackResources<3>> =
        static_cell::StaticCell::new();
    let spawner = embassy_executor::Spawner::for_current_executor().await;

    let mut rng = unsafe { init::RAND.assume_init_ref().clone() };
    let stack_resources = STACK_RESOURCES.init(embassy_net::StackResources::new());

    let mac = interfaces.sta.mac_address();
    let ll_addr = embassy_net::Ipv6Address::new(
        0xfe80,
        0x0000,
        0x0000,
        0x0000,
        ((mac[0] as u16 ^ 0x02) << 8) | mac[1] as u16,
        ((mac[2] as u16) << 8) | 0xff,
        (0xfe << 8) | mac[3] as u16,
        ((mac[4] as u16) << 8) | mac[5] as u16,
    );
    let config = embassy_net::Config::ipv6_static(embassy_net::StaticConfigV6 {
        address: embassy_net::Ipv6Cidr::new(ll_addr, 64),
        gateway: None,
        dns_servers: heapless::Vec::new(),
    });

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;
    let (stack, runner) = embassy_net::new(interfaces.sta, config, stack_resources, seed);

    spawner.spawn(net::net_task(runner)).ok();

    let mut ctx = tls::Context::new(tls::Method::dtls13_client());
    let lt_identity = LT_IDENTITY.try_get().unwrap();
    let lt_private_asn1 = lt_identity.private_asn1();
    let lt_public_asn1 = lt_identity.public_key().public_asn1();
    ctx.set_certificate(&lt_public_asn1).unwrap();
    ctx.set_private_key(&lt_private_asn1).unwrap();
    ctx.set_verify_none(); // TODO: verify server identity

    loop {
        status_sender.send(DTLSStatus::Startup);
        stack.wait_link_up().await;
        info!("Link up");

        let server = mdns::get_server(stack.clone()).await;
        status_sender.send(DTLSStatus::DTLSConnecting);
        info!("Connecting to {}", server);

        let mut rx_metadata = [embassy_net::udp::PacketMetadata::EMPTY; 4];
        let mut rx_buffer = [0; 1500];
        let mut tx_metadata = [embassy_net::udp::PacketMetadata::EMPTY; 4];
        let mut tx_buffer = [0; 1500];
        let mut socket = embassy_net::udp::UdpSocket::new(
            stack.clone(),
            &mut rx_metadata,
            &mut rx_buffer,
            &mut tx_metadata,
            &mut tx_buffer,
        );
        socket.bind(0).unwrap();

        let mut conn = ctx.connection(socket, server);
        if let Err(e) = conn.connect().await {
            warn!("Error establishing TLS connection: {:?}", e);
            continue;
        }
        status_sender.send(DTLSStatus::DTLSConnected);

        let mut coap_connection = coap::CoAPConnection::new(conn);
        let coap_client = coap::CoAPClient::new(coap_connection.handle()).await;
        client_sender.send(coap_client);
        if let Err(e) = coap_connection.run().await {
            warn!("Connection error: {:?}", e);
        }
    }
}

