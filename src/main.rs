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
mod net;
mod pn532;
mod storage;
mod util;
mod vas;
mod ui;
mod crypto;

mod asn {
    include!(concat!(env!("OUT_DIR"), "/asn.rs"));
}

use alloc::string::ToString;
use core::mem::MaybeUninit;
use esp_alloc as _;

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

pub static AES: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    MaybeUninit<esp_hal::aes::Aes>,
> = embassy_sync::mutex::Mutex::new(MaybeUninit::uninit());

pub static UART_TX: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    MaybeUninit<esp_hal::uart::UartTx<esp_hal::Blocking>>,
> = embassy_sync::mutex::Mutex::new(MaybeUninit::uninit());

pub struct Fs(
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
    0,
> = embassy_sync::watch::Watch::new();

pub static COAP_CLIENT: embassy_sync::watch::Watch<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    net::coap::CoAPClient,
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

#[derive(Debug)]
struct VASConfig {
    apple_config: Option<alloc::sync::Arc<vas::apple::TerminalConfig>>,
    google_config: Option<alloc::sync::Arc<vas::google::TerminalConfig>>
}

async fn map_reader_config(config: asn::tappybara::ReaderConfig) -> VASConfig {
    VASConfig {
        apple_config: match config.apple_vasconfig {
            Some(c) => {
                let mut passes = vec![];
                for p in c.passes.into_iter() {
                    let pass_id = p.pass_id.to_string();
                    let pass_id_hash = crypto::sha256(pass_id.as_bytes()).await;
                    let mut keys = vec![];
                    if let Some(pk) = p.private_keys {
                        for k in pk.0.into_iter() {
                            let private_key = ecc::PrivateKey::from_bytes(k.0.as_ref().try_into().unwrap());
                            let key_id = crypto::sha256(&private_key.public_key().x()).await;
                            keys.push(vas::apple::Key {
                                key_id: (&key_id[0..4]).try_into().unwrap(),
                                key: private_key
                            })
                        }
                    }
                    passes.push(vas::apple::PassConfig {
                        pass_id,
                        pass_id_hash,
                        keys: alloc::sync::Arc::new(keys),
                    })
                }
                Some(alloc::sync::Arc::new(vas::apple::TerminalConfig {
                    passes,
                }))
            },
            None => None
        },
        google_config: config.google_smart_tap_config.map(|c| {
            alloc::sync::Arc::new(vas::google::TerminalConfig {
                collector_id: c.collector_id,
                key_version: c.collector_key_version,
                private_key: ecc::PrivateKey::from_bytes(c.collector_private_key.as_ref().try_into().unwrap()),
                services: c.services.0.into_iter().map(|v| v.0).collect(),
                store_location_id: c.store_location_id.and_then(|i| i.try_into().ok()),
                merchant_name: c.merchant_name,
                merchant_category_code: c.mcc,
            })
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

    'outer: loop {
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
                embassy_time::Timer::after_secs(3).await;
                continue 'outer;
            }
        };
        drop(coap_client);
        let Some(config) = parse_config_response(config_resp) else {
            status_sender.send(VASStatus::Error);
            continue 'outer;
        };
        let mut reader_config = map_reader_config(config).await;
        info!("Reader config: {:?}", reader_config);

        let ecp = &[0x6A, 0x01, 0x00, 0x00, 0x02];
        'main: loop {
            let google_reader_ephemeral_key = ecc::PrivateKey::new();
            status_sender.send(VASStatus::Polling);
            let target = if let Some(observer) = config_observe.as_mut() {
                loop {
                    if observer.has_next() {
                        let resp = observer.next().await;
                        match resp {
                            Ok(Some(resp)) => match parse_config_response(resp) {
                                Some(new_config) => {
                                    reader_config = map_reader_config(new_config).await;
                                    info!("New reader config: {:?}", reader_config);
                                },
                                None => {
                                    error!("Error getting VAS config: observe empty");
                                    status_sender.send(VASStatus::Error);
                                    continue 'outer;
                                }
                            },
                            Ok(None) => {
                                config_observe = None;
                            }
                            Err(e) => {
                                error!("Error getting VAS config: {:?}", e);
                                status_sender.send(VASStatus::Error);
                                continue 'outer;
                            }
                        }
                        continue 'main;
                    }
                    if let Some(target) = pn532::poll_target(&[pn532::types::Pn532PollType::Iso14443TypeA], Some(ecp)).await.transpose() {
                        break target;
                    }
                    embassy_time::Timer::after_millis(50).await;
                }
            } else {
                pn532::poll_target_loop(&[pn532::types::Pn532PollType::Iso14443TypeA], Some(ecp)).await
            };
            match async {
                // Sometimes the polling loop goes a little fucky
                if let Err(pn532::Pn532Error::Protocol) = &target {
                    return Ok(None);
                }
                let target = target?;
                info!("Got target: {:02X?}", target);
                status_sender.send(VASStatus::Communicating);

                let mut target = match &target.target {
                    pn532::types::Pn532TargetType::Iso14443TypeA(_) => {
                        pn532::iso_dep::IsoDep::new_type_a().await?
                    }
                    _ => unreachable!(),
                };

                let res: Result<Option<vas::ResultData>, vas::VasError> = (async || {
                    let mut client = vas::VasClient::new(&mut target);
                    let imp = client.get_client().await?;
                    debug!("Implementation: {:02X?}", imp);
                    match imp {
                        vas::Implementation::Apple(fci) => {
                            let Some(apple_config) = reader_config.apple_config.as_ref() else {
                                return Err(vas::VasError::CommunicationError("No Apple config"));
                            };
                            let mut apple_client = vas::apple::Client::new(&mut target, fci, apple_config.clone());
                            let res = apple_client.do_exchange().await?;
                            debug!("Apple result: {:?}", res);
                            Ok(Some(vas::ResultData::Apple(res)))
                        }
                        vas::Implementation::Google(fci) => {
                            let Some(google_config) = reader_config.google_config.as_ref() else {
                                return Err(vas::VasError::CommunicationError("No Google config"));
                            };
                            let mut google_client = vas::google::Client::new(&mut target, fci, google_config.clone()).await;
                            let res = google_client.do_exchange(google_reader_ephemeral_key).await?;
                            debug!("Google result: {:02X?}", res);
                            match res {
                                vas::google::SmartTapResult::Success(d) => Ok(Some(vas::ResultData::Google(d))),
                                _ => Ok(None),
                            }
                        }
                    }
                })()
                    .await;

                target.deselect().await?;
                debug!("Deselected target");

                res
            }
                .await
            {
                Ok(res) => {
                    if let Some(res) = res {
                        if handle_response(res).await {
                            status_sender.send(VASStatus::Done);
                        } else {
                            status_sender.send(VASStatus::Error);
                        }
                    }
                }
                Err(e) => {
                    warn!("{:?}", e);
                    status_sender.send(VASStatus::Error);
                }
            }
            embassy_time::Timer::after_secs(3).await;
        }
    }
}

async fn handle_response(res: vas::ResultData) -> bool {
    let to_submit = match res {
        vas::ResultData::Apple(res) => {
            let mut passes = vec![];
            for p in res.results {
                if let vas::apple::VASResultType::Success(s) = p.result {
                    let data = match s.try_decrypt().await {
                        Some(d) => crate::asn::tappybara::AppleVASPassDataData::decrypted(
                            crate::asn::tappybara::AppleVASDecryptedData {
                                timestamp: d.timestamp.into(),
                                payload: d.payload.into(),
                            }
                        ),
                        None => crate::asn::tappybara::AppleVASPassDataData::encrypted(
                            crate::asn::tappybara::AppleVASEncryptedData {
                                key_id: s.device_key_id.into(),
                                device_public_key: s.device_public_key.public_compressed_point().into(),
                                encrypted_data: s.encrypted_data.into(),
                            }
                        )
                    };
                    passes.push(crate::asn::tappybara::AppleVASPassData {
                        pass_id: rasn::types::Ia5String::try_from(p.pass_id).unwrap(),
                        data
                    });
                }
            }

            if passes.is_empty() {
                return true;
            }

            crate::asn::tappybara::TapData {
                redemption: crate::asn::tappybara::TapDataRedemption::appleVas(
                    crate::asn::tappybara::AppleVASData {
                        passes,
                    }
                )
            }
        },
        vas::ResultData::Google(res) => {
            let data = if res.is_encrypted() {
                match res.decrypt_data().await {
                    Some(d) => alloc::borrow::Cow::Owned(d),
                    None => return false,
                }
            } else {
                alloc::borrow::Cow::Borrowed(res.raw_data())
            };

            let data = if res.is_compressed() {
                let version = libz_rs_sys::zlibVersion();
                let mut strm = libz_rs_sys::z_stream::default();
                let stream_size = size_of_val(&strm) as i32;
                let err = unsafe { libz_rs_sys::inflateInit_(&mut strm, version, stream_size) };
                if err != libz_rs_sys::Z_OK {
                    warn!("libz_rs_sys::inflateInit_ failed with status {}", err);
                    return false;
                }
                strm.avail_in = data.len() as _;
                strm.next_in = data.as_ptr();
                let mut output = vec![0u8; data.len() * 4];
                strm.avail_out = output.len() as _;
                strm.next_out = output.as_mut_ptr();
                let err = unsafe { libz_rs_sys::inflate(&mut strm, libz_rs_sys::Z_FINISH) };
                if err != libz_rs_sys::Z_STREAM_END {
                    warn!("libz_rs_sys::inflate failed with status {}", err);
                    return false;
                }
                let err = unsafe { libz_rs_sys::inflateEnd(&mut strm) };
                if err != libz_rs_sys::Z_OK {
                    warn!("libz_rs_sys::inflateEnd failed with status {}", err);
                }
                output.truncate(strm.total_out as usize);
                alloc::borrow::Cow::Owned(output)
            } else {
                data
            };

            debug!("Google data: {:02X?}", data);

            let data = match vas::google::ServiceData::decode(&data) {
                Ok(d) => d,
                Err(e) => {
                    warn!("Failed to decode Google service data: {:?}", e);
                    return false;
                }
            };

            debug!("Google data: {:02X?}", data);

            crate::asn::tappybara::TapData {
                redemption: crate::asn::tappybara::TapDataRedemption::googleSmartTap(
                    crate::asn::tappybara::GoogleSmartTapData {
                        service_values: data.records.into_iter().map(|v| {
                            crate::asn::tappybara::GoogleSmartTapServiceValue {
                                issuer: crate::asn::tappybara::GoogleSmartTapServiceIssuer {
                                    issuer_type: match v.issuer.issuer_type {
                                        vas::google::IssuerType::Unspecified => crate::asn::tappybara::GoogleSmartTapServiceIssuerIssuerType::unknown,
                                        vas::google::IssuerType::Merchant => crate::asn::tappybara::GoogleSmartTapServiceIssuerIssuerType::merchant,
                                        vas::google::IssuerType::Wallet => crate::asn::tappybara::GoogleSmartTapServiceIssuerIssuerType::wallet,
                                        vas::google::IssuerType::Manufacturer => crate::asn::tappybara::GoogleSmartTapServiceIssuerIssuerType::manufacturer,
                                    },
                                    issuer_id: rasn::types::Integer::from(v.issuer.issuer_id)
                                },
                                records: crate::asn::tappybara::GoogleSmartTapServiceValueRecords(v.objects.into_iter().map(|o| {
                                    match o {
                                        vas::google::Object::Customer(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::customer(
                                                crate::asn::tappybara::GoogleSmartTapCustomerRecord {
                                                    customer_id: c.customer_id.as_ref().into(),
                                                    preferred_language: c.preferred_language_code.as_ref().map(|t| t.as_ref().into()),
                                                    unique_device_id: c.unique_device_id.as_ref().map(|t| t.as_ref().into()),
                                                    unique_tap_id: c.unique_tap_id.as_ref().map(|t| t.as_ref().into()),
                                                }
                                            )
                                        }
                                        vas::google::Object::Loyalty(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::loyalty(
                                                crate::asn::tappybara::GoogleSmartTapLoyaltyRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                    track1: c.track1.as_ref().map(|t| t.as_ref().into()),
                                                    track2: c.track2.as_ref().map(|t| t.as_ref().into()),
                                                }
                                            )
                                        }
                                        vas::google::Object::Offer(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::offer(
                                                crate::asn::tappybara::GoogleSmartTapBasePassRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                }
                                            )
                                        }
                                        vas::google::Object::GiftCard(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::giftCard(
                                                crate::asn::tappybara::GoogleSmartTapGiftCardRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                    pin: c.pin.as_ref().map(|t| t.as_ref().into()),
                                                    track1: c.track1.as_ref().map(|t| t.as_ref().into()),
                                                    track2: c.track2.as_ref().map(|t| t.as_ref().into()),
                                                }
                                            )
                                        }
                                        vas::google::Object::PLC(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::privateLabelCard(
                                                crate::asn::tappybara::GoogleSmartTapPrivateLabelCardRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.pan.as_ref().into(),
                                                    expiration: c.expiration.as_ref().map(|t| t.as_ref().into()),
                                                    cvc1: c.cvc1.as_ref().map(|t| t.as_ref().into()),
                                                    track1: c.track1.as_ref().map(|t| t.as_ref().into()),
                                                    track2: c.track2.as_ref().map(|t| t.as_ref().into()),
                                                }
                                            )
                                        }
                                        vas::google::Object::EventTicket(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::eventTicket(
                                                crate::asn::tappybara::GoogleSmartTapBasePassRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                }
                                            )
                                        }
                                        vas::google::Object::Flight(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::flight(
                                                crate::asn::tappybara::GoogleSmartTapBasePassRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                }
                                            )
                                        }
                                        vas::google::Object::Transit(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::transit(
                                                crate::asn::tappybara::GoogleSmartTapBasePassRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                }
                                            )
                                        }
                                        vas::google::Object::Generic(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::generic(
                                                crate::asn::tappybara::GoogleSmartTapBasePassRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                }
                                            )
                                        }
                                        vas::google::Object::GenericPrivate(c) => {
                                            crate::asn::tappybara::AnonymousGoogleSmartTapServiceValueRecords::genericPrivatePass(
                                                crate::asn::tappybara::GoogleSmartTapBasePassRecord {
                                                    object_id: c.object_id.as_ref().into(),
                                                    redemption_data: c.redemption_data.as_ref().into(),
                                                }
                                            )
                                        }
                                    }
                                }).collect()),
                            }
                        }).collect(),
                    }
                ),
            }
        }
    };

    let Some(coap_client) = COAP_CLIENT.try_get() else {
        warn!("No CoAP client available to submit tap");
        return false;
    };

    let mut data_request = coap_lite::CoapRequest::new();
    data_request.set_method(coap_lite::RequestType::Post);
    data_request.set_path("/tap");
    data_request.message.add_option_as(coap_lite::CoapOption::ContentFormat, coap_lite::option_value::OptionValueU16(65002));
    data_request.message.payload = rasn::uper::encode(&to_submit).unwrap();
    let coap_resp = match coap_client.send_request(data_request).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Error submitting tap: {:?}", e);
            return false;
        }
    };
    if coap_resp.get_status().is_error() {
        warn!("Error submitting tap: {:?}", coap_resp);
        return false;
    }

    true
}

#[embassy_executor::task]
async fn server_connection(interfaces: esp_wifi::wifi::Interfaces<'static>) {
    let status_sender = DTLS_STATUS.sender();
    let client_sender = COAP_CLIENT.sender();
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

    let mut ctx = net::tls::Context::new(net::tls::Method::dtls13_client());
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

        let server = net::mdns::get_server(stack.clone()).await;
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

        let mut coap_connection = net::coap::CoAPConnection::new(conn);
        let coap_client = net::coap::CoAPClient::new(coap_connection.handle()).await;
        client_sender.send(coap_client);
        if let Err(e) = coap_connection.run().await {
            warn!("Connection error: {:?}", e);
        }
    }
}

