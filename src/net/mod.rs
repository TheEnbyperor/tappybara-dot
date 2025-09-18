pub mod mdns;
pub mod tls;
pub mod coap;

#[embassy_executor::task]
pub async fn wifi_connection(mut controller: esp_wifi::wifi::WifiController<'static>) {
    let status_sender = crate::WIFI_STATUS.sender();
    let scan_sender = crate::WIFI_SCAN.sender();
    let mut config_recv = crate::CONNECTION_CONFIG.receiver().unwrap();
    info!("Start WiFi connection task");

    let (mut client_config, mut has_ssid) = match config_recv.try_get() {
        Some(config) => map_config(config),
        _ => (esp_wifi::wifi::Configuration::Client(Default::default()), false)
    };
    controller.set_configuration(&client_config).unwrap();

    loop {
        if !controller.is_started().unwrap() {
            info!("Starting wifi");
            controller.start_async().await.unwrap();
        }

        info!("Wifi scan");
        let scan_config = esp_wifi::wifi::ScanConfig::default();
        let result = controller
            .scan_with_config_async(scan_config)
            .await
            .unwrap();
        scan_sender.send(result);

        if has_ssid {
            status_sender.send(crate::WifiStatus::WifiConnecting);
            debug!("About to connect: {:?}", client_config);

            match controller.connect_async().await {
                Ok(_) => {
                    info!("Wifi connected");
                    status_sender.send(crate::WifiStatus::WifiConnected);
                },
                Err(e) => {
                    warn!("Failed to connect to wifi: {:?}", e);
                    controller.stop_async().await.unwrap();
                    embassy_time::Timer::after_secs(1).await;
                    (client_config, has_ssid) = map_config(config_recv.get().await);
                    controller.set_configuration(&client_config).unwrap();
                    continue;
                }
            }

            match embassy_futures::select::select(
                controller.wait_for_event(esp_wifi::wifi::WifiEvent::StaDisconnected),
                config_recv.changed()
            ).await {
                embassy_futures::select::Either::First(_) => {
                    info!("Wifi disconnected");
                    status_sender.send(crate::WifiStatus::WifiConnecting);
                    controller.stop_async().await.unwrap();
                    embassy_time::Timer::after_secs(1).await;
                }
                embassy_futures::select::Either::Second(new_config) => {
                    if let Err(e) = controller.disconnect_async().await {
                        warn!("Failed to disconnect from WiFi: {:?}", e);
                    }
                    controller.stop_async().await.unwrap();
                    (client_config, has_ssid) = map_config(new_config);
                    controller.set_configuration(&client_config).unwrap();
                }
            }
        } else {
            match embassy_futures::select::select(
                embassy_time::Timer::after_secs(1),
                config_recv.changed()
            ).await {
                embassy_futures::select::Either::First(_) => {}
                embassy_futures::select::Either::Second(new_config) => {
                    controller.stop_async().await.unwrap();
                    (client_config, has_ssid) = map_config(new_config);
                    controller.set_configuration(&client_config).unwrap();
                }
            }
        }
    }
}

fn map_config(config: crate::asn::tappybara_config::ConnectionConfig) -> (esp_wifi::wifi::Configuration, bool) {
    if !config.networks.is_empty() {
        let network = &config.networks[0];
        if !network.ssid.is_empty() {
            return (esp_wifi::wifi::Configuration::Client(esp_wifi::wifi::ClientConfiguration {
                ssid: network.ssid.clone(),
                password: match &network.password {
                    Some(p) => p.into(),
                    None => "".into(),
                },
                auth_method: match network.auth_method {
                    crate::asn::tappybara_config::WifiAuthMethod::WPA2Personal => esp_wifi::wifi::AuthMethod::WPA2Personal,
                    crate::asn::tappybara_config::WifiAuthMethod::WPA3Personal => esp_wifi::wifi::AuthMethod::WPA3Personal,
                    crate::asn::tappybara_config::WifiAuthMethod::WPA2WPA3Personal => esp_wifi::wifi::AuthMethod::WPA2WPA3Personal,
                    crate::asn::tappybara_config::WifiAuthMethod::Open => esp_wifi::wifi::AuthMethod::None,
                },
                ..Default::default()
            }), true);
        }
    }

    (esp_wifi::wifi::Configuration::Client(Default::default()), false)
}

#[embassy_executor::task]
pub async fn net_task(mut runner: embassy_net::Runner<'static, esp_wifi::wifi::WifiDevice<'static>>) {
    runner.run().await
}
