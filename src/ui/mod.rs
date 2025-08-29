mod ws2812;

#[embassy_executor::task]
pub async fn lights() {
    let rmt = unsafe { esp_hal::peripherals::RMT::steal() };
    let light_pin = unsafe { esp_hal::peripherals::GPIO32::steal() };
    let mut ws2812 = ws2812::Ws2812Driver::new(rmt, light_pin).unwrap();

    const NUM_LEDS: usize = 24;
    let mut x: usize = 0;
    let mut y: usize = 0;
    let mut leds = [ws2812::Color::default(); NUM_LEDS];

    loop {
        let wifi_status = crate::WIFI_STATUS.try_get().unwrap_or(crate::WifiStatus::Startup);
        let dtls_status = crate::DTLS_STATUS.try_get().unwrap_or(crate::DTLSStatus::Startup);
        let vas_status = crate::VAS_STATUS.try_get().unwrap_or(crate::VASStatus::Startup);
        match wifi_status {
            crate::WifiStatus::Startup => {
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
            crate::WifiStatus::WifiConnecting => {
                for j in 0..NUM_LEDS {
                    let mul = 2usize.pow(j as u32);
                    let j = NUM_LEDS - j;
                    leds[(x + j) % NUM_LEDS] =
                        ws2812::Color::new((255usize / mul) as u8, 0, (255usize / mul) as u8);
                }
                x = (x + 1) % NUM_LEDS;
            }
            crate::WifiStatus::WifiConnected => match dtls_status {
                crate::DTLSStatus::Startup => {
                    for j in 0..NUM_LEDS {
                        let mul = 2usize.pow(j as u32);
                        let j = NUM_LEDS - j;
                        leds[(x + j) % NUM_LEDS] =
                            ws2812::Color::new((255usize / mul) as u8, (255usize / mul) as u8, 0);
                    }
                    x = (x + 1) % NUM_LEDS;
                }
                crate::DTLSStatus::DTLSConnecting => {
                    for j in 0..NUM_LEDS {
                        let mul = 2usize.pow(j as u32);
                        let j = NUM_LEDS - j;
                        leds[(x + j) % NUM_LEDS] =
                            ws2812::Color::new(0, (255usize / mul) as u8, (255usize / mul) as u8);
                    }
                    x = (x + 1) % NUM_LEDS;
                }
                crate::DTLSStatus::DTLSConnected => match vas_status {
                    crate::VASStatus::Startup => {
                        for j in 0..NUM_LEDS {
                            let mul = 2usize.pow(j as u32);
                            let j = NUM_LEDS - j;
                            leds[(x + j) % NUM_LEDS] =
                                ws2812::Color::new(0, (255usize / mul) as u8, 0);
                        }
                        x = (x + 1) % NUM_LEDS;
                    }
                    crate::VASStatus::Polling => {
                        let mut v = (5 * y) % 511;
                        if v > 255 {
                            v = 511 - v;
                        }
                        for j in 0..NUM_LEDS {
                            leds[j] = ws2812::Color::new(0, 0, v as u8);
                        }
                        y = (y + 1) % 102;
                    }
                    crate::VASStatus::Communicating => {
                        for j in 0..NUM_LEDS {
                            let mul = 2usize.pow(j as u32);
                            let j = NUM_LEDS - j;
                            leds[(x + j) % NUM_LEDS] =
                                ws2812::Color::new(0, 0, (255usize / mul) as u8);
                        }
                        x = (x + 1) % NUM_LEDS;
                    }
                    crate::VASStatus::Done => {
                        let mut v = (15 * y) % 511;
                        if v > 255 {
                            v = 511 - v;
                        }
                        for j in 0..NUM_LEDS {
                            leds[j] = ws2812::Color::new(0, v as u8, 0);
                        }
                        y = (y + 1) % 102;
                    }
                    crate::VASStatus::Error => {
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