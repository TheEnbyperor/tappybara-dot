use core::mem::MaybeUninit;
use embassy_executor::Spawner;
use embedded_storage::ReadStorage;
use esp_hal::interrupt;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::interrupt::Priority;
use esp_hal::peripherals::Interrupt;
use esp_hal_embassy::InterruptExecutor;
use rand_chacha::rand_core::SeedableRng;
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

static mut APP_CORE_STACK: esp_hal::system::Stack<8192> = esp_hal::system::Stack::new();
static mut APP_CORE_GUARD: Option<esp_hal::system::AppCoreGuard> = None;

pub static mut RAND: MaybeUninit<esp_hal::rng::Rng> = MaybeUninit::uninit();

static EXEC1: StaticCell<InterruptExecutor<1>> = StaticCell::new();
static UART_RX: StaticCell<esp_hal::uart::UartRx<esp_hal::Async>> = StaticCell::new();
static FLASH: StaticCell<esp_storage::FlashStorage> = StaticCell::new();
static LFS_PT: StaticCell<esp_bootloader_esp_idf::partitions::PartitionEntry> = StaticCell::new();
static LFS_STORAGE: StaticCell<crate::storage::LfsFlash<
    esp_bootloader_esp_idf::partitions::FlashRegion<esp_storage::FlashStorage>
>> = StaticCell::new();
static LFS_ALLOC: StaticCell<littlefs2::fs::Allocation<crate::storage::LfsFlash<
    esp_bootloader_esp_idf::partitions::FlashRegion<esp_storage::FlashStorage>
>>> = StaticCell::new();

static mut PT_MEM: [u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN] =
    [0u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    crate::WIFI_STATUS.sender().send(crate::WifiStatus::Startup);
    static ESP_RADIO_CTRL: StaticCell<esp_wifi::EspWifiController> = StaticCell::new();

    let hal_config = esp_hal::Config::default()
        .with_cpu_clock(esp_hal::clock::CpuClock::max());
    let peripherals = esp_hal::init(hal_config);

    let (uart_rx, uart_tx) = esp_hal::uart::Uart::new(peripherals.UART0, esp_hal::uart::Config::default())
        .unwrap()
        .with_rx(peripherals.GPIO3)
        .with_tx(peripherals.GPIO1)
        .split();
    let uart_rx = UART_RX.init(uart_rx.into_async());
    *crate::UART_TX.lock().await = MaybeUninit::new(uart_tx);

    crate::util::init_heap();
    crate::util::setup_logger();
    log::set_max_level(log::LevelFilter::Debug);

    let timg1 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init([timg1.timer0, timg1.timer1]);

    let swints = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let mut cpu_control = esp_hal::system::CpuControl::new(peripherals.CPU_CTRL);
    let guard = unsafe {
        cpu_control
            .start_app_core(&mut APP_CORE_STACK, move || {
                let exec1 = EXEC1.init(InterruptExecutor::new(swints.software_interrupt1));
                interrupt::enable(Interrupt::FROM_CPU_INTR1, Priority::Priority2).unwrap();
                let spawner = exec1.start(Priority::Priority2);

                spawner.must_spawn(crate::ui::lights());
                spawner.must_spawn(crate::pn532::io());

                loop { core::hint::spin_loop() }
            })
            .expect("Failed to start on core 1")
    };
    unsafe {
        APP_CORE_GUARD = Some(guard);
    }

    info!("Seeding RNG");
    let mut esp_rng = esp_hal::rng::Rng::new(peripherals.RNG);
    unsafe {
        RAND = MaybeUninit::new(esp_rng.clone());
    }
    let rng = rand_chacha::ChaCha12Rng::from_rng(&mut esp_rng);
    *crate::RAND.lock().await = MaybeUninit::new(rng);

    crate::ecc::init();
    crate::net::tls::init();

    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    let esp_radio_ctrl = ESP_RADIO_CTRL.init(esp_wifi::init(timg0.timer0, esp_rng.clone()).unwrap());
    let (wifi_controller, wifi_interfaces) = esp_wifi::wifi::new(esp_radio_ctrl, peripherals.WIFI).unwrap();

    let flash = FLASH.init(esp_storage::FlashStorage::new());
    info!("Flash size: {}", flash.capacity());

    let pt = unsafe {
        esp_bootloader_esp_idf::partitions::read_partition_table(flash, &mut PT_MEM).unwrap()
    };

    info!("=== Partition table ===");
    for i in 0..pt.len() {
        let raw = pt.get_partition(i).unwrap();
        info!("{:?}", raw);
    }

    let lfs = LFS_PT.init(pt
        .find_partition(esp_bootloader_esp_idf::partitions::PartitionType::Data(
            esp_bootloader_esp_idf::partitions::DataPartitionSubType::LittleFs,
        ))
        .unwrap()
        .unwrap());
    assert_eq!(lfs.len() as usize, crate::storage::PARTITION_LEN);
    let lfs_partition = lfs.as_embedded_storage(flash);

    let storage = LFS_STORAGE.init(crate::storage::LfsFlash(lfs_partition));
    let alloc = LFS_ALLOC.init(littlefs2::fs::Filesystem::allocate());
    let fs = littlefs2::fs::Filesystem::mount_or_else(alloc, storage, |_, s| {
        info!("Formatting filesystem");
        littlefs2::fs::Filesystem::format(s)
    }).unwrap();
    *crate::FS.0.lock().await = MaybeUninit::new(fs);
    info!("Filesystem mounted");

    crate::LT_IDENTITY.sender().send(crate::config::get_identity().await);

    info!("Loading connection config");
    if let Some(config) = crate::config::get_connection_config().await {
        crate::CONNECTION_CONFIG.sender().send(config);
    }

    let sha = esp_hal::sha::Sha::new(peripherals.SHA);
    *crate::SHA.lock().await = MaybeUninit::new(sha);

    let aes = esp_hal::aes::Aes::new(peripherals.AES);
    *crate::AES.lock().await = MaybeUninit::new(aes);

    spawner.must_spawn(crate::net::wifi_connection(wifi_controller));
    spawner.must_spawn(crate::server_connection(wifi_interfaces));
    spawner.must_spawn(crate::vas());
    spawner.must_spawn(crate::improv::improv(uart_rx));

    loop {
        embassy_time::Timer::after_secs(5).await;
    }
}
