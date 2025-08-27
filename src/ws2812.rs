use core::mem::MaybeUninit;
use embassy_futures::select::Either;
use esp_hal::{handler, system};
use esp_hal::rmt::ChannelInternal;
use esp_hal::rmt::{TxChannelCreator, TxChannelInternal};
use esp_hal::system::GenericPeripheralGuard;

struct Ws2812Esp32RmtItemEncoder {
    bit0: u32,
    bit1: u32,
}

impl Ws2812Esp32RmtItemEncoder {
    fn new(clock_hz: esp_hal::time::Rate) -> Self {
        let t0h = clock_hz.as_hz() as u64 / (1000000000u64 / 400u64);
        let t0l = clock_hz.as_hz() as u64 / (1000000000u64 / 850u64);
        let t1h = clock_hz.as_hz() as u64 / (1000000000u64 / 800u64);
        let t1l = clock_hz.as_hz() as u64 / (1000000000u64 / 450u64);
        let (bit0, bit1) = (
            esp_hal::rmt::PulseCode::new(esp_hal::gpio::Level::High, t0h as u16, esp_hal::gpio::Level::Low, t0l as u16),
            esp_hal::rmt::PulseCode::new(esp_hal::gpio::Level::High, t1h as u16, esp_hal::gpio::Level::Low, t1l as u16),
        );

        Self { bit0, bit1 }
    }

    #[inline]
    fn encode_iter<I: Iterator<Item = u8>>(&self, src: I) -> alloc::vec::Vec<u32> {
        let mut out = vec![];
        for b in src {
            out.extend((0..(u8::BITS as usize)).map(move |i| {
                if b & (1 << (7 - i)) != 0 {
                    self.bit1
                } else {
                    self.bit0
                }
            }))
        }
        out.push(esp_hal::rmt::PulseCode::empty());
        out
    }
}

#[derive(Debug)]
struct State {
    channel: esp_hal::rmt::ConstChannelAccess<esp_hal::rmt::Tx, 0>,
    buffer: alloc::vec::Vec<u32>,
    offset: usize,
    half: usize,
    _guard: GenericPeripheralGuard<{ system::Peripheral::Rmt as u8 }>,
}

static mut STATE: MaybeUninit<State> = MaybeUninit::uninit();
const MAX_PULSES: usize = 192;

use embassy_sync::signal::Signal;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::semaphore::Semaphore;

static COPY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

pub struct Ws2812Driver {
    encoder: Ws2812Esp32RmtItemEncoder,
}

impl Ws2812Driver {
    pub fn new<'a, P: Into<esp_hal::gpio::AnyPin<'a>> + esp_hal::gpio::OutputPin>(rmt: esp_hal::peripherals::RMT, pin: P) -> Result<Self, esp_hal::rmt::Error> {
        let clock = esp_hal::time::Rate::from_mhz(80);
        let mut rmt = esp_hal::rmt::Rmt::new(rmt, clock)?;
        rmt.set_interrupt_handler(interrupt_handler);

        let raw_channel = esp_hal::rmt::ChannelCreator::<esp_hal::Blocking, 0>::RAW;

        let pin = esp_hal::gpio::Output::new(
            pin.into(),
            esp_hal::gpio::Level::Low,
            esp_hal::gpio::OutputConfig::default(),
        );

        raw_channel.output_signal().connect_to(&pin);
        raw_channel.set_divider(1);
        raw_channel.set_tx_carrier(
            false,
            1,
            1,
            esp_hal::gpio::Level::Low,
        );
        raw_channel.set_tx_idle_output(false, esp_hal::gpio::Level::Low);
        raw_channel.set_memsize(unsafe { core::mem::transmute(6u8) });
        raw_channel.set_tx_threshold(MAX_PULSES as u8);

        let encoder = Ws2812Esp32RmtItemEncoder::new(clock);

        unsafe { STATE = MaybeUninit::new(State {
            channel: raw_channel,
            buffer: vec![],
            offset: 0,
            half: 0,
            _guard:  GenericPeripheralGuard::new(),
        }); }

        Ok(Self { encoder })
    }

    pub async fn write(&mut self, data: &[Color]) -> Result<(), esp_hal::rmt::Error> {
        let l = crate::IO_LOCK.acquire(1).await.unwrap();
        let state = unsafe { STATE.assume_init_mut() };

        state.channel.clear_tx_interrupts();
        state.channel.listen_tx_interrupt(esp_hal::rmt::Event::Error | esp_hal::rmt::Event::End | esp_hal::rmt::Event::Threshold);

        state.buffer = self.encoder.encode_iter(data.iter().flat_map(|c| {
            [c.g, c.r, c.b]
        }));
        state.half = 0;
        state.offset = state.channel.start_send(&state.buffer, false, 0)?;

        loop {
            match embassy_futures::select::select(COPY.wait(), DONE.wait()).await {
                Either::First(_) => {
                    state.copy()
                }
                Either::Second(_) => break
            }
        }

        drop(l);

        if state.channel.is_error() {
            Err(esp_hal::rmt::Error::TransmissionError)
        } else {
            Ok(())
        }
    }
}

impl State {
    fn copy(&mut self) {
        let ptr = self.channel.channel_ram_start();
        let len = core::cmp::min(self.buffer.len() - self.offset, MAX_PULSES);
        let offset = MAX_PULSES * self.half;
        self.half = if self.half == 0 { 1 } else { 0 };
        for i in 0..len {
            unsafe {
                ptr.add(i + offset).write_volatile(self.buffer[self.offset + i]);
            }
        }
        self.offset += len;
        for j in len..MAX_PULSES {
            unsafe {
                ptr.add(j + offset).write_volatile(0);
            }
        }
    }
}

#[handler]
fn interrupt_handler() {
    let state = unsafe { STATE.assume_init_mut() };

    if state.channel.is_tx_threshold_set() {
        COPY.signal(());
        state.channel.reset_tx_threshold_set();
    } else if state.channel.is_error() || state.channel.is_tx_done() {
        DONE.signal(());
        state.channel.unlisten_tx_interrupt(esp_hal::rmt::Event::Error | esp_hal::rmt::Event::End | esp_hal::rmt::Event::Threshold);
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct Color {
    r: u8,
    g: u8,
    b: u8,
}

impl Color {
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}