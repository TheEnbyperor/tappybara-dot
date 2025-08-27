use core::fmt::Write;

pub struct PrintlnLogger;
impl log::Log for PrintlnLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let level = match record.level() {
            log::Level::Error => b"\x1b[31mERROR\x1b[0m ",
            log::Level::Warn => b"\x1b[33mWARN\x1b[0m  ",
            log::Level::Info => b"\x1b[32mINFO\x1b[0m  ",
            log::Level::Debug => b"\x1b[36mDEBUG\x1b[0m ",
            log::Level::Trace => b"\x1b[36mTRACE\x1b[0m ",
        };
        let mut uart = embassy_futures::block_on(crate::UART_TX.lock());
        unsafe { uart.assume_init_mut() }.write(level).unwrap();
        unsafe { uart.assume_init_mut() }
            .write_fmt(*record.args())
            .unwrap();
        unsafe { uart.assume_init_mut() }.write_char('\n').unwrap();
        unsafe { uart.assume_init_mut() }.flush().unwrap();
    }

    fn flush(&self) {}
}

static LOGGER: PrintlnLogger = PrintlnLogger;

pub fn setup_logger() {
    let _ = log::set_logger(&LOGGER);
}

pub fn init_heap() {
    fn add_region<const N: usize>(region: &'static mut core::mem::MaybeUninit<[u8; N]>) {
        unsafe {
            esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
                region.as_mut_ptr() as *mut u8,
                N,
                esp_alloc::MemoryCapability::Internal.into(),
            ));
        }
    }

    // static mut HEAP1: core::mem::MaybeUninit<[u8; 60 * 1024]> = core::mem::MaybeUninit::uninit();
    #[link_section = ".dram2_uninit"]
    static mut HEAP2: core::mem::MaybeUninit<[u8; 96 * 1024]> = core::mem::MaybeUninit::uninit();

    // add_region(unsafe { &mut HEAP1 });
    add_region(unsafe { &mut HEAP2 });
}

struct Backtrace(heapless::Vec<BacktraceFrame, 10>);

impl Backtrace {
    /// Captures a stack backtrace.
    #[inline]
    pub fn capture() -> Self {
        let sp = sp();

        let mut result = Self(heapless::Vec::new());

        let mut fp = sp;

        if !is_valid_ram_address(fp) {
            return result;
        }

        while !result.0.is_full() {
            // RA/PC
            let address = unsafe { (fp as *const u32).offset(-4).read_volatile() };
            let address = remove_window_increment(address);
            // next FP
            fp = unsafe { (fp as *const u32).offset(-3).read_volatile() };

            // the return address is 0 but we sanitized the address - then 0 becomes
            // 0x40000000
            if address == 0x40000000 {
                break;
            }

            if !is_valid_ram_address(fp) {
                break;
            }

            _ = result.0.push(BacktraceFrame {
                pc: address as usize,
            });
        }

        result
    }

    /// Returns the backtrace frames as a slice.
    #[inline]
    pub fn frames(&self) -> &[BacktraceFrame] {
        &self.0
    }
}

#[inline(never)]
#[cold]
fn sp() -> u32 {
    let mut sp: u32;
    unsafe {
        core::arch::asm!(
        "mov {0}, a1",
        "add a12,a12,a12",
        "rotw 3",
        "add a12,a12,a12",
        "rotw 3",
        "add a12,a12,a12",
        "rotw 3",
        "add a12,a12,a12",
        "rotw 3",
        "add a12,a12,a12",
        "rotw 4",
        out(reg) sp
        );
    }

    // current frame pointer, caller's stack pointer
    unsafe { ((sp - 12) as *const u32).read_volatile() }
}

fn remove_window_increment(address: u32) -> u32 {
    (address & 0x3fff_ffff) | 0x4000_0000
}

fn is_valid_ram_address(address: u32) -> bool {
    if (address & 0xF) != 0 {
        return false;
    }

    if !(0x3FFA_E000..=0x4000_0000).contains(&address) {
        return false;
    }

    true
}

pub struct BacktraceFrame {
    pub(crate) pc: usize,
}

impl BacktraceFrame {
    pub fn program_counter(&self) -> usize {
        const RA_OFFSET: usize = 3;
        self.pc - RA_OFFSET
    }
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    error!("====================== PANIC ======================");
    error!("{}", info);
    error!("Backtrace:");

    let backtrace = Backtrace::capture();
    for frame in backtrace.frames() {
        error!("0x{:x}", frame.program_counter());
    }

    const OPTIONS0: *mut u32 = 0x3ff48000 as *mut u32;
    const SW_CPU_STALL: *mut u32 = 0x3ff480ac as *mut u32;

    unsafe {
        OPTIONS0.write_volatile(OPTIONS0.read_volatile() & !(0b1111) | 0b1010);
        SW_CPU_STALL.write_volatile(
            SW_CPU_STALL.read_volatile() & !(0b111111 << 20) & !(0b111111 << 26)
                | (0x21 << 20)
                | (0x21 << 26),
        );
    }

    loop {}
}
