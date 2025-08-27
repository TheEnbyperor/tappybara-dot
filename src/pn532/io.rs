use embassy_sync::semaphore::Semaphore;
use super::{types, Pn532Error};
use super::types::Pn532Command;

const PN532_I2C_ADDRESS: u8 = 0x48 >> 1;
const PN532_PREAMBLE: u8 = 0x00;
const PN532_START_CODE_1: u8 = 0x00;
const PN532_START_CODE_2: u8 = 0xFF;
const PN532_POSTAMBLE: u8 = 0x00;
const PN532_HOST_TO_PN532: u8 = 0xD4;
const PN532_PN532_TO_HOST: u8 = 0xD5;

pub static COMMANDS: embassy_sync::channel::Channel<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, Command, 1
> = embassy_sync::channel::Channel::new();

pub static RESPONSE: embassy_sync::channel::Channel<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, Result<alloc::vec::Vec<u8>, Pn532Error>, 1
> = embassy_sync::channel::Channel::new();

pub struct Command {
    pub command: Pn532Command,
    pub timeout: embassy_time::Duration,
}

struct I2CRead<'a> {
    transaction: esp_hal::i2c::master::Transaction<'a>,
    buf: alloc::vec::Vec<u8>,
    start: bool,
    end: bool,
}

impl<'a> I2CRead<'a> {
    fn new(t: esp_hal::i2c::master::Transaction<'a>) -> Self {
        Self {
            transaction: t,
            buf: alloc::vec::Vec::new(),
            start: true,
            end: false,
        }
    }

    async fn read_next(&mut self, count: usize) -> Result<(), esp_hal::i2c::master::Error> {
        let mut buf = vec![0u8; count];
        self.transaction.read(&mut buf, self.start, self.end, !self.end).await?;
        self.buf.extend(buf);
        self.start = false;
        Ok(())
    }

    async fn read_until(&mut self, index: usize) -> Result<(), esp_hal::i2c::master::Error> {
        if index >= self.buf.len() || self.end {
            let to_read = core::cmp::max(2, index - self.buf.len());
            self.read_next(to_read).await?;
        }
        Ok(())
    }

    async fn val(&mut self, index: usize) -> Result<u8, esp_hal::i2c::master::Error> {
        self.read_until(index).await?;
        Ok(self.buf[index])
    }

    async fn buf(&mut self, index: usize, buf: &mut [u8]) -> Result<(), esp_hal::i2c::master::Error> {
        let read_until_index = index + buf.len();
        self.read_until(read_until_index).await?;
        for (i, v) in self.buf[index..read_until_index].iter().enumerate() {
            buf[i] = *v;
        }
        Ok(())
    }

    fn end(&mut self) {
        self.end = true;
    }
}

struct Pn532Io<'a> {
    i2c: esp_hal::i2c::master::I2c<'a, esp_hal::Async>,
    irq: esp_hal::gpio::Input<'a>,
    rst: esp_hal::gpio::Output<'a>,
}

impl<'a> Pn532Io<'a> {
    fn new<I: Into<esp_hal::gpio::AnyPin<'a>>, R: Into<esp_hal::gpio::AnyPin<'a>>>(
        i2c: esp_hal::i2c::master::I2c<'a, esp_hal::Async>,
        irq_pin: I,
        rst_pin: R,
    ) -> Self {
        let irq = esp_hal::gpio::Input::new(
            irq_pin.into(),
            esp_hal::gpio::InputConfig::default().with_pull(esp_hal::gpio::Pull::Up),
        );
        let rst = esp_hal::gpio::Output::new(
            rst_pin.into(),
            esp_hal::gpio::Level::High,
            esp_hal::gpio::OutputConfig::default().with_pull(esp_hal::gpio::Pull::Up),
        );
        Self { i2c, irq, rst }
    }

    async fn reset(&mut self) {
        self.rst.set_high();
        embassy_time::Timer::after_millis(100).await;
        self.rst.set_low();
        embassy_time::Timer::after_millis(400).await;
        self.rst.set_high();
        embassy_time::Timer::after_millis(10).await;
    }

    async fn write_command(&mut self, command: types::Pn532Command) -> Result<(), Pn532Error> {
        let mut checksum: u8 = PN532_PREAMBLE
            .wrapping_add(PN532_START_CODE_1)
            .wrapping_add(PN532_START_CODE_2)
            .wrapping_add(PN532_HOST_TO_PN532)
            .wrapping_add(command.command);

        let data_len = (command.data.len() + 2) as u16;

        let mut output = if data_len <= 255 {
            vec![
                PN532_PREAMBLE,
                PN532_START_CODE_1,
                PN532_START_CODE_2,
                data_len as u8,
                (!(data_len as u8)).wrapping_add(1),
                PN532_HOST_TO_PN532,
                command.command,
            ]
        } else {
            vec![
                PN532_PREAMBLE,
                PN532_START_CODE_1,
                PN532_START_CODE_2,
                0xFF,
                0xFF,
                (data_len >> 8) as u8,
                (data_len & 0xFF) as u8,
                (!(((data_len >> 8) + (data_len & 0xFF)) as u8)).wrapping_add(1),
                PN532_HOST_TO_PN532,
                command.command,
            ]
        };

        output.extend(&command.data);
        for v in command.data {
            checksum = checksum.wrapping_add(v);
        }

        output.push(!checksum);
        output.push(PN532_POSTAMBLE);

        let l = crate::IO_LOCK.acquire(1).await.unwrap();
        trace!("sending: {:02X?}", output.as_slice());
        self.i2c
            .write_async(PN532_I2C_ADDRESS, output.as_slice())
            .await?;
        drop(l);

        Ok(())
    }

    async fn read_packet(&mut self) -> Result<types::Pn532Packet, Pn532Error> {
        let l = crate::IO_LOCK.acquire(1).await.unwrap();
        let res = self.i2c.transaction_async_cb(PN532_I2C_ADDRESS, async move |t| {
            let mut read = I2CRead::new(t);
            if read.val(0).await? != 0x01 {
                return Err(Pn532Error::Protocol);
            }
            let mut i = 1;
            while !(read.val(i).await? == 0x00 && read.val(i + 1).await? == 0xFF) {
                i += 1;
            }
            i += 2;
            let (b1, b2) = (read.val(i).await?, read.val(i + 1).await?);
            i += 2;
            let packet = if b1 == 0x00 && b2 == 0xFF {
                types::Pn532Packet::Ack
            } else if b1 == 0xFF && b2 == 0x00 {
                types::Pn532Packet::Nack
            } else {
                let len = b1;
                let len_chk = b2;
                if len_chk.wrapping_add(len) != 0 {
                    return Err(Pn532Error::Protocol);
                }
                read.read_until(i + len as usize + 1).await?;
                let mut data = vec![0u8; len as usize];
                read.buf(i, &mut data).await?;
                i += len as usize;
                let mut data_chk = read.val(i).await?;
                for v in &data {
                    data_chk = data_chk.wrapping_add(*v);
                }
                if data_chk != 0 {
                    return Err(Pn532Error::Protocol);
                }
                i += 1;
                if data.len() < 2 {
                    return Err(Pn532Error::Protocol);
                }
                if data[0] != PN532_PN532_TO_HOST {
                    return Err(Pn532Error::Protocol);
                }
                types::Pn532Packet::Data(types::Pn532Command {
                    command: data[1],
                    data: data[2..].to_vec(),
                })
            };
            read.end();
            if read.val(i).await? != 0x00 {
                return Err(Pn532Error::Protocol);
            }
            Ok(packet)
        }).await;
        drop(l);
        res
    }

    async fn wait_for_ready(&mut self, timeout: embassy_time::Duration) -> Result<(), Pn532Error> {
        let l = crate::IO_LOCK.acquire(1).await.unwrap();
        if self.irq.is_low() {
            return Ok(());
        }
        let r = match embassy_futures::select::select(
            self.irq.wait_for_low(),
            embassy_time::Timer::after(timeout),
        )
            .await
        {
            embassy_futures::select::Either::First(_) => Ok(()),
            embassy_futures::select::Either::Second(_) => Err(Pn532Error::Timeout),
        };
        drop(l);
        r
    }

    async fn read_ack(&mut self) -> Result<(), Pn532Error> {
        if !matches!(self.read_packet().await?, types::Pn532Packet::Ack) {
            return Err(Pn532Error::Ack);
        }
        Ok(())
    }

    async fn send_command(
        &mut self,
        command: Pn532Command,
        timeout: embassy_time::Duration,
    ) -> Result<(), Pn532Error> {
        trace!("writing command: {:02X?}", command);
        self.write_command(command).await?;
        trace!("waiting for ready");
        self.wait_for_ready(timeout).await.map_err(|e| match e {
            Pn532Error::Timeout => Pn532Error::AckTimeout,
            o => o,
        })?;
        trace!("reading ack");
        self.read_ack().await?;
        Ok(())
    }

    async fn execute_command(
        &mut self,
        command: Pn532Command,
        timeout: embassy_time::Duration,
    ) -> Result<alloc::vec::Vec<u8>, Pn532Error> {
        let expected_response_command = command.command + 1;
        self.send_command(command, embassy_time::Duration::from_millis(100))
            .await?;
        trace!("waiting for ready");
        self.wait_for_ready(timeout).await?;
        embassy_time::Timer::after_millis(10).await;
        let resp = self.read_packet().await?;
        trace!("response: {:02X?}", resp);
        let resp = match resp {
            types::Pn532Packet::Data(data) => data,
            _ => return Err(Pn532Error::Protocol),
        };
        if resp.command != expected_response_command {
            return Err(Pn532Error::Protocol);
        }
        Ok(resp.data)
    }
}

#[embassy_executor::task]
pub async fn io() {
    let i2c = unsafe { esp_hal::peripherals::I2C0::steal() };
    let sda_pin = unsafe { esp_hal::peripherals::GPIO21::steal() };
    let scl_pin = unsafe { esp_hal::peripherals::GPIO22::steal() };
    let irq_pin = unsafe { esp_hal::peripherals::GPIO16::steal() };
    let rst_pin = unsafe { esp_hal::peripherals::GPIO25::steal() };

    let i2c_config = esp_hal::i2c::master::Config::default()
        .with_frequency(esp_hal::time::Rate::from_khz(400))
        .with_timeout(esp_hal::i2c::master::BusTimeout::Maximum);
    let i2c = esp_hal::i2c::master::I2c::new(i2c, i2c_config)
        .unwrap()
        .with_sda(sda_pin)
        .with_scl(scl_pin)
        .into_async();

    let mut pn532 = Pn532Io::new(i2c, irq_pin, rst_pin);

    pn532.reset().await;

    loop {
        let command = COMMANDS.receive().await;
        RESPONSE.send(pn532.execute_command(command.command, command.timeout).await).await;
    }
}