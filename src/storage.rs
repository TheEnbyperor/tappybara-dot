pub struct LfsFlash<F>(pub F);

pub const PARTITION_LEN: usize = 0x50000;

impl<F: embedded_storage::nor_flash::NorFlash + embedded_storage::nor_flash::ReadNorFlash> littlefs2::driver::Storage for LfsFlash<F> {
    const READ_SIZE: usize = F::READ_SIZE;
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const BLOCK_SIZE: usize = F::ERASE_SIZE;
    const BLOCK_COUNT: usize = PARTITION_LEN / Self::BLOCK_SIZE;
    type CACHE_SIZE = littlefs2::consts::U32;
    type LOOKAHEAD_SIZE = littlefs2::consts::U1;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        match F::read(&mut self.0, off as u32, buf) {
            Ok(()) => Ok(buf.len()),
            Err(_) => Err(littlefs2::io::Error::IO)
        }
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        match F::write(&mut self.0, off as u32, data) {
            Ok(()) => Ok(data.len()),
            Err(_) => Err(littlefs2::io::Error::IO)
        }
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        match F::erase(&mut self.0, off as u32, (off + len) as u32) {
            Ok(()) => Ok(len),
            Err(_) => Err(littlefs2::io::Error::IO)
        }
    }
}