use std::io;
use std::io::{Read, Result, Write};

use cryptovec::CryptoVec;

/// A clear-on-drop vector based on `CryptoVec`
///
/// This structure is designed for internal use only.
/// It may disappear/breaking change at any version.
#[derive(Debug, Default)]
pub struct SshBuffer {
    read_pos: usize,
    buf: CryptoVec,
}

impl SshBuffer {
    pub fn with_vec(v: CryptoVec) -> SshBuffer {
        SshBuffer {
            read_pos: 0,
            buf: v,
        }
    }
}

impl Read for SshBuffer {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.read_pos >= self.buf.len() {
            return Ok(0);
        }
        let n = self.buf.write_all_from(self.read_pos, buf)?;
        self.read_pos += n;
        Ok(n)
    }
}

impl Write for SshBuffer {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.buf.extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// [io::Read](https://doc.rust-lang.org/std/io/trait.Read.html) extension to read ssh data
pub trait SshReadExt {
    fn read_bool(&mut self) -> io::Result<bool>;
    fn read_uint8(&mut self) -> io::Result<u8>;
    fn read_uint32(&mut self) -> io::Result<u32>;
    fn read_uint64(&mut self) -> io::Result<u64>;
    fn read_string(&mut self) -> io::Result<Vec<u8>>;
    fn read_utf8(&mut self) -> io::Result<String>;
    fn read_mpint(&mut self) -> io::Result<Vec<u8>>;
}

impl<R: io::Read + ?Sized> SshReadExt for R {
    fn read_bool(&mut self) -> io::Result<bool> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }

    fn read_uint8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_uint32(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_uint64(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_uint32()? as usize;
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_utf8(&mut self) -> io::Result<String> {
        let bytes = self.read_string()?;
        match String::from_utf8(bytes) {
            Ok(s) => Ok(s),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }

    fn read_mpint(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = self.read_string()?;
        if buf.is_empty() {
            return Ok(vec![0]);
        }
        if buf[0] & 0x80 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "negative big number",
            ));
        }
        while buf.len() > 1 && buf[0] == 0 && buf[1] & 0x80 == 0 {
            buf.remove(0);
        }
        Ok(buf)
    }
}
