use std::io;
use std::io::{Read, Result, Write};
use std::str;

use zeroize::{Zeroize, Zeroizing};

use cryptovec::CryptoVec;

const MAX_BIGNUM: usize = 16384 / 8;

/// A clear-on-drop vector based on `CryptoVec`
///
/// This structure is designed for internal use only.
/// It may disappear/breaking change at any version.
#[derive(Debug, Default)]
pub struct SshBuf {
    read_pos: usize,
    buf: CryptoVec,
}

impl SshBuf {
    pub fn new() -> SshBuf {
        SshBuf {
            read_pos: 0,
            buf: CryptoVec::new(),
        }
    }

    pub fn with_vec(v: CryptoVec) -> SshBuf {
        SshBuf {
            read_pos: 0,
            buf: v,
        }
    }

    pub fn position(&self) -> usize {
        self.read_pos
    }

    pub fn set_position(&mut self, offset: usize) {
        if offset > self.buf.len() {
            panic!("Offset exceed length");
        }
        self.read_pos = offset;
    }

    pub fn into_inner(self) -> CryptoVec {
        self.buf
    }

    pub fn get_ref(&self) -> &CryptoVec {
        &self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Read for SshBuf {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.read_pos >= self.buf.len() {
            return Ok(0);
        }
        let n = self.buf.write_all_from(self.read_pos, buf)?;
        self.read_pos += n;
        Ok(n)
    }
}

impl Write for SshBuf {
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
    /// Read a byte and convert it to boolean
    ///
    /// By definition, all non-zero value would be interpreted as true.
    fn read_bool(&mut self) -> Result<bool>;

    /// Read a byte from the stream
    fn read_uint8(&mut self) -> io::Result<u8>;

    /// Read 32 bits unsigned integer in big endian
    fn read_uint32(&mut self) -> io::Result<u32>;

    /// Read 64 bits unsigned integer in big endian
    fn read_uint64(&mut self) -> io::Result<u64>;

    /// Read bytes array or string
    ///
    /// Before the binary string, there is a 32 bits unsigned integer to indicate the length of the data,
    /// and the binary string is **NOT** null-terminating.
    fn read_string(&mut self) -> io::Result<Vec<u8>>;

    /// Read UTF-8 string
    ///
    /// This actually does the same thing as [read_string()](trait.SshReadExt.html#tymethod.read_string) does.
    /// But it also convert the binary data to [String](https://doc.rust-lang.org/std/string/struct.String.html).
    fn read_utf8(&mut self) -> io::Result<String>;

    /// Read multiple precision integer
    ///
    /// Although it can contain negative number, but we don't support it currently.
    /// Integers which is longer than 16384 bits are also not supporting.
    fn read_mpint(&mut self) ->  io::Result<Vec<u8>>;

    /*
    /// Read name-list
    ///
    /// It is a list representing in an ASCII string separated by the `,` charactor.
    fn read_list<B: FromIterator<String>>(&mut self) -> io::Result<B>;
    */
}

impl<R: io::Read + ?Sized> SshReadExt for R {
    fn read_bool(&mut self) -> io::Result<bool> {
        let i = Zeroizing::new(self.read_uint8()?);
        Ok(*i != 0)
    }

    fn read_uint8(&mut self) -> io::Result<u8> {
        let mut buf = Zeroizing::new([0u8; 1]);
        self.read_exact(&mut *buf)?;
        Ok(buf[0])
    }

    fn read_uint32(&mut self) -> io::Result<u32> {
        let mut buf = Zeroizing::new([0u8; 4]);
        self.read_exact(&mut *buf)?;
        Ok(u32::from_be_bytes(*buf))
    }

    fn read_uint64(&mut self) -> io::Result<u64> {
        let mut buf = Zeroizing::new([0u8; 8]);
        self.read_exact(&mut *buf)?;
        Ok(u64::from_be_bytes(*buf))
    }

    fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_uint32()? as usize;
        let mut buf = vec![0u8; len];
        match self.read_exact(buf.as_mut_slice()) {
            Ok(_) => Ok(buf),
            Err(e) => {
                buf.zeroize();
                Err(e)
            }
        }
    }

    fn read_utf8(&mut self) -> io::Result<String> {
        let mut buf = self.read_string()?;
        // Make data be zeroed even an error occurred
        // So we cannot directly use `String::from_utf8()`
        match str::from_utf8(&buf) {
            Ok(_) => unsafe {
                // We have checked the string using `str::from_utf8()`
                // To avoid memory copy, just use `from_utf8_unchecked()`
                Ok(String::from_utf8_unchecked(buf))
            },
            Err(_) => {
                buf.zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid UTF-8 sequence",
                ))
            }
        }
    }

    fn read_mpint(&mut self) ->  io::Result<Vec<u8>> {
        let data = Zeroizing::new(self.read_string()?);
            if !data.is_empty() && data[0] & 0x80 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Negative Big Number",
        ));
    }
    if (data.len() > MAX_BIGNUM + 1) || (data.len() == MAX_BIGNUM + 1 && data[0] != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Big Number Too Long",
        ));
    }
        Ok(data.to_vec())
    }
}
