//! SHA-256 of executable images via Windows CNG (BCrypt): FIPS-validated, no extra crates.

use std::fs::File;
use std::io::Read;

use windows_sys::core::w;
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE,
};

pub struct Sha256Provider(BCRYPT_ALG_HANDLE);

impl Sha256Provider {
    pub fn open() -> Option<Self> {
        let mut h: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
        let st = unsafe { BCryptOpenAlgorithmProvider(&mut h, w!("SHA256"), std::ptr::null(), 0) };
        (st >= 0).then_some(Sha256Provider(h))
    }

    pub fn hash_reader(&self, mut r: impl Read) -> std::io::Result<String> {
        let mut hh: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        let st = unsafe {
            BCryptCreateHash(
                self.0,
                &mut hh,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        };
        if st < 0 {
            return Err(std::io::Error::other(format!(
                "BCryptCreateHash 0x{:08X}",
                st as u32
            )));
        }
        struct Guard(BCRYPT_HASH_HANDLE);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe { BCryptDestroyHash(self.0) };
            }
        }
        let _g = Guard(hh);
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let st = unsafe { BCryptHashData(hh, buf.as_ptr(), n as u32, 0) };
            if st < 0 {
                return Err(std::io::Error::other(format!(
                    "BCryptHashData 0x{:08X}",
                    st as u32
                )));
            }
        }
        let mut digest = [0u8; 32];
        let st = unsafe { BCryptFinishHash(hh, digest.as_mut_ptr(), 32, 0) };
        if st < 0 {
            return Err(std::io::Error::other(format!(
                "BCryptFinishHash 0x{:08X}",
                st as u32
            )));
        }
        Ok(digest.iter().map(|b| format!("{:02x}", b)).collect())
    }

    pub fn hash_file(&self, path: &str) -> std::io::Result<String> {
        self.hash_reader(File::open(path)?)
    }
}

impl Drop for Sha256Provider {
    fn drop(&mut self) {
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        let p = Sha256Provider::open().unwrap();
        assert_eq!(
            p.hash_reader(&b""[..]).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            p.hash_reader(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
