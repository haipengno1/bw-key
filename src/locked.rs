use zeroize::Zeroize;

pub struct Vec {
    data: Box<arrayvec::ArrayVec<u8,4096>>,
    _lock: region::LockGuard,
}

impl Default for Vec {
    fn default() -> Self {
        let data = Box::new(arrayvec::ArrayVec::<_,4096>::new());
        // XXX it'd be nice to handle this better than .unwrap(), but it'd be
        // a lot of effort
        let lock = region::lock(data.as_ptr(), data.capacity()).unwrap();
        Self { data, _lock: lock }
    }
}

impl Vec {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_str(str:&[u8]) -> Self {
        let mut array = arrayvec::ArrayVec::<u8, 4096>::new();
        array.extend(std::iter::repeat(0).take(str.len()));
        array.copy_from_slice(str);
        array.truncate(str.len());
        let data = Box::new(array);
        // XXX it'd be nice to handle this better than .unwrap(), but it'd be
        // a lot of effort
        let lock = region::lock(data.as_ptr(), data.capacity()).unwrap();
        Self { data, _lock: lock }
    }
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    // pub fn truncate(&mut self, len: usize) {
    //     self.data.truncate(len);
    // }
}

impl Drop for Vec {
    fn drop(&mut self) {
        self.data.as_mut().zeroize();
    }
}

pub struct Password {
    password: Vec,
}

impl Password {
    pub fn new(password: Vec) -> Self {
        Self { password }
    }

    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

pub struct Keys {
    keys: Vec,
}

impl Keys {
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }
}

pub struct PasswordHash {
    hash: Vec,
}

impl PasswordHash {
    pub fn new(hash: Vec) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}