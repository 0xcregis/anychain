use hex;
use ripemd::{Digest, Ripemd160};

pub fn ripemd(msg: &[u8]) -> String {
    // create a RIPEMD-160 hasher instance
    let mut hasher = Ripemd160::new();
    // process input message
    //hasher.update(b"Hello world!");
    hasher.update(msg);
    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    let result = hasher.finalize();
    hex::encode(&result[..])
}
