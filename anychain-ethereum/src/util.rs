use crate::{EthereumAddress, EthereumFormat, EthereumPublicKey};
use anychain_core::{PublicKey, TransactionError};
use libsecp256k1::{recover, Error, Message, RecoveryId, Signature};

/// Trim the leading zeros of a byte stream and return it
pub(crate) fn trim_leading_zeros(v: &Vec<u8>) -> &[u8] {
    let mut cnt: usize = 0;
    for byte in v {
        if *byte != 0 {
            break;
        } else {
            cnt += 1;
        }
    }
    &v[cnt..]
}

/// Prepend a number of zeros to 'v' to make it 'to_len' bytes long
pub(crate) fn pad_zeros(v: &mut Vec<u8>, to_len: usize) {
    if v.len() < to_len {
        let mut temp = v.clone();
        let len = v.len();
        v.clear();
        v.resize(to_len - len, 0);
        v.append(&mut temp);
    }
}

pub(crate) fn adapt1<T>(v: Result<T, Error>) -> Result<T, TransactionError> {
    match v {
        Ok(t) => Ok(t),
        Err(e) => Err(TransactionError::Message(format!(
            "libsecp256k1 error: {}",
            e
        ))),
    }
}

pub(crate) fn adapt2<T>(v: Result<T, rlp::DecoderError>) -> Result<T, TransactionError> {
    match v {
        Ok(t) => Ok(t),
        Err(e) => Err(TransactionError::Message(format!("rlp error:{}", e))),
    }
}

pub(crate) fn restore_sender(
    msg: Vec<u8>,
    sig: Vec<u8>,
    recid: u8,
) -> Result<EthereumAddress, TransactionError> {
    let recid = adapt1(RecoveryId::parse(recid))?;
    let sig = adapt1(Signature::parse_standard_slice(&sig))?;
    let msg = adapt1(Message::parse_slice(&msg))?;
    let pk = adapt1(recover(&msg, &sig, &recid))?;
    let pk = EthereumPublicKey::from_secp256k1_public_key(pk);
    Ok(pk.to_address(&EthereumFormat::Standard)?)
}
