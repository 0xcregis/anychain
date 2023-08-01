use core::fmt;
use std::{fmt::Display, str::FromStr};

use crate::{RippleAddress, RippleFormat, RipplePublicKey};
use anychain_core::{
    crypto::{hash160, sha512},
    hex,
    libsecp256k1::Signature,
    no_std::io::Read,
    Transaction, TransactionError, TransactionId,
};

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct RippleTransactionParameters {
    destination: [u8; 20],
    fee: u32,
    sequence: u32,
    destination_tag: u32,
    amount: u64,
    memos: Vec<String>,
    public_key: [u8; 33],
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct RippleTransaction {
    pub params: RippleTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

impl Transaction for RippleTransaction {
    type Address = RippleAddress;
    type Format = RippleFormat;
    type PublicKey = RipplePublicKey;
    type TransactionParameters = RippleTransactionParameters;
    type TransactionId = RippleTransactionId;

    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            params: parameters.clone(),
            signature: None,
        })
    }

    fn sign(&mut self, rs: Vec<u8>, _recid: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some(rs);
        self.to_bytes()
    }

    fn from_bytes(stream: &[u8]) -> Result<Self, TransactionError> {
        // Before we deserialize the stream, we should postfix the
        // stream with a mark of ending for object type
        let mut stream = stream.to_vec();
        stream.extend(serialize_type(SerializedTypeID::Object, 1)?);

        // Deserialize the stream to a SerializedType object, which
        // is then converted to a Ripple Transaction
        Self::from_st(&SerializedType::deserialize(
            &mut stream.as_slice(),
            SerializedTypeID::Object,
            0,
        )?)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        self.to_st()?.serialize()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        match &self.signature {
            // compute the txid of the signed tx
            Some(_) => {
                // prefix the tx stream with "TXN\0"
                let mut stream = vec![b'T', b'X', b'N', 0];
                stream.extend(self.to_bytes()?);
                // we take the first half of the sha512 hash as txid
                let txid = sha512(&stream)[..32].to_vec();
                Ok(RippleTransactionId { txid })
            }
            // compute the raw tx's digest for signing
            None => {
                // preifx the tx stream with "STX\0"
                let mut stream = vec![b'S', b'T', b'X', 0];
                stream.extend(self.to_bytes()?);
                // we take the first half of the sha512 hash as digest for signing
                let digest = sha512(&stream)[..32].to_vec();
                Ok(RippleTransactionId { txid: digest })
            }
        }
    }
}

impl FromStr for RippleTransaction {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&hex::decode(tx)?)
    }
}

impl fmt::Display for RippleTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

impl RippleTransaction {
    fn to_st(&self) -> Result<SerializedType, TransactionError> {
        let mut account_id = [0u8; 20];
        account_id.copy_from_slice(&hash160(&self.params.public_key));

        let account = SerializedType::Account {
            field_value: 1,
            account_id,
        };

        let dest = SerializedType::Account {
            field_value: 3,
            account_id: self.params.destination,
        };

        let fee = SerializedType::Amount {
            field_value: 8,
            value: self.params.fee as u64,
        };

        let sequence = SerializedType::Integer {
            field_value: 4,
            value: self.params.sequence,
        };

        let dest_tag = SerializedType::Integer {
            field_value: 14,
            value: self.params.destination_tag,
        };

        let amount = SerializedType::Amount {
            field_value: 1,
            value: self.params.amount,
        };

        let memos: Vec<SerializedType> = self
            .params
            .memos
            .iter()
            .map(|memo| {
                let memo = SerializedType::Blob {
                    field_value: 13,
                    buffer: memo.as_bytes().to_vec(),
                };

                let memo_type = SerializedType::Blob {
                    field_value: 12,
                    buffer: "payment".as_bytes().to_vec(),
                };

                SerializedType::Object {
                    field_value: 10,
                    members: vec![memo, memo_type],
                }
            })
            .collect();

        let memos = SerializedType::Array {
            field_value: 9,
            elems: memos,
        };

        let public_key = SerializedType::Blob {
            field_value: 3,
            buffer: self.params.public_key.to_vec(),
        };

        let mut st = SerializedType::Object {
            field_value: 0,
            members: vec![
                account, dest, fee, sequence, dest_tag, amount, memos, public_key,
            ],
        };

        if let Some(sig) = &self.signature {
            let sig = Signature::parse_standard_slice(sig)?
                .serialize_der()
                .as_ref()
                .to_vec();
            let sig = SerializedType::Blob {
                field_value: 4,
                buffer: sig,
            };
            st.add_member(sig)?;
        }

        Ok(st)
    }

    fn from_st(st: &SerializedType) -> Result<Self, TransactionError> {
        if let SerializedType::Object { members, .. } = st {
            let mut destination = [0u8; 20];
            let mut fee = 0;
            let mut sequence = 0;
            let mut destination_tag = 0;
            let mut amount = 0;
            let mut memos = vec![];
            let mut public_key = [0u8; 33];
            let mut signature: Option<Vec<u8>> = None;

            for mem in members {
                match mem {
                    SerializedType::Account {
                        field_value,
                        account_id,
                        ..
                    } => {
                        if *field_value == 3 {
                            destination = *account_id;
                        } else if *field_value == 1 {
                            // we skip the deserialization of account
                        } else {
                            return Err(TransactionError::Message(format!(
                                "Invalid field value {} for field serialized type 'account'",
                                *field_value,
                            )));
                        }
                    }
                    SerializedType::Amount {
                        field_value, value, ..
                    } => {
                        if *field_value == 1 {
                            amount = *value;
                        } else if *field_value == 8 {
                            fee = *value as u32;
                        } else {
                            return Err(TransactionError::Message(format!(
                                "Invalid field value {} for serialized type 'amount'",
                                *field_value,
                            )));
                        }
                    }
                    SerializedType::Array { field_value, elems } => {
                        if *field_value == 9 {
                            for elem in elems {
                                if let SerializedType::Object {
                                    field_value,
                                    members,
                                } = elem
                                {
                                    if *field_value == 10 {
                                        for mem in members {
                                            if let SerializedType::Blob {
                                                field_value,
                                                buffer,
                                            } = mem
                                            {
                                                if *field_value == 12 {
                                                    // we skip the deserialization of memo_type
                                                } else if *field_value == 13 {
                                                    match String::from_utf8(buffer.clone()) {
                                                        Ok(memo) => memos.push(memo),
                                                        Err(_) => {
                                                            return Err(TransactionError::Message(
                                                                "Invalid memo".to_string(),
                                                            ))
                                                        }
                                                    }
                                                } else {
                                                    return Err(TransactionError::Message(format!(
                                                        "Invalid field value {} for serialized type",
                                                        *field_value,
                                                    )));
                                                }
                                            }
                                        }
                                    } else {
                                        return Err(TransactionError::Message(format!(
                                            "Invalid field value {} for serialized type 'object'",
                                            *field_value,
                                        )));
                                    }
                                } else {
                                    return Err(TransactionError::Message(
                                        "None object array elements not allowed".to_string(),
                                    ));
                                }
                            }
                        } else {
                            return Err(TransactionError::Message(format!(
                                "Invalid field value {} for serialized type 'array'",
                                *field_value,
                            )));
                        }
                    }
                    SerializedType::Blob {
                        field_value,
                        buffer,
                    } => {
                        if *field_value == 3 {
                            if buffer.len() != 33 {
                                return Err(TransactionError::Message(format!(
                                    "Invalid public key length {}",
                                    buffer.len(),
                                )));
                            }
                            public_key.copy_from_slice(buffer);
                        } else if *field_value == 4 {
                            if !(70..=72).contains(&buffer.len()) {
                                return Err(TransactionError::Message(format!(
                                    "Invalid signature length {}",
                                    buffer.len(),
                                )));
                            }
                            let sig = Signature::parse_der(buffer)?.serialize().to_vec();
                            signature = Some(sig);
                        } else {
                            return Err(TransactionError::Message(format!(
                                "Invalid field value {} for serialized type 'blob'",
                                *field_value,
                            )));
                        }
                    }
                    SerializedType::Integer { field_value, value } => {
                        if *field_value == 4 {
                            sequence = *value;
                        } else if *field_value == 14 {
                            destination_tag = *value;
                        } else {
                            return Err(TransactionError::Message(format!(
                                "Invalid field value {} for serialized type 'integer'",
                                *field_value,
                            )));
                        }
                    }
                    SerializedType::Object { .. } => {
                        return Err(TransactionError::Message(
                            "Serialized type 'object' not allowd in first layer deserialization"
                                .to_string(),
                        ))
                    }
                }
            }

            let mut tx = RippleTransaction::new(&RippleTransactionParameters {
                destination,
                fee,
                sequence,
                destination_tag,
                amount,
                memos,
                public_key,
            })?;

            if signature.is_some() {
                tx.signature = signature;
            }

            Ok(tx)
        } else {
            Err(TransactionError::Message(
                "Deserialization of none object serialized type not allowed for Ripple transaction"
                    .to_string(),
            ))
        }
    }
}

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
struct RippleTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for RippleTransactionId {}

impl Display for RippleTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.txid))
    }
}

#[derive(PartialEq)]
enum SerializedTypeID {
    Uint32 = 2,
    Amount = 6,
    VL = 7,
    Account = 8,
    // 9-13 are reserved
    Object = 14,
    Array = 15,
}

impl SerializedTypeID {
    fn from_u8(b: u8) -> Result<Self, TransactionError> {
        match b {
            2 => Ok(Self::Uint32),
            6 => Ok(Self::Amount),
            7 => Ok(Self::VL),
            8 => Ok(Self::Account),
            14 => Ok(Self::Object),
            15 => Ok(Self::Array),
            _ => Err(TransactionError::Message(format!(
                "Unsupported serialized type id {}",
                b,
            ))),
        }
    }
}

impl fmt::Display for SerializedTypeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uint32 => write!(f, "Integer"),
            Self::Amount => write!(f, "Amount"),
            Self::VL => write!(f, "Blob"),
            Self::Account => write!(f, "Account"),
            Self::Object => write!(f, "Object"),
            Self::Array => write!(f, "Array"),
        }
    }
}

#[derive(Clone, Debug)]
enum SerializedType {
    Account {
        field_value: u32,
        account_id: [u8; 20],
    },

    Amount {
        field_value: u32,
        value: u64,
    },

    Integer {
        field_value: u32,
        value: u32,
    },

    Blob {
        field_value: u32,
        buffer: Vec<u8>,
    },

    Array {
        field_value: u32,
        elems: Vec<SerializedType>,
    },

    Object {
        field_value: u32,
        members: Vec<SerializedType>,
    },
}

fn serialize_len(mut len: u32) -> Result<Vec<u8>, TransactionError> {
    if len <= 192 {
        Ok(vec![len as u8])
    } else if len <= 12480 {
        len -= 193;
        let b0 = 193 + (len >> 8) as u8;
        let b1 = (len & 0xff) as u8;
        Ok(vec![b0, b1])
    } else if len <= 918744 {
        len -= 12481;
        let b0 = 241 + (len >> 16) as u8;
        let b1 = ((len >> 8) & 0xff) as u8;
        let b2 = (len & 0xff) as u8;
        Ok(vec![b0, b1, b2])
    } else {
        Err(TransactionError::Message(
            "Maximum length exceeded".to_string(),
        ))
    }
}

fn deserialize_len(stream: &mut &[u8]) -> Result<u32, TransactionError> {
    let mut b = [0u8; 1];
    let _ = stream.read(&mut b)?;

    match b[0] {
        (..=192) => Ok(b[0] as u32),
        (193..=240) => {
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf)?;
            let mut len = [0u8; 4];
            len[2] = b[0] - 193;
            len[3] = buf[0];
            Ok(u32::from_be_bytes(len))
        }
        (241..) => {
            let mut buf = [0u8; 2];
            let _ = stream.read(&mut buf)?;
            let mut len = [0u8; 4];
            len[1] = b[0] - 241;
            len[2] = buf[0];
            len[3] = buf[1];
            Ok(u32::from_be_bytes(len))
        }
    }
}

fn serialize_type(typ: SerializedTypeID, val: u32) -> Result<Vec<u8>, TransactionError> {
    let typ = typ as u32;

    if !(..256).contains(&typ) || !(..256).contains(&val) {
        return Err(TransactionError::Message("Number out of range".to_string()));
    }

    if typ < 16 {
        if val < 16 {
            // common type, common val
            Ok(vec![((typ << 4) | val) as u8])
        } else {
            // common type, uncommon val
            let b0 = (typ << 4) as u8;
            let b1 = val as u8;
            Ok(vec![b0, b1])
        }
    } else if val < 16 {
        // uncommon type, common val
        let b0 = val as u8;
        let b1 = typ as u8;
        Ok(vec![b0, b1])
    } else {
        // uncommon type, uncommon val
        let b0 = 0;
        let b1 = typ as u8;
        let b2 = val as u8;
        Ok(vec![b0, b1, b2])
    }
}

fn deserialize_type(stream: &mut &[u8]) -> Result<(u8, u8), TransactionError> {
    let mut b = [0u8; 1];
    let _ = stream.read(&mut b)?;

    match (b[0] & 0xf0 == 0, b[0] & 0x0f == 0) {
        // both higher and lower 4 bits are zero
        (true, true) => {
            let mut buf = [0u8; 2];
            let _ = stream.read(&mut buf)?;
            Ok((buf[0], buf[1]))
        }
        // only higher 4 bits are zero
        (true, false) => {
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf)?;
            Ok((buf[0], b[0]))
        }
        // only lower 4 bits are zero
        (false, true) => {
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf)?;
            Ok((b[0] >> 4, buf[0]))
        }
        // neither higher 4 bits nor lower 4 bits are zero
        (false, false) => Ok(((b[0] & 0xf0) >> 4, b[0] & 0x0f)),
    }
}

impl SerializedType {
    fn typ(&self) -> SerializedTypeID {
        match self {
            Self::Account { .. } => SerializedTypeID::Account,
            Self::Amount { .. } => SerializedTypeID::Amount,
            Self::Integer { .. } => SerializedTypeID::Uint32,
            Self::Blob { .. } => SerializedTypeID::VL,
            Self::Array { .. } => SerializedTypeID::Array,
            Self::Object { .. } => SerializedTypeID::Object,
        }
    }

    fn val(&self) -> u32 {
        match self {
            Self::Account { field_value, .. } => *field_value,
            Self::Amount { field_value, .. } => *field_value,
            Self::Integer { field_value, .. } => *field_value,
            Self::Blob { field_value, .. } => *field_value,
            Self::Array { field_value, .. } => *field_value,
            Self::Object { field_value, .. } => *field_value,
        }
    }

    fn serialize_type(&self) -> Result<Vec<u8>, TransactionError> {
        serialize_type(self.typ(), self.val())
    }

    fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        match self {
            Self::Amount { value, .. } => Ok(value.to_be_bytes().to_vec()),
            Self::Integer { value, .. } => Ok(value.to_be_bytes().to_vec()),
            Self::Account { account_id, .. } => {
                let mut stream = serialize_len(account_id.len() as u32)?;
                stream.extend(account_id.to_vec());
                Ok(stream)
            }
            Self::Blob { buffer, .. } => {
                let mut stream = serialize_len(buffer.len() as u32)?;
                stream.extend(buffer);
                Ok(stream)
            }
            Self::Array { elems, .. } => {
                let mut stream = vec![];
                for elem in elems {
                    stream.extend(elem.serialize_type()?);
                    stream.extend(elem.serialize()?);
                    stream.extend(serialize_type(SerializedTypeID::Object, 1)?);
                }
                Ok(stream)
            }
            Self::Object { members, .. } => {
                let mut stream = vec![];
                for mem in members {
                    stream.extend(mem.serialize_type()?);
                    stream.extend(mem.serialize()?);
                    match mem.typ() {
                        SerializedTypeID::Array | SerializedTypeID::Object => {
                            stream.extend(serialize_type(mem.typ(), 1)?)
                        }
                        _ => {}
                    }
                }
                Ok(stream)
            }
        }
    }

    fn deserialize(
        stream: &mut &[u8],
        typ: SerializedTypeID,
        field_value: u32,
    ) -> Result<Self, TransactionError> {
        match typ {
            SerializedTypeID::Account => {
                // Firstly we extract the length of the account id
                let len = deserialize_len(stream)?;
                if len != 20 {
                    return Err(TransactionError::Message(format!(
                        "Invalid account length {}",
                        len,
                    )));
                }

                // Then we extract the account id
                let mut account_id = [0u8; 20];
                let _ = stream.read(&mut account_id)?;

                // Return the ST
                Ok(SerializedType::Account {
                    field_value,
                    account_id,
                })
            }
            SerializedTypeID::Amount => {
                let mut value = [0u8; 8];
                let _ = stream.read(&mut value)?;
                let value = u64::from_be_bytes(value);

                // Return the ST
                Ok(SerializedType::Amount { field_value, value })
            }
            SerializedTypeID::Uint32 => {
                let mut value = [0u8; 4];
                let _ = stream.read(&mut value)?;
                let value = u32::from_be_bytes(value);

                // Return the ST
                Ok(SerializedType::Integer { field_value, value })
            }
            SerializedTypeID::VL => {
                // Firstly we extract the length of the blob
                let len = deserialize_len(stream)?;

                // Then we extract the blob according to its length
                let mut buffer = vec![0u8; len as usize];
                let _ = stream.read(&mut buffer)?;

                // Return the ST
                Ok(SerializedType::Blob {
                    field_value,
                    buffer,
                })
            }
            SerializedTypeID::Array => {
                let mut array = SerializedType::Array {
                    field_value,
                    elems: vec![],
                };
                loop {
                    let (typ, fv) = deserialize_type(stream)?;
                    let typ = SerializedTypeID::from_u8(typ)?;

                    // we have reached the end of the array
                    if typ == SerializedTypeID::Array && fv == 1 {
                        break;
                    }

                    let st = Self::deserialize(stream, typ, fv as u32)?;
                    array.add_member(st)?;
                }
                Ok(array)
            }
            SerializedTypeID::Object => {
                let mut obj = SerializedType::Object {
                    field_value,
                    members: vec![],
                };
                loop {
                    let (typ, fv) = deserialize_type(stream)?;
                    let typ = SerializedTypeID::from_u8(typ)?;

                    // we have reached the end of the object
                    if (typ == SerializedTypeID::Object || typ == SerializedTypeID::Array)
                        && fv == 1
                    {
                        break;
                    }

                    let st = Self::deserialize(stream, typ, fv as u32)?;
                    obj.add_member(st)?;
                }
                Ok(obj)
            }
        }
    }

    fn add_member(&mut self, st: SerializedType) -> Result<(), TransactionError> {
        match self {
            SerializedType::Object { members, .. } => {
                members.push(st);
                Ok(())
            }
            SerializedType::Array { elems, .. } => {
                elems.push(st);
                Ok(())
            }
            _ => Err(TransactionError::Message(
                "Adding fields to neither an object or an array".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RippleTransaction, RippleTransactionParameters};
    use anychain_core::{
        libsecp256k1::{self, Message, PublicKey, SecretKey},
        Transaction,
    };
    use std::str::FromStr;

    #[test]
    fn tx_gen() {
        let sk = [
            1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1,
        ];

        let sk = SecretKey::parse(&sk).unwrap();
        let pk = PublicKey::from_secret_key(&sk);
        let pk = pk.serialize_compressed();

        let params = RippleTransactionParameters {
            destination: [1u8; 20],
            fee: 5000000,
            sequence: 88888,
            destination_tag: 333333,
            amount: 10000000000,
            memos: vec!["guai".to_string(), "xia".to_string(), "mao".to_string()],
            public_key: pk,
        };

        let mut tx = RippleTransaction::new(&params).unwrap();

        let txid = tx.to_transaction_id().unwrap().txid;

        let msg = Message::parse_slice(&txid).unwrap();

        let sig = libsecp256k1::sign(&msg, &sk).0.serialize().to_vec();

        let tx = tx.sign(sig, 0).unwrap();
        let tx = RippleTransaction::from_bytes(&tx).unwrap();

        println!("tx = {:?}", tx);
        println!("tx = {}", tx);
    }

    #[test]
    fn tx_from_str() {
        let tx = "811479b000887626b294a914501a4cd226b58b235983831401010101010101010101010101010101010101016800000000004c4b402400015b382e000516156100000002540be400f9ea7d04677561697c077061796d656e74e1ea7d037869617c077061796d656e74e1ea7d036d616f7c077061796d656e74e1f17321031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
        let tx = RippleTransaction::from_str(tx).unwrap();

        println!("tx = {:?}", tx.params);
        println!("tx = {}", tx);
    }
}
