use std::fmt::Display;

use crate::{RippleAddress, RippleFormat, RipplePublicKey};
use anychain_core::{
    crypto::{hash160, sha512},
    hex,
    libsecp256k1::Signature,
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
        Self::from_st(&SerializedType::deserialize(stream)?)
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
            st.add_field(sig)?;
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
                                                    // we skip the deserialization of "payment"
                                                } else if *field_value == 13 {
                                                    match String::from_utf8(buffer.clone()) {
                                                        Ok(s) => memos.push(s),
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
                            if buffer.len() != 64 {
                                return Err(TransactionError::Message(format!(
                                    "Invalid signature length {}",
                                    buffer.len(),
                                )));
                            }
                            signature = Some(buffer.clone());
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

enum SerializedTypeID {
    Uint32 = 2,
    Amount = 6,
    VL = 7,
    Account = 8,
    // 9-13 are reserved
    Object = 14,
    Array = 15,
}

#[derive(Clone)]
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

impl SerializedType {
    fn type_id(&self) -> SerializedTypeID {
        match self {
            Self::Account { .. } => SerializedTypeID::Account,
            Self::Amount { .. } => SerializedTypeID::Amount,
            Self::Integer { .. } => SerializedTypeID::Uint32,
            Self::Blob { .. } => SerializedTypeID::VL,
            Self::Array { .. } => SerializedTypeID::Array,
            Self::Object { .. } => SerializedTypeID::Object,
        }
    }

    fn field_value(&self) -> u32 {
        match self {
            Self::Account { field_value, .. } => *field_value,
            Self::Amount { field_value, .. } => *field_value,
            Self::Integer { field_value, .. } => *field_value,
            Self::Blob { field_value, .. } => *field_value,
            Self::Array { field_value, .. } => *field_value,
            Self::Object { field_value, .. } => *field_value,
        }
    }

    fn serialize_field_id(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(serialize_field_id(self.type_id(), self.field_value()))
    }

    fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        match self {
            Self::Amount { value, .. } => Ok(value.to_be_bytes().to_vec()),
            Self::Integer { value, .. } => Ok(value.to_be_bytes().to_vec()),
            Self::Blob { buffer, .. } => Ok(buffer.clone()),
            Self::Account { account_id, .. } => {
                let mut stream = serialize_len(account_id.len() as u32);
                stream.extend(account_id.to_vec());
                Ok(stream)
            }
            Self::Array { elems, .. } => {
                let mut stream = vec![];
                for elem in elems {
                    stream.extend(elem.serialize_field_id()?);
                    stream.extend(elem.serialize()?);
                    stream.extend(serialize_field_id(SerializedTypeID::Object, 1))
                }
                Ok(stream)
            }
            Self::Object { members, .. } => {
                let mut stream = vec![];
                for mem in members {
                    stream.extend(mem.serialize_field_id()?);
                    stream.extend(mem.serialize()?);
                    match mem.type_id() {
                        SerializedTypeID::Array | SerializedTypeID::Object => {
                            stream.extend(serialize_field_id(mem.type_id(), 1))
                        }
                        _ => {}
                    }
                }
                Ok(stream)
            }
        }
    }

    fn deserialize(_stream: &[u8]) -> Result<Self, TransactionError> {









        todo!()
    }

    fn add_field(&mut self, st: SerializedType) -> Result<(), TransactionError> {
        if let SerializedType::Object { members, .. } = self {
            members.push(st);
            Ok(())
        } else {
            Err(TransactionError::Message(
                "Adding fields to non object serialized type".to_string(),
            ))
        }
    }
}

fn serialize_len(mut len: u32) -> Vec<u8> {
    if len <= 192 {
        vec![len as u8]
    } else if len <= 12480 {
        len -= 193;
        let b0 = 193 + (len >> 8) as u8;
        let b1 = (len & 0xff) as u8;
        vec![b0, b1]
    } else if len <= 918744 {
        len -= 12481;
        let b0 = 241 + (len >> 16) as u8;
        let b1 = ((len >> 8) & 0xff) as u8;
        let b2 = (len & 0xff) as u8;
        vec![b0, b1, b2]
    } else {
        panic!("Maximum length exceeded");
    }
}

fn serialize_field_id(typ: SerializedTypeID, name: u32) -> Vec<u8> {
    let typ = typ as u32;

    if !(..256).contains(&typ) || !(..256).contains(&name) {
        panic!("Number out of range");
    }

    if typ < 16 {
        if name < 16 {
            // common type, common name
            vec![((typ << 4) | name) as u8]
        } else {
            // common type, uncommon name
            let b0 = (typ << 4) as u8;
            let b1 = name as u8;
            vec![b0, b1]
        }
    } else if name < 16 {
        // uncommon type, common name
        let b0 = name as u8;
        let b1 = typ as u8;
        vec![b0, b1]
    } else {
        // uncommon type, uncommon name
        let b0 = 0;
        let b1 = typ as u8;
        let b2 = name as u8;
        vec![b0, b1, b2]
    }
}
