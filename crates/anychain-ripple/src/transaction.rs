use std::cmp::{Ord, Ordering};
use std::{fmt, str::FromStr};

use crate::{RippleAddress, RippleFormat, RipplePublicKey};
use anychain_core::{
    crypto::{hash160, sha512},
    hex,
    no_std::io::Read,
    Transaction, TransactionError, TransactionId,
};
use libsecp256k1::Signature;

/// Standard XRPL currency code for RLUSD ("RLUSD" right-padded with zeroes to 20 bytes).
pub const RLUSD_CURRENCY_CODE: [u8; 20] = [
    b'R', b'L', b'U', b'S', b'D', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Official Ripple RLUSD issuer address on XRPL Mainnet.
pub const RLUSD_MAINNET_ISSUER: &str = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De";

/// Official Ripple RLUSD issuer address on XRPL Testnet.
pub const RLUSD_TESTNET_ISSUER: &str = "rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV";

/// Common XRPL TrustSet transaction flags.
pub mod trust_set_flags {
    /// Authorize the other party to hold currency issued by this account.
    pub const TF_SET_AUTH: u32 = 0x0001_0000;
    /// Enable No Ripple on this trust line.
    pub const TF_SET_NO_RIPPLE: u32 = 0x0002_0000;
    /// Disable No Ripple on this trust line.
    pub const TF_CLEAR_NO_RIPPLE: u32 = 0x0004_0000;
    /// Freeze the trust line.
    pub const TF_SET_FREEZE: u32 = 0x0010_0000;
    /// Unfreeze the trust line.
    pub const TF_CLEAR_FREEZE: u32 = 0x0020_0000;
}

/// Encodes an XRPL currency string into its 20-byte (160-bit) representation:
/// - 3-character standard currency codes (e.g., `"USD"`) are placed at bytes 12..15.
/// - 4..=20-character non-standard ASCII currency codes (e.g., `"RLUSD"`) are right-padded with `0x00`.
/// - 40-character hex strings are decoded directly into 20 bytes.
pub fn encode_currency_code(code: &str) -> Result<[u8; 20], TransactionError> {
    if code.len() == 3 {
        if code == "XRP" {
            return Err(TransactionError::Message(
                "XRP is not a valid issued currency code".to_string(),
            ));
        }
        if !code.is_ascii() {
            return Err(TransactionError::Message(
                "Currency code must be ASCII".to_string(),
            ));
        }
        let mut bytes = [0u8; 20];
        bytes[12..15].copy_from_slice(code.as_bytes());
        Ok(bytes)
    } else if code.len() == 40 && code.chars().all(|c| c.is_ascii_hexdigit()) {
        let decoded = hex::decode(code)?;
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&decoded);
        if bytes[0] == 0x00 {
            return Err(TransactionError::Message(
                "Non-standard 160-bit currency code cannot start with 0x00 unless standard 3-char"
                    .to_string(),
            ));
        }
        Ok(bytes)
    } else if (4..=20).contains(&code.len()) && code.is_ascii() {
        let mut bytes = [0u8; 20];
        bytes[..code.len()].copy_from_slice(code.as_bytes());
        if bytes[0] == 0x00 {
            return Err(TransactionError::Message(
                "Non-standard currency code cannot start with 0x00".to_string(),
            ));
        }
        Ok(bytes)
    } else {
        Err(TransactionError::Message(format!(
            "Invalid currency code '{}'",
            code
        )))
    }
}

/// Represents a non-XRP Issued Currency (IOU) amount on the XRP Ledger (e.g., RLUSD).
///
/// Value is stored as `mantissa * 10^exponent` where non-zero amounts are normalized such that:
/// - `mantissa` is in `[1_000_000_000_000_000, 9_999_999_999_999_999]` (`10^15..10^16`)
/// - `exponent` is in `[-96, 80]`
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct IssuedAmount {
    pub is_negative: bool,
    pub mantissa: u64,
    pub exponent: i8,
    pub currency: [u8; 20],
    pub issuer: [u8; 20],
}

impl IssuedAmount {
    pub const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
    pub const MAX_MANTISSA: u64 = 9_999_999_999_999_999;
    pub const MIN_EXPONENT: i8 = -96;
    pub const MAX_EXPONENT: i8 = 80;

    /// Creates and normalizes an `IssuedAmount` from its components (`(-1)^is_negative * mantissa * 10^exponent`).
    pub fn new(
        is_negative: bool,
        mut mantissa: u64,
        mut exponent: i32,
        currency: [u8; 20],
        issuer: [u8; 20],
    ) -> Result<Self, TransactionError> {
        if mantissa == 0 {
            return Ok(Self {
                is_negative: false,
                mantissa: 0,
                exponent: 0,
                currency,
                issuer,
            });
        }

        while mantissa < Self::MIN_MANTISSA {
            mantissa = mantissa.checked_mul(10).ok_or_else(|| {
                TransactionError::Message("IssuedAmount mantissa overflow".to_string())
            })?;
            exponent -= 1;
        }

        while mantissa > Self::MAX_MANTISSA {
            if !mantissa.is_multiple_of(10) {
                return Err(TransactionError::Message(
                    "IssuedAmount exceeds 16 significant digits of precision".to_string(),
                ));
            }
            mantissa /= 10;
            exponent += 1;
        }

        if !(Self::MIN_EXPONENT as i32..=Self::MAX_EXPONENT as i32).contains(&exponent) {
            return Err(TransactionError::Message(format!(
                "IssuedAmount exponent {} out of range [-96, 80]",
                exponent
            )));
        }

        Ok(Self {
            is_negative,
            mantissa,
            exponent: exponent as i8,
            currency,
            issuer,
        })
    }

    /// Parses a decimal string (e.g., `"100.50"`, `"1000000"`, `"1.5e-4"`) along with a currency code and issuer.
    pub fn from_decimal_str(
        value: &str,
        currency: &str,
        issuer: [u8; 20],
    ) -> Result<Self, TransactionError> {
        let currency_bytes = encode_currency_code(currency)?;
        Self::from_decimal_str_with_currency_bytes(value, currency_bytes, issuer)
    }

    /// Creates an RLUSD `IssuedAmount` from a decimal string and the RLUSD issuer's 20-byte AccountID.
    pub fn rlusd(value: &str, issuer: [u8; 20]) -> Result<Self, TransactionError> {
        Self::from_decimal_str_with_currency_bytes(value, RLUSD_CURRENCY_CODE, issuer)
    }

    /// Creates an official Mainnet RLUSD `IssuedAmount` (`rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De`).
    pub fn rlusd_mainnet(value: &str) -> Result<Self, TransactionError> {
        let issuer = RippleAddress::from_str(RLUSD_MAINNET_ISSUER)
            .map_err(|e| TransactionError::Message(format!("Invalid RLUSD mainnet issuer: {}", e)))?
            .to_hash160()
            .map_err(|e| {
                TransactionError::Message(format!("Invalid RLUSD mainnet issuer: {}", e))
            })?;
        Self::rlusd(value, issuer)
    }

    /// Creates an official Testnet RLUSD `IssuedAmount` (`rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV`).
    pub fn rlusd_testnet(value: &str) -> Result<Self, TransactionError> {
        let issuer = RippleAddress::from_str(RLUSD_TESTNET_ISSUER)
            .map_err(|e| TransactionError::Message(format!("Invalid RLUSD testnet issuer: {}", e)))?
            .to_hash160()
            .map_err(|e| {
                TransactionError::Message(format!("Invalid RLUSD testnet issuer: {}", e))
            })?;
        Self::rlusd(value, issuer)
    }

    /// Parses a decimal string with a raw 20-byte currency code and 20-byte issuer AccountID.
    pub fn from_decimal_str_with_currency_bytes(
        value: &str,
        currency: [u8; 20],
        issuer: [u8; 20],
    ) -> Result<Self, TransactionError> {
        let s = value.trim();
        if s.is_empty() {
            return Err(TransactionError::Message(
                "Empty issued amount value".to_string(),
            ));
        }

        let (is_negative, s) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else if let Some(rest) = s.strip_prefix('+') {
            (false, rest)
        } else {
            (false, s)
        };

        let (num_part, exp_part) = if let Some((n, e)) = s.split_once(['e', 'E']) {
            let parsed_exp = e.parse::<i32>().map_err(|_| {
                TransactionError::Message(format!("Invalid exponent in amount '{}'", value))
            })?;
            (n, parsed_exp)
        } else {
            (s, 0i32)
        };

        let (int_part, frac_part) = if let Some((i, f)) = num_part.split_once('.') {
            if f.contains('.') {
                return Err(TransactionError::Message(format!(
                    "Invalid decimal amount '{}'",
                    value
                )));
            }
            (i, f)
        } else {
            (num_part, "")
        };

        if int_part.is_empty() && frac_part.is_empty() {
            return Err(TransactionError::Message(format!(
                "Invalid decimal amount '{}'",
                value
            )));
        }

        if !int_part.chars().all(|c| c.is_ascii_digit())
            || !frac_part.chars().all(|c| c.is_ascii_digit())
        {
            return Err(TransactionError::Message(format!(
                "Invalid characters in decimal amount '{}'",
                value
            )));
        }

        let combined = format!("{}{}", int_part, frac_part);
        let trimmed_leading = combined.trim_start_matches('0');
        if trimmed_leading.is_empty() {
            return Self::new(false, 0, 0, currency, issuer);
        }

        let trailing_zeros = trimmed_leading.len() - trimmed_leading.trim_end_matches('0').len();
        let sig_digits = trimmed_leading.trim_end_matches('0');

        let mantissa = sig_digits.parse::<u64>().map_err(|_| {
            TransactionError::Message(format!("Significant digits overflow in amount '{}'", value))
        })?;

        let exponent = exp_part - (frac_part.len() as i32) + (trailing_zeros as i32);
        Self::new(is_negative, mantissa, exponent, currency, issuer)
    }

    /// Encodes the 64-bit value header (first 8 bytes of the 48-byte XRPL IOU Amount).
    pub fn encode_value_bits(&self) -> u64 {
        if self.mantissa == 0 {
            return 0x8000_0000_0000_0000;
        }
        let mut bits: u64 = 0x8000_0000_0000_0000; // bit 63: not XRP
        if !self.is_negative {
            bits |= 0x4000_0000_0000_0000; // bit 62: positive
        }
        let biased_exp = ((self.exponent as i32) + 97) as u64;
        bits |= (biased_exp & 0xFF) << 54;
        bits |= self.mantissa & 0x003F_FFFF_FFFF_FFFF;
        bits
    }

    /// Decodes an `IssuedAmount` from its 48-byte XRPL binary representation.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, TransactionError> {
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&bytes[0..8]);
        let raw_val = u64::from_be_bytes(val_bytes);

        if raw_val & 0x8000_0000_0000_0000 == 0 {
            return Err(TransactionError::Message(
                "Expected non-XRP amount bit to be set".to_string(),
            ));
        }

        let mut currency = [0u8; 20];
        currency.copy_from_slice(&bytes[8..28]);

        let mut issuer = [0u8; 20];
        issuer.copy_from_slice(&bytes[28..48]);

        if raw_val == 0x8000_0000_0000_0000 {
            return Ok(Self {
                is_negative: false,
                mantissa: 0,
                exponent: 0,
                currency,
                issuer,
            });
        }

        let is_negative = (raw_val & 0x4000_0000_0000_0000) == 0;
        let biased_exp = ((raw_val >> 54) & 0xFF) as i32;
        let exponent = biased_exp - 97;
        let mantissa = raw_val & 0x003F_FFFF_FFFF_FFFF;

        Self::new(is_negative, mantissa, exponent, currency, issuer)
    }

    /// Serializes this `IssuedAmount` into its 48-byte XRPL binary representation.
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[0..8].copy_from_slice(&self.encode_value_bits().to_be_bytes());
        out[8..28].copy_from_slice(&self.currency);
        out[28..48].copy_from_slice(&self.issuer);
        out
    }
}

/// Represents either a native XRP amount (in drops) or an Issued Currency (IOU) amount (such as RLUSD).
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum RippleAmount {
    /// Native XRP amount in drops.
    Xrp(u64),
    /// Issued Currency (IOU) amount (e.g., RLUSD).
    Issued(IssuedAmount),
}

/// Supported XRPL transaction types.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Default)]
pub enum RippleTransactionType {
    /// Standard `Payment` transaction (`TransactionType = 0`).
    #[default]
    Payment,
    /// `TrustSet` transaction (`TransactionType = 20`) to create or modify a trust line.
    TrustSet,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RippleTransactionParameters {
    pub transaction_type: RippleTransactionType,
    pub destination: [u8; 20],
    pub fee: u32,
    pub sequence: u32,
    pub destination_tag: u32,
    pub amount: u64,
    pub issued_amount: Option<IssuedAmount>,
    pub send_max: Option<RippleAmount>,
    pub flags: Option<u32>,
    pub quality_in: Option<u32>,
    pub quality_out: Option<u32>,
    pub memos: Vec<String>,
    pub public_key: [u8; 33],
}

impl RippleTransactionParameters {
    /// Creates parameters for a native XRP `Payment` transaction.
    pub fn new_xrp_payment(
        destination: [u8; 20],
        fee: u32,
        sequence: u32,
        destination_tag: u32,
        amount: u64,
        memos: Vec<String>,
        public_key: [u8; 33],
    ) -> Self {
        Self {
            transaction_type: RippleTransactionType::Payment,
            destination,
            fee,
            sequence,
            destination_tag,
            amount,
            issued_amount: None,
            send_max: None,
            flags: None,
            quality_in: None,
            quality_out: None,
            memos,
            public_key,
        }
    }

    /// Creates parameters for an Issued Currency (e.g., RLUSD) `Payment` transaction.
    pub fn new_issued_payment(
        destination: [u8; 20],
        fee: u32,
        sequence: u32,
        destination_tag: u32,
        issued_amount: IssuedAmount,
        memos: Vec<String>,
        public_key: [u8; 33],
    ) -> Self {
        Self {
            transaction_type: RippleTransactionType::Payment,
            destination,
            fee,
            sequence,
            destination_tag,
            amount: 0,
            issued_amount: Some(issued_amount),
            send_max: None,
            flags: None,
            quality_in: None,
            quality_out: None,
            memos,
            public_key,
        }
    }

    /// Creates parameters for a `TrustSet` transaction (e.g., establishing an RLUSD trust line).
    pub fn new_trust_set(
        fee: u32,
        sequence: u32,
        limit_amount: IssuedAmount,
        flags: Option<u32>,
        memos: Vec<String>,
        public_key: [u8; 33],
    ) -> Self {
        Self {
            transaction_type: RippleTransactionType::TrustSet,
            destination: [0u8; 20],
            fee,
            sequence,
            destination_tag: 0,
            amount: 0,
            issued_amount: Some(limit_amount),
            send_max: None,
            flags,
            quality_in: None,
            quality_out: None,
            memos,
            public_key,
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RippleTransaction {
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

        let tx_type_val = match self.params.transaction_type {
            RippleTransactionType::Payment => 0,
            RippleTransactionType::TrustSet => 20,
        };

        let tx_type = SerializedType::Uint16 {
            field_value: 2,
            value: tx_type_val,
        };

        let account = SerializedType::Account {
            field_value: 1,
            account_id,
        };

        let fee = SerializedType::Amount {
            field_value: 8,
            value: AmountValue::Xrp(self.params.fee as u64 | 0x4000000000000000),
        };

        let sequence = SerializedType::Uint32 {
            field_value: 4,
            value: self.params.sequence,
        };

        let public_key = SerializedType::Blob {
            field_value: 3,
            buffer: self.params.public_key.to_vec(),
        };

        let mut members = vec![tx_type, account, fee, sequence, public_key];

        if let Some(flags) = self.params.flags {
            members.push(SerializedType::Uint32 {
                field_value: 2,
                value: flags,
            });
        }

        match self.params.transaction_type {
            RippleTransactionType::Payment => {
                let dest = SerializedType::Account {
                    field_value: 3,
                    account_id: self.params.destination,
                };
                let dest_tag = SerializedType::Uint32 {
                    field_value: 14,
                    value: self.params.destination_tag,
                };
                let amount_value = match &self.params.issued_amount {
                    Some(issued) => AmountValue::Issued(issued.clone()),
                    None => AmountValue::Xrp(self.params.amount | 0x4000000000000000),
                };
                let amount = SerializedType::Amount {
                    field_value: 1,
                    value: amount_value,
                };
                members.push(dest);
                members.push(dest_tag);
                members.push(amount);

                if let Some(send_max) = &self.params.send_max {
                    let sm_val = match send_max {
                        RippleAmount::Xrp(drops) => AmountValue::Xrp(*drops | 0x4000000000000000),
                        RippleAmount::Issued(iou) => AmountValue::Issued(iou.clone()),
                    };
                    members.push(SerializedType::Amount {
                        field_value: 9,
                        value: sm_val,
                    });
                }
            }
            RippleTransactionType::TrustSet => {
                let limit_issued = self.params.issued_amount.as_ref().ok_or_else(|| {
                    TransactionError::Message(
                        "TrustSet transaction requires an issued_amount (LimitAmount)".to_string(),
                    )
                })?;
                let limit_amount = SerializedType::Amount {
                    field_value: 3,
                    value: AmountValue::Issued(limit_issued.clone()),
                };
                members.push(limit_amount);

                if let Some(q_in) = self.params.quality_in {
                    members.push(SerializedType::Uint32 {
                        field_value: 20,
                        value: q_in,
                    });
                }
                if let Some(q_out) = self.params.quality_out {
                    members.push(SerializedType::Uint32 {
                        field_value: 21,
                        value: q_out,
                    });
                }
            }
        }

        let mut st = SerializedType::Object {
            field_value: 0,
            members,
        };

        let memos: Vec<SerializedType> = self
            .params
            .memos
            .iter()
            .map(|memo| {
                let memo_type = SerializedType::Blob {
                    field_value: 12,
                    buffer: "payment".as_bytes().to_vec(),
                };
                let memo = SerializedType::Blob {
                    field_value: 13,
                    buffer: memo.as_bytes().to_vec(),
                };
                SerializedType::Object {
                    field_value: 10,
                    members: vec![memo_type, memo],
                }
            })
            .collect();

        if !memos.is_empty() {
            st.add(SerializedType::Array {
                field_value: 9,
                elems: memos,
            })?
        }

        if let Some(sig) = &self.signature {
            let sig = Signature::parse_standard_slice(sig)
                .map_err(|error| TransactionError::Crate("libsecp256k1", format!("{:?}", error)))?
                .serialize_der()
                .as_ref()
                .to_vec();
            let sig = SerializedType::Blob {
                field_value: 4,
                buffer: sig,
            };
            st.add(sig)?;
        }

        // Ascendingly sort the object's members by SerializedTypeID. If SerializedTypeIDs
        // are equal, ascendingly sort them by field value
        st.sort()?;

        Ok(st)
    }

    fn from_st(st: &SerializedType) -> Result<Self, TransactionError> {
        if let SerializedType::Object { members, .. } = st {
            let mut transaction_type = RippleTransactionType::Payment;
            let mut source = [0u8; 20];
            let mut destination = [0u8; 20];
            let mut fee = 0;
            let mut sequence = 0;
            let mut destination_tag = 0;
            let mut amount = 0;
            let mut issued_amount: Option<IssuedAmount> = None;
            let mut send_max: Option<RippleAmount> = None;
            let mut flags: Option<u32> = None;
            let mut quality_in: Option<u32> = None;
            let mut quality_out: Option<u32> = None;
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
                            // Store source account (field 1) for later hash160(public_key) verification.
                            source = *account_id;
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
                            match value {
                                AmountValue::Xrp(v) => {
                                    amount = *v & !0x4000000000000000;
                                }
                                AmountValue::Issued(iou) => {
                                    issued_amount = Some(iou.clone());
                                }
                            }
                        } else if *field_value == 3 {
                            // LimitAmount for TrustSet
                            match value {
                                AmountValue::Issued(iou) => {
                                    issued_amount = Some(iou.clone());
                                }
                                AmountValue::Xrp(_) => {
                                    return Err(TransactionError::Message(
                                        "LimitAmount cannot be native XRP".to_string(),
                                    ));
                                }
                            }
                        } else if *field_value == 8 {
                            match value {
                                AmountValue::Xrp(v) => {
                                    fee = (*v & !0x4000000000000000) as u32;
                                }
                                AmountValue::Issued(_) => {
                                    return Err(TransactionError::Message(
                                        "Transaction fee must be native XRP".to_string(),
                                    ));
                                }
                            }
                        } else if *field_value == 9 {
                            match value {
                                AmountValue::Xrp(v) => {
                                    send_max = Some(RippleAmount::Xrp(*v & !0x4000000000000000));
                                }
                                AmountValue::Issued(iou) => {
                                    send_max = Some(RippleAmount::Issued(iou.clone()));
                                }
                            }
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
                            let sig = Signature::parse_der(buffer)
                                .map_err(|error| {
                                    TransactionError::Crate("libsecp256k1", format!("{:?}", error))
                                })?
                                .serialize()
                                .to_vec();
                            signature = Some(sig);
                        } else {
                            return Err(TransactionError::Message(format!(
                                "Invalid field value {} for serialized type 'blob'",
                                *field_value,
                            )));
                        }
                    }
                    SerializedType::Uint32 { field_value, value } => {
                        if *field_value == 2 {
                            flags = Some(*value);
                        } else if *field_value == 4 {
                            sequence = *value;
                        } else if *field_value == 14 {
                            destination_tag = *value;
                        } else if *field_value == 20 {
                            quality_in = Some(*value);
                        } else if *field_value == 21 {
                            quality_out = Some(*value);
                        } else {
                            return Err(TransactionError::Message(format!(
                                "Invalid field value {} for serialized type 'integer'",
                                *field_value,
                            )));
                        }
                    }
                    SerializedType::Uint16 { field_value, value } => {
                        if *field_value == 2 {
                            transaction_type = match *value {
                                0 => RippleTransactionType::Payment,
                                20 => RippleTransactionType::TrustSet,
                                other => {
                                    return Err(TransactionError::Message(format!(
                                        "Unsupported transaction type {}",
                                        other
                                    )))
                                }
                            };
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

            // Enforce that Account(source) matches the signer public key hash.
            let derived_source = hash160(&public_key);
            if source != derived_source.as_slice() {
                return Err(TransactionError::Message(format!(
                    "Invalid source account: expected {}, got {}",
                    hex::encode(derived_source),
                    hex::encode(source),
                )));
            }

            let mut tx = RippleTransaction::new(&RippleTransactionParameters {
                transaction_type,
                destination,
                fee,
                sequence,
                destination_tag,
                amount,
                issued_amount,
                send_max,
                flags,
                quality_in,
                quality_out,
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

    pub fn set_public_key(&mut self, pk: Vec<u8>) -> Result<(), TransactionError> {
        self.params.public_key = pk.try_into().unwrap();
        Ok(())
    }
}

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct RippleTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for RippleTransactionId {}

impl fmt::Display for RippleTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.txid).to_uppercase())
    }
}

#[derive(PartialEq)]
enum SerializedTypeID {
    Uint16 = 1,
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
            1 => Ok(Self::Uint16),
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
            Self::Uint16 => write!(f, "Uint16"),
            Self::Uint32 => write!(f, "Uint32"),
            Self::Amount => write!(f, "Amount"),
            Self::VL => write!(f, "Blob"),
            Self::Account => write!(f, "Account"),
            Self::Object => write!(f, "Object"),
            Self::Array => write!(f, "Array"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AmountValue {
    Xrp(u64),
    Issued(IssuedAmount),
}

#[derive(Clone, Debug, Eq)]
enum SerializedType {
    Account {
        field_value: u32,
        account_id: [u8; 20],
    },

    Amount {
        field_value: u32,
        value: AmountValue,
    },

    Uint16 {
        field_value: u32,
        value: u16,
    },

    Uint32 {
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

impl PartialEq for SerializedType {
    fn eq(&self, other: &Self) -> bool {
        let typ0 = self.typ() as u32;
        let val0 = self.val();
        let typ1 = other.typ() as u32;
        let val1 = other.val();

        typ0 == typ1 && val0 == val1
    }
}

impl Ord for SerializedType {
    fn cmp(&self, other: &Self) -> Ordering {
        let typ0 = self.typ() as u32;
        let val0 = self.val();
        let typ1 = other.typ() as u32;
        let val1 = other.val();

        if typ0 < typ1 {
            Ordering::Less
        } else if typ0 > typ1 {
            Ordering::Greater
        } else if val0 < val1 {
            Ordering::Less
        } else if val0 > val1 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

impl PartialOrd for SerializedType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
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
            Self::Uint16 { .. } => SerializedTypeID::Uint16,
            Self::Uint32 { .. } => SerializedTypeID::Uint32,
            Self::Blob { .. } => SerializedTypeID::VL,
            Self::Array { .. } => SerializedTypeID::Array,
            Self::Object { .. } => SerializedTypeID::Object,
        }
    }

    fn val(&self) -> u32 {
        match self {
            Self::Account { field_value, .. } => *field_value,
            Self::Amount { field_value, .. } => *field_value,
            Self::Uint16 { field_value, .. } => *field_value,
            Self::Uint32 { field_value, .. } => *field_value,
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
            Self::Amount { value, .. } => match value {
                AmountValue::Xrp(v) => Ok(v.to_be_bytes().to_vec()),
                AmountValue::Issued(iou) => Ok(iou.to_bytes().to_vec()),
            },
            Self::Uint16 { value, .. } => Ok(value.to_be_bytes().to_vec()),
            Self::Uint32 { value, .. } => Ok(value.to_be_bytes().to_vec()),
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
                let mut first_eight = [0u8; 8];
                let _ = stream.read(&mut first_eight)?;

                // Bit 63 (first_eight[0] & 0x80) indicates whether this is an Issued Currency (1) or native XRP (0).
                let value = if first_eight[0] & 0x80 == 0 {
                    AmountValue::Xrp(u64::from_be_bytes(first_eight))
                } else {
                    let mut raw_iou = [0u8; 48];
                    raw_iou[0..8].copy_from_slice(&first_eight);
                    let _ = stream.read(&mut raw_iou[8..48])?;
                    AmountValue::Issued(IssuedAmount::from_bytes(&raw_iou)?)
                };

                // Return the ST
                Ok(SerializedType::Amount { field_value, value })
            }
            SerializedTypeID::Uint16 => {
                let mut value = [0u8; 2];
                let _ = stream.read(&mut value)?;
                let value = u16::from_be_bytes(value);

                // Return the ST
                Ok(SerializedType::Uint16 { field_value, value })
            }
            SerializedTypeID::Uint32 => {
                let mut value = [0u8; 4];
                let _ = stream.read(&mut value)?;
                let value = u32::from_be_bytes(value);

                // Return the ST
                Ok(SerializedType::Uint32 { field_value, value })
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
                    array.add(st)?;
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
                    if typ == SerializedTypeID::Object && fv == 1 {
                        break;
                    }

                    let st = Self::deserialize(stream, typ, fv as u32)?;
                    obj.add(st)?;
                }
                Ok(obj)
            }
        }
    }

    fn add(&mut self, st: SerializedType) -> Result<(), TransactionError> {
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

    fn sort(&mut self) -> Result<(), TransactionError> {
        match self {
            SerializedType::Object { members, .. } => {
                members.sort();
                Ok(())
            }
            _ => Err(TransactionError::Message(
                "Sorting non-object ST".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encode_currency_code, trust_set_flags, IssuedAmount, RippleAddress, RippleAmount,
        RippleFormat, RipplePublicKey, RippleTransactionType, RLUSD_CURRENCY_CODE,
        RLUSD_MAINNET_ISSUER, RLUSD_TESTNET_ISSUER,
    };

    use super::{RippleTransaction, RippleTransactionParameters};
    use anychain_core::{hex, PublicKey, Transaction, TransactionError};
    use libsecp256k1::{self, Message, SecretKey};
    use std::str::FromStr;

    #[test]
    fn test_tx_gen() {
        let sk_from = [
            1u8, 1, 1, 1, 1, 117, 1, 1, 1, 1, 1, 1, 118, 1, 1, 92, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1,
        ];

        let sk_to = [
            1u8, 1, 8, 1, 33, 17, 1, 1, 1, 99, 1, 1, 18, 1, 1, 2, 1, 1, 1, 1, 1, 37, 1, 1, 101, 7,
            1, 1, 1, 0, 1, 2,
        ];

        let sk_from = SecretKey::parse(&sk_from).unwrap();
        let sk_to = SecretKey::parse(&sk_to).unwrap();

        let pk_from = RipplePublicKey::from_secret_key(&sk_from);
        let pk_to = RipplePublicKey::from_secret_key(&sk_to);

        let from = pk_from.to_address(&RippleFormat::Standard).unwrap();
        let to = pk_to.to_address(&RippleFormat::Standard).unwrap();

        assert_eq!(from.to_string(), "rDZr8KX1A5Ws1DyT7jZd8TPonchDzDGfX2");
        assert_eq!(to.to_string(), "rpnZmX9CW1QoP2uPRgB5mupp9exFyZmuKM");

        let pk_from = pk_from.serialize();

        let params = RippleTransactionParameters::new_xrp_payment(
            to.to_hash160().unwrap(),
            500000,
            39998031,
            50,
            100000000,
            vec!["guai".to_string()],
            pk_from.try_into().unwrap(),
        );

        let mut tx = RippleTransaction::new(&params).unwrap();

        let txid = tx.to_transaction_id().unwrap().txid;
        let msg = Message::parse_slice(&txid).unwrap();
        let sig = libsecp256k1::sign(&msg, &sk_from).0.serialize().to_vec();

        let tx = tx.sign(sig, 0).unwrap();
        let tx = RippleTransaction::from_bytes(&tx).unwrap();

        assert_eq!("120000240262524f2e00000032614000000005f5e10068400000000007a120732102b722a70170451981d269bb52db986c46cd5e46d82628f7770fbc2962a60c5e997446304402200adf9912caaf33ef357031cd46a49c026e5780ca198b1d32dfd252f38fdde572022056b953c08d31b0d68ed6e9ffb810fd8deeefbad21d08f82527bbfa3ec6de0330811489af78f1b802fca6dfaa06c9b6807d2288a9c3be83140bd52483842334109d52935847c4bc188a04998ff9ea7c077061796d656e747d0467756169e1f1", tx.to_string());
    }

    #[test]
    fn test_tx_from_str() {
        let tx = "120000240262524f2e00000032614000000005f5e10068400000000007a120732102b722a70170451981d269bb52db986c46cd5e46d82628f7770fbc2962a60c5e997446304402200adf9912caaf33ef357031cd46a49c026e5780ca198b1d32dfd252f38fdde572022056b953c08d31b0d68ed6e9ffb810fd8deeefbad21d08f82527bbfa3ec6de0330811489af78f1b802fca6dfaa06c9b6807d2288a9c3be83140bd52483842334109d52935847c4bc188a04998ff9ea7c077061796d656e747d0467756169e1f1";
        let tx = RippleTransaction::from_str(tx).unwrap();

        assert_eq!(tx.params.transaction_type, RippleTransactionType::Payment);
        assert_eq!(
            tx.params.destination,
            [
                11, 213, 36, 131, 132, 35, 52, 16, 157, 82, 147, 88, 71, 196, 188, 24, 138, 4, 153,
                143
            ]
        );
        assert_eq!(tx.params.fee, 500000);
        assert_eq!(tx.params.sequence, 39998031);
        assert_eq!(tx.params.destination_tag, 50);
        assert_eq!(tx.params.amount, 100000000);
        assert!(tx.params.issued_amount.is_none());
        assert_eq!(tx.params.memos.len(), 1);
        assert_eq!(
            tx.params.public_key,
            [
                2, 183, 34, 167, 1, 112, 69, 25, 129, 210, 105, 187, 82, 219, 152, 108, 70, 205,
                94, 70, 216, 38, 40, 247, 119, 15, 188, 41, 98, 166, 12, 94, 153
            ]
        );
        let expected_signagure: Vec<u8> = [
            10, 223, 153, 18, 202, 175, 51, 239, 53, 112, 49, 205, 70, 164, 156, 2, 110, 87, 128,
            202, 25, 139, 29, 50, 223, 210, 82, 243, 143, 221, 229, 114, 86, 185, 83, 192, 141, 49,
            176, 214, 142, 214, 233, 255, 184, 16, 253, 141, 238, 239, 186, 210, 29, 8, 248, 37,
            39, 187, 250, 62, 198, 222, 3, 48,
        ]
        .into();
        assert_eq!(tx.signature, Some(expected_signagure));
    }

    #[test]
    fn test_tx_from_str_rejects_tampered_source_account() {
        let tx = "120000240262524f2e00000032614000000005f5e10068400000000007a120732102b722a70170451981d269bb52db986c46cd5e46d82628f7770fbc2962a60c5e997446304402200adf9912caaf33ef357031cd46a49c026e5780ca198b1d32dfd252f38fdde572022056b953c08d31b0d68ed6e9ffb810fd8deeefbad21d08f82527bbfa3ec6de0330811489af78f1b802fca6dfaa06c9b6807d2288a9c3be83140bd52483842334109d52935847c4bc188a04998ff9ea7c077061796d656e747d0467756169e1f1";

        // Tamper source account (field 0x81 + len 0x14 + 20-byte payload) but keep SigningPubKey unchanged.
        let tampered = tx.replacen(
            "811489af78f1b802fca6dfaa06c9b6807d2288a9c3b",
            "811400af78f1b802fca6dfaa06c9b6807d2288a9c3b",
            1,
        );

        let err = RippleTransaction::from_str(&tampered).unwrap_err();
        assert!(matches!(
            err,
            TransactionError::Message(msg) if msg.contains("Invalid source account")
        ));
    }

    #[test]
    fn test_currency_code_encoding() {
        let rlusd = encode_currency_code("RLUSD").unwrap();
        assert_eq!(rlusd, RLUSD_CURRENCY_CODE);
        assert_eq!(
            hex::encode(rlusd).to_uppercase(),
            "524C555344000000000000000000000000000000"
        );

        let rlusd_hex = encode_currency_code("524C555344000000000000000000000000000000").unwrap();
        assert_eq!(rlusd_hex, RLUSD_CURRENCY_CODE);

        let usd = encode_currency_code("USD").unwrap();
        assert_eq!(
            hex::encode(usd).to_uppercase(),
            "0000000000000000000000005553440000000000"
        );

        assert!(encode_currency_code("XRP").is_err());
    }

    #[test]
    fn test_issued_amount_encoding_and_roundtrip() {
        let issuer = RippleAddress::from_str(RLUSD_MAINNET_ISSUER)
            .unwrap()
            .to_hash160()
            .unwrap();

        // 100.50 RLUSD -> 1005000000000000 * 10^-13 -> biased exp = 84 (0x54)
        let amt = IssuedAmount::rlusd_mainnet("100.50").unwrap();
        assert!(!amt.is_negative);
        assert_eq!(amt.mantissa, 1_005_000_000_000_000);
        assert_eq!(amt.exponent, -13);
        assert_eq!(amt.currency, RLUSD_CURRENCY_CODE);
        assert_eq!(amt.issuer, issuer);

        let bytes = amt.to_bytes();
        let decoded = IssuedAmount::from_bytes(&bytes).unwrap();
        assert_eq!(amt, decoded);

        // Zero amount test (used to remove a trust line)
        let zero_amt = IssuedAmount::rlusd_mainnet("0").unwrap();
        assert_eq!(zero_amt.mantissa, 0);
        assert_eq!(zero_amt.encode_value_bits(), 0x8000_0000_0000_0000);
        let zero_decoded = IssuedAmount::from_bytes(&zero_amt.to_bytes()).unwrap();
        assert_eq!(zero_amt, zero_decoded);
    }

    #[test]
    fn test_rlusd_payment_tx_roundtrip() {
        let sk_from = [
            1u8, 1, 1, 1, 1, 117, 1, 1, 1, 1, 1, 1, 118, 1, 1, 92, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1,
        ];
        let sk_to = [
            1u8, 1, 8, 1, 33, 17, 1, 1, 1, 99, 1, 1, 18, 1, 1, 2, 1, 1, 1, 1, 1, 37, 1, 1, 101, 7,
            1, 1, 1, 0, 1, 2,
        ];

        let sk_from = SecretKey::parse(&sk_from).unwrap();
        let sk_to = SecretKey::parse(&sk_to).unwrap();

        let pk_from = RipplePublicKey::from_secret_key(&sk_from);
        let pk_to = RipplePublicKey::from_secret_key(&sk_to);
        let to = pk_to.to_address(&RippleFormat::Standard).unwrap();

        let rlusd_amount = IssuedAmount::rlusd_mainnet("25.75").unwrap();

        let params = RippleTransactionParameters::new_issued_payment(
            to.to_hash160().unwrap(),
            12,
            100,
            42,
            rlusd_amount.clone(),
            vec!["rlusd-payment".to_string()],
            pk_from.serialize().try_into().unwrap(),
        );

        let mut tx = RippleTransaction::new(&params).unwrap();
        let digest = tx.to_transaction_id().unwrap().txid;
        let msg = Message::parse_slice(&digest).unwrap();
        let sig = libsecp256k1::sign(&msg, &sk_from).0.serialize().to_vec();

        let signed_bytes = tx.sign(sig.clone(), 0).unwrap();
        let decoded_tx = RippleTransaction::from_bytes(&signed_bytes).unwrap();

        assert_eq!(
            decoded_tx.params.transaction_type,
            RippleTransactionType::Payment
        );
        assert_eq!(decoded_tx.params.destination, to.to_hash160().unwrap());
        assert_eq!(decoded_tx.params.fee, 12);
        assert_eq!(decoded_tx.params.sequence, 100);
        assert_eq!(decoded_tx.params.destination_tag, 42);
        assert_eq!(decoded_tx.params.issued_amount, Some(rlusd_amount));
        assert_eq!(decoded_tx.params.memos, vec!["rlusd-payment".to_string()]);
        assert_eq!(decoded_tx.signature, Some(sig));
    }

    #[test]
    fn test_rlusd_trust_set_tx_roundtrip() {
        let sk_from = [
            1u8, 1, 1, 1, 1, 117, 1, 1, 1, 1, 1, 1, 118, 1, 1, 92, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1,
        ];
        let sk_from = SecretKey::parse(&sk_from).unwrap();
        let pk_from = RipplePublicKey::from_secret_key(&sk_from);

        let limit_amount = IssuedAmount::rlusd_mainnet("1000000000").unwrap();

        let params = RippleTransactionParameters::new_trust_set(
            12,
            101,
            limit_amount.clone(),
            Some(trust_set_flags::TF_SET_NO_RIPPLE),
            vec![],
            pk_from.serialize().try_into().unwrap(),
        );

        let mut tx = RippleTransaction::new(&params).unwrap();
        let digest = tx.to_transaction_id().unwrap().txid;
        let msg = Message::parse_slice(&digest).unwrap();
        let sig = libsecp256k1::sign(&msg, &sk_from).0.serialize().to_vec();

        let signed_bytes = tx.sign(sig.clone(), 0).unwrap();
        let decoded_tx = RippleTransaction::from_bytes(&signed_bytes).unwrap();

        assert_eq!(
            decoded_tx.params.transaction_type,
            RippleTransactionType::TrustSet
        );
        assert_eq!(decoded_tx.params.fee, 12);
        assert_eq!(decoded_tx.params.sequence, 101);
        assert_eq!(decoded_tx.params.issued_amount, Some(limit_amount));
        assert_eq!(
            decoded_tx.params.flags,
            Some(trust_set_flags::TF_SET_NO_RIPPLE)
        );
        assert_eq!(decoded_tx.signature, Some(sig));
    }

    #[test]
    #[ignore]
    fn test_live_testnet_official_rlusd_trustset_and_payment() {
        use std::process::Command;

        // Two holder accounts on XRPL Testnet that transact OFFICIAL Testnet RLUSD
        // (issuer: `rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV`).
        let sk_holder_a = SecretKey::parse(&[0x51u8; 32]).unwrap();
        let sk_holder_b = SecretKey::parse(&[0x52u8; 32]).unwrap();

        let pk_holder_a = RipplePublicKey::from_secret_key(&sk_holder_a);
        let pk_holder_b = RipplePublicKey::from_secret_key(&sk_holder_b);

        let addr_holder_a = pk_holder_a.to_address(&RippleFormat::Standard).unwrap();
        let addr_holder_b = pk_holder_b.to_address(&RippleFormat::Standard).unwrap();

        println!("Official RLUSD Testnet Issuer: {}", RLUSD_TESTNET_ISSUER);
        println!("Holder A Address: {}", addr_holder_a);
        println!("Holder B Address: {}", addr_holder_b);

        let get_account_info = |addr: &RippleAddress| -> String {
            let body = format!(
                r#"{{"method":"account_info","params":[{{"account":"{}","ledger_index":"validated"}}]}}"#,
                addr
            );
            let out = Command::new("curl")
                .args([
                    "-s",
                    "-X",
                    "POST",
                    "https://s.altnet.rippletest.net:51234/",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    &body,
                ])
                .output()
                .expect("Failed to call account_info");
            String::from_utf8_lossy(&out.stdout).to_string()
        };

        // Fund Holder A and Holder B via XRPL Testnet Faucet if not yet funded
        let mut funded_any = false;
        for addr in [&addr_holder_a, &addr_holder_b] {
            let info = get_account_info(addr);
            if !info.contains("\"Sequence\":") {
                let body = format!(r#"{{"destination":"{}"}}"#, addr);
                let out = Command::new("curl")
                    .args([
                        "-s",
                        "-X",
                        "POST",
                        "https://faucet.altnet.rippletest.net/accounts",
                        "-H",
                        "Content-Type: application/json",
                        "-d",
                        &body,
                    ])
                    .output()
                    .expect("Failed to call testnet faucet");
                println!(
                    "Faucet response for {}: {}",
                    addr,
                    String::from_utf8_lossy(&out.stdout)
                );
                funded_any = true;
            }
        }

        if funded_any {
            std::thread::sleep(std::time::Duration::from_secs(7));
        }

        let get_sequence = |addr: &RippleAddress| -> u32 {
            let resp = get_account_info(addr);
            let marker = "\"Sequence\":";
            let idx = resp
                .find(marker)
                .expect("Sequence field not found in account_info")
                + marker.len();
            let rest = &resp[idx..];
            let end = rest.find([',', '}']).unwrap();
            rest[..end].trim().parse::<u32>().unwrap()
        };

        let submit_blob = |tx_blob: &str| -> String {
            let body = format!(
                r#"{{"method":"submit","params":[{{"tx_blob":"{}"}}]}}"#,
                tx_blob
            );
            let out = Command::new("curl")
                .args([
                    "-s",
                    "-X",
                    "POST",
                    "https://s.altnet.rippletest.net:51234/",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    &body,
                ])
                .output()
                .expect("Failed to submit tx_blob");
            String::from_utf8_lossy(&out.stdout).to_string()
        };

        let get_account_lines = |addr: &RippleAddress| -> String {
            let lines_body = format!(
                r#"{{"method":"account_lines","params":[{{"account":"{}","ledger_index":"validated"}}]}}"#,
                addr
            );
            let lines_out = Command::new("curl")
                .args([
                    "-s",
                    "-X",
                    "POST",
                    "https://s.altnet.rippletest.net:51234/",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    &lines_body,
                ])
                .output()
                .expect("Failed to call account_lines");
            String::from_utf8_lossy(&lines_out.stdout).to_string()
        };

        let mut seq_a = get_sequence(&addr_holder_a);
        let mut seq_b = get_sequence(&addr_holder_b);

        // Step 1: Both Holder A and Holder B establish a TrustSet to the official RLUSD Testnet issuer (`rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV`)
        let official_limit = IssuedAmount::rlusd_testnet("1000000").unwrap();
        let initial_lines_a = get_account_lines(&addr_holder_a);
        let initial_lines_b = get_account_lines(&addr_holder_b);
        println!(
            "Initial lines Holder A ({}): {}",
            addr_holder_a, initial_lines_a
        );
        println!(
            "Initial lines Holder B ({}): {}",
            addr_holder_b, initial_lines_b
        );

        if !initial_lines_a.contains(RLUSD_TESTNET_ISSUER) {
            for (label, addr, sk, pk, seq) in [
                (
                    "Holder A",
                    &addr_holder_a,
                    &sk_holder_a,
                    &pk_holder_a,
                    seq_a,
                ),
                (
                    "Holder B",
                    &addr_holder_b,
                    &sk_holder_b,
                    &pk_holder_b,
                    seq_b,
                ),
            ] {
                let trust_params = RippleTransactionParameters::new_trust_set(
                    12,
                    seq,
                    official_limit.clone(),
                    Some(trust_set_flags::TF_SET_NO_RIPPLE),
                    vec!["official-rlusd-trustset".to_string()],
                    pk.serialize().try_into().unwrap(),
                );
                let mut trust_tx = RippleTransaction::new(&trust_params).unwrap();
                let digest = trust_tx.to_transaction_id().unwrap().txid;
                let sig = libsecp256k1::sign(&Message::parse_slice(&digest).unwrap(), sk)
                    .0
                    .serialize()
                    .to_vec();
                let blob = hex::encode(trust_tx.sign(sig, 0).unwrap()).to_uppercase();
                let txid = trust_tx.to_transaction_id().unwrap().to_string();
                let resp = submit_blob(&blob);
                println!(
                    "{} ({}) TrustSet txid={} response: {}",
                    label, addr, txid, resp
                );
                assert!(
                    resp.contains("\"engine_result\":\"tesSUCCESS\""),
                    "{} TrustSet failed: {}",
                    label,
                    resp
                );
            }
            seq_a += 1;
            seq_b += 1;

            std::thread::sleep(std::time::Duration::from_secs(6));

            // Step 2: Holder A acquires official Testnet RLUSD from the XRPL Testnet DEX/AMM
            let acquire_amount = IssuedAmount::rlusd_testnet("100").unwrap();
            let mut acquire_params = RippleTransactionParameters::new_issued_payment(
                addr_holder_a.to_hash160().unwrap(),
                12,
                seq_a,
                100,
                acquire_amount,
                vec!["acquire-official-rlusd".to_string()],
                pk_holder_a.serialize().try_into().unwrap(),
            );
            acquire_params.send_max = Some(RippleAmount::Xrp(25_000_000));
            acquire_params.flags = Some(0x0002_0000); // tfPartialPayment

            let mut acquire_tx = RippleTransaction::new(&acquire_params).unwrap();
            let acquire_digest = acquire_tx.to_transaction_id().unwrap().txid;
            let acquire_sig = libsecp256k1::sign(
                &Message::parse_slice(&acquire_digest).unwrap(),
                &sk_holder_a,
            )
            .0
            .serialize()
            .to_vec();
            let acquire_blob = hex::encode(acquire_tx.sign(acquire_sig, 0).unwrap()).to_uppercase();
            let acquire_txid = acquire_tx.to_transaction_id().unwrap().to_string();
            let acquire_resp = submit_blob(&acquire_blob);
            println!(
                "Holder A DEX Acquire Official RLUSD txid={} response: {}",
                acquire_txid, acquire_resp
            );
            assert!(
                acquire_resp.contains("\"engine_result\":\"tesSUCCESS\""),
                "Acquire official RLUSD failed: {}",
                acquire_resp
            );
            seq_a += 1;

            std::thread::sleep(std::time::Duration::from_secs(6));

            // Step 3: Holder A transfers 1 official Testnet RLUSD to Holder B
            let transfer_amount = IssuedAmount::rlusd_testnet("1").unwrap();
            let transfer_params = RippleTransactionParameters::new_issued_payment(
                addr_holder_b.to_hash160().unwrap(),
                12,
                seq_a,
                200,
                transfer_amount,
                vec!["official-rlusd-transfer".to_string()],
                pk_holder_a.serialize().try_into().unwrap(),
            );
            let mut transfer_tx = RippleTransaction::new(&transfer_params).unwrap();
            let transfer_digest = transfer_tx.to_transaction_id().unwrap().txid;
            let transfer_sig = libsecp256k1::sign(
                &Message::parse_slice(&transfer_digest).unwrap(),
                &sk_holder_a,
            )
            .0
            .serialize()
            .to_vec();
            let transfer_blob =
                hex::encode(transfer_tx.sign(transfer_sig, 0).unwrap()).to_uppercase();
            let transfer_txid = transfer_tx.to_transaction_id().unwrap().to_string();
            let transfer_resp = submit_blob(&transfer_blob);
            println!(
                "Official RLUSD Payment (Holder A -> Holder B) txid={} response: {}",
                transfer_txid, transfer_resp
            );
            assert!(
                transfer_resp.contains("\"engine_result\":\"tesSUCCESS\""),
                "Official RLUSD transfer failed: {}",
                transfer_resp
            );

            std::thread::sleep(std::time::Duration::from_secs(6));
        }

        // Step 4: Holder B (`rEHw8JLaSF7EhwtdLcimWe9JQRxt6bgDq6`) transfers 0.5 official RLUSD
        // back to Holder A (`rJYemKok5Na5MBDWnJVALjYBDH5FZdCVsZ`)
        let return_amount = IssuedAmount::rlusd_testnet("0.5").unwrap();
        let return_params = RippleTransactionParameters::new_issued_payment(
            addr_holder_a.to_hash160().unwrap(),
            12,
            seq_b,
            300,
            return_amount,
            vec!["official-rlusd-return-0.5".to_string()],
            pk_holder_b.serialize().try_into().unwrap(),
        );
        let mut return_tx = RippleTransaction::new(&return_params).unwrap();
        let return_digest = return_tx.to_transaction_id().unwrap().txid;
        let return_sig =
            libsecp256k1::sign(&Message::parse_slice(&return_digest).unwrap(), &sk_holder_b)
                .0
                .serialize()
                .to_vec();
        let return_blob = hex::encode(return_tx.sign(return_sig, 0).unwrap()).to_uppercase();
        let return_txid = return_tx.to_transaction_id().unwrap().to_string();
        let return_resp = submit_blob(&return_blob);
        println!(
            "Official RLUSD Payment (Holder B -> Holder A, 0.5 RLUSD) txid={} response: {}",
            return_txid, return_resp
        );
        assert!(
            return_resp.contains("\"engine_result\":\"tesSUCCESS\""),
            "Official RLUSD 0.5 return transfer failed: {}",
            return_resp
        );

        std::thread::sleep(std::time::Duration::from_secs(7));

        let lines_a = get_account_lines(&addr_holder_a);
        let lines_b = get_account_lines(&addr_holder_b);
        println!(
            "Validated account_lines for Holder A ({}): {}",
            addr_holder_a, lines_a
        );
        println!(
            "Validated account_lines for Holder B ({}): {}",
            addr_holder_b, lines_b
        );
    }
}
