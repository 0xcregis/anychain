use anychain_core::no_std::*;
use anychain_core::{Amount, AmountError};

use core::fmt;
use std::ops::{Add, Sub};

// Number of satoshis (base unit) per BCH
const COIN: i64 = 1_0000_0000;

// Maximum number of satoshis
const MAX_COINS: i64 = 21_000_000 * COIN;

/// Represents the amount of Bitcoin cash in satoshis
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoincashAmount(pub i64);

pub enum Denomination {
    // sat
    Satoshi,
    // uBCH (bit)
    MicroBch,
    // mBCH
    MilliBch,
    // cBCH
    CentiBch,
    // dBCH
    DeciBch,
    // BCH
    BitcoinCash,
}

impl Denomination {
    /// The number of decimal places more than a satoshi.
    fn precision(self) -> u32 {
        match self {
            Denomination::Satoshi => 0,
            Denomination::MicroBch => 2,
            Denomination::MilliBch => 5,
            Denomination::CentiBch => 6,
            Denomination::DeciBch => 7,
            Denomination::BitcoinCash => 8,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::Satoshi => "satoshi",
                Denomination::MicroBch => "uBCH",
                Denomination::MilliBch => "mBCH",
                Denomination::CentiBch => "cBCH",
                Denomination::DeciBch => "dBCH",
                Denomination::BitcoinCash => "BCH",
            }
        )
    }
}

impl Amount for BitcoincashAmount {}

impl BitcoincashAmount {
    /// The zero amount.
    pub const ZERO: BitcoincashAmount = BitcoincashAmount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: BitcoincashAmount = BitcoincashAmount(1);
    /// Exactly one bitcoin.
    pub const ONE_BCH: BitcoincashAmount = BitcoincashAmount(COIN);

    pub fn from_satoshi(satoshis: i64) -> Result<Self, AmountError> {
        if (-MAX_COINS..=MAX_COINS).contains(&satoshis) {
            Ok(Self(satoshis))
        } else {
            Err(AmountError::AmountOutOfBounds(
                satoshis.to_string(),
                MAX_COINS.to_string(),
            ))
        }
    }

    pub fn from_ubch(ubtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = ubtc_value * 10_i64.pow(Denomination::MicroBch.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_mbch(mbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = mbtc_value * 10_i64.pow(Denomination::MilliBch.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_cbch(cbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = cbtc_value * 10_i64.pow(Denomination::CentiBch.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_dbch(dbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = dbtc_value * 10_i64.pow(Denomination::DeciBch.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_bch(btc_value: i64) -> Result<Self, AmountError> {
        let satoshis = btc_value * 10_i64.pow(Denomination::BitcoinCash.precision());

        Self::from_satoshi(satoshis)
    }
}

impl Add for BitcoincashAmount {
    type Output = Result<Self, AmountError>;
    fn add(self, rhs: Self) -> Self::Output {
        Self::from_satoshi(self.0 + rhs.0)
    }
}

impl Sub for BitcoincashAmount {
    type Output = Result<Self, AmountError>;
    fn sub(self, rhs: Self) -> Self::Output {
        Self::from_satoshi(self.0 - rhs.0)
    }
}

impl fmt::Display for BitcoincashAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
