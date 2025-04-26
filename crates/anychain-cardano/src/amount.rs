//! Definitions for the native Cardano token and its fractional LOVELACE.

use {
    anychain_core::{to_basic_unit_u64, Amount, AmountError},
    core::fmt,
    serde::{Deserialize, Serialize},
    std::ops::{Add, Sub},
};

/// Represents the amount of SOL in lamports
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CardanoAmount(pub u64);

pub enum Denomination {
    LOVELACE,
    ADA,
}

impl Denomination {
    /// The number of decimal places more than one LOVELACE.
    /// There are 10^6 LOVELACE in one ADA
    fn precision(self) -> u64 {
        match self {
            Denomination::LOVELACE => 0,

            Denomination::ADA => 6,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::LOVELACE => "lovelace",
                Denomination::ADA => "ADA",
            }
        )
    }
}

impl Amount for CardanoAmount {}

impl CardanoAmount {
    pub fn from_u64(lovelace: u64) -> Self {
        Self(lovelace)
    }

    pub fn from_u64_str(value: &str) -> Result<u64, AmountError> {
        match value.parse::<u64>() {
            Ok(lovelace) => Ok(lovelace),
            Err(error) => Err(AmountError::Crate("uint", format!("{:?}", error))),
        }
    }
    pub fn from_lovelace(lovelace_value: &str) -> Result<Self, AmountError> {
        let lovelace = Self::from_u64_str(lovelace_value)?;
        Ok(Self::from_u64(lovelace))
    }

    pub fn from_ada(sol_value: &str) -> Result<Self, AmountError> {
        let lovelace_value = to_basic_unit_u64(sol_value, Denomination::ADA.precision());
        let lovelace = Self::from_u64_str(&lovelace_value)?;
        Ok(Self::from_u64(lovelace))
    }
}

impl Add for CardanoAmount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for CardanoAmount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for CardanoAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    fn test_from_lovelace(lovelace_value: &str, expected_amount: &str) {
        let amount = CardanoAmount::from_lovelace(lovelace_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_ada(ada_value: &str, expected_amount: &str) {
        let amount = CardanoAmount::from_ada(ada_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    pub struct AmountDenominationTestCase {
        lovelace: &'static str,
        ada: &'static str,
    }

    const TEST_AMOUNTS: [AmountDenominationTestCase; 2] = [
        AmountDenominationTestCase {
            lovelace: "0",
            ada: "0",
        },
        AmountDenominationTestCase {
            lovelace: "1000000",
            ada: "1",
        },
    ];

    #[test]
    fn test_lovelace_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_lovelace(amounts.lovelace, amounts.lovelace));
    }

    #[test]
    fn test_sol_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_ada(amounts.ada, amounts.lovelace));
    }

    fn test_addition(a: &str, b: &str, result: &str) {
        let a = CardanoAmount::from_lovelace(a).unwrap();
        let b = CardanoAmount::from_lovelace(b).unwrap();
        let result = CardanoAmount::from_lovelace(result).unwrap();

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &str, b: &str, result: &str) {
        let a = CardanoAmount::from_lovelace(a).unwrap();
        let b = CardanoAmount::from_lovelace(b).unwrap();
        let result = CardanoAmount::from_lovelace(result).unwrap();

        assert_eq!(result, a.sub(b));
    }
    mod valid_arithmetic {
        use super::*;

        const TEST_VALUES: [(&str, &str, &str); 5] = [
            ("0", "0", "0"),
            ("1", "2", "3"),
            ("100000", "0", "100000"),
            ("123456789", "987654321", "1111111110"),
            ("1000000000000000", "2000000000000000", "3000000000000000"),
        ];

        #[test]
        fn test_valid_addition() {
            TEST_VALUES
                .iter()
                .for_each(|(a, b, c)| test_addition(a, b, c));
        }
    }
}
