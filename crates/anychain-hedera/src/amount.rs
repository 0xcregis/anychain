//! Definitions for the native SOL token and its fractional lamports.

use {
    anychain_core::{to_basic_unit_u64, Amount, AmountError},
    core::fmt,
    serde::{Deserialize, Serialize},
    std::ops::{Add, Sub},
};

/// Represents the amount of SOL in lamports
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HederaAmount(pub u64);

pub enum Denomination {
    TINYBAR,
    HBAR,
}

impl Denomination {
    /// The number of decimal places more than one tinybar.
    /// There are 10^8 lamports in one SOL
    fn precision(self) -> u64 {
        match self {
            Denomination::TINYBAR => 0,

            Denomination::HBAR => 8,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::TINYBAR => "tinybar",
                Denomination::HBAR => "HBAR",
            }
        )
    }
}

impl Amount for HederaAmount {}

impl HederaAmount {
    pub fn from_u64(tinybars: u64) -> Self {
        Self(tinybars)
    }

    pub fn from_u64_str(value: &str) -> Result<u64, AmountError> {
        match value.parse::<u64>() {
            Ok(tinybars) => Ok(tinybars),
            Err(error) => Err(AmountError::Crate("uint", format!("{error:?}"))),
        }
    }
    pub fn from_tinybars(tinybars_value: &str) -> Result<Self, AmountError> {
        let tinybars = Self::from_u64_str(tinybars_value)?;
        Ok(Self::from_u64(tinybars))
    }

    pub fn from_hbar(hbar_value: &str) -> Result<Self, AmountError> {
        let tinybars_value = to_basic_unit_u64(hbar_value, Denomination::HBAR.precision());
        let tinybars = Self::from_u64_str(&tinybars_value)?;
        Ok(Self::from_u64(tinybars))
    }
}

impl Add for HederaAmount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for HederaAmount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for HederaAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    fn test_from_tinybars(tinybars_value: &str, expected_amount: &str) {
        let amount = HederaAmount::from_tinybars(tinybars_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_hbar(hbar_value: &str, expected_amount: &str) {
        let amount = HederaAmount::from_hbar(hbar_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    pub struct AmountDenominationTestCase {
        tinybars: &'static str,
        hbar: &'static str,
    }

    const TEST_AMOUNTS: [AmountDenominationTestCase; 2] = [
        AmountDenominationTestCase {
            tinybars: "0",
            hbar: "0",
        },
        AmountDenominationTestCase {
            tinybars: "100000000",
            hbar: "1",
        },
    ];

    #[test]
    fn test_lamports_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_tinybars(amounts.tinybars, amounts.tinybars));
    }

    #[test]
    fn test_sol_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_hbar(amounts.hbar, amounts.tinybars));
    }

    fn test_addition(a: &str, b: &str, result: &str) {
        let a = HederaAmount::from_tinybars(a).unwrap();
        let b = HederaAmount::from_tinybars(b).unwrap();
        let result = HederaAmount::from_tinybars(result).unwrap();

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &str, b: &str, result: &str) {
        let a = HederaAmount::from_tinybars(a).unwrap();
        let b = HederaAmount::from_tinybars(b).unwrap();
        let result = HederaAmount::from_tinybars(result).unwrap();

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
