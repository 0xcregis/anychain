//! Definitions for the native SOL token and its fractional lamports.
// https://developers.stellar.org/docs/learn/fundamentals/stellar-data-structures/assets#amount-precision

use {
    anychain_core::{to_basic_unit_u64, Amount, AmountError},
    core::fmt,
    serde::{Deserialize, Serialize},
    std::ops::{Add, Sub},
};

/// Represents the amount of SOL in lamports
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StellarAmount(pub u64);

pub enum Denomination {
    STROOP,
    XLM,
}

impl Denomination {
    /// The number of decimal places more than one lamports.
    /// There are 10^9 lamports in one SOL
    fn precision(self) -> u64 {
        match self {
            Denomination::STROOP => 0,

            Denomination::XLM => 7,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::STROOP => "STROOP",
                Denomination::XLM => "XLM",
            }
        )
    }
}

impl Amount for StellarAmount {}

impl StellarAmount {
    pub fn from_u64(stroop: u64) -> Self {
        Self(stroop)
    }

    pub fn from_u64_str(value: &str) -> Result<u64, AmountError> {
        match value.parse::<u64>() {
            Ok(stroop) => Ok(stroop),
            Err(error) => Err(AmountError::Crate("uint", format!("{error:?}"))),
        }
    }
    pub fn from_stroop(stroop_value: &str) -> Result<Self, AmountError> {
        let stroop = Self::from_u64_str(stroop_value)?;
        Ok(Self::from_u64(stroop))
    }

    pub fn from_xlm(xlm_value: &str) -> Result<Self, AmountError> {
        let stroop_value = to_basic_unit_u64(xlm_value, Denomination::XLM.precision());
        let stroop = Self::from_u64_str(&stroop_value)?;
        Ok(Self::from_u64(stroop))
    }
}

impl Add for StellarAmount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for StellarAmount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for StellarAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    fn test_from_stroop(stroop_value: &str, expected_amount: &str) {
        let amount = StellarAmount::from_stroop(stroop_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_xlm(xlm_value: &str, expected_amount: &str) {
        let amount = StellarAmount::from_xlm(xlm_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    pub struct AmountDenominationTestCase {
        stroop: &'static str,
        xlm: &'static str,
    }

    const TEST_AMOUNTS: [AmountDenominationTestCase; 2] = [
        AmountDenominationTestCase {
            stroop: "0",
            xlm: "0",
        },
        AmountDenominationTestCase {
            stroop: "10000000",
            xlm: "1",
        },
    ];

    #[test]
    fn test_lamports_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_stroop(amounts.stroop, amounts.stroop));
    }

    #[test]
    fn test_sol_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_xlm(amounts.xlm, amounts.stroop));
    }

    fn test_addition(a: &str, b: &str, result: &str) {
        let a = StellarAmount::from_stroop(a).unwrap();
        let b = StellarAmount::from_stroop(b).unwrap();
        let result = StellarAmount::from_stroop(result).unwrap();

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &str, b: &str, result: &str) {
        let a = StellarAmount::from_stroop(a).unwrap();
        let b = StellarAmount::from_stroop(b).unwrap();
        let result = StellarAmount::from_stroop(result).unwrap();

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
