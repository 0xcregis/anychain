//! Definitions for the native SOL token and its fractional lamports.

use {
    anychain_core::{to_basic_unit_u64, Amount, AmountError},
    core::fmt,
    serde::{Deserialize, Serialize},
    std::ops::{Add, Sub},
};

/// Represents the amount of SOL in lamports
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SolanaAmount(pub u64);

pub enum Denomination {
    LAMPORTS,
    SOL,
}

impl Denomination {
    /// The number of decimal places more than one lamports.
    /// There are 10^9 lamports in one SOL
    fn precision(self) -> u64 {
        match self {
            Denomination::LAMPORTS => 0,

            Denomination::SOL => 9,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::LAMPORTS => "lamports",
                Denomination::SOL => "SOL",
            }
        )
    }
}

impl Amount for SolanaAmount {}

impl SolanaAmount {
    pub fn from_u64(lamports: u64) -> Self {
        Self(lamports)
    }

    pub fn from_u64_str(value: &str) -> Result<u64, AmountError> {
        match value.parse::<u64>() {
            Ok(lamports) => Ok(lamports),
            Err(error) => Err(AmountError::Crate("uint", format!("{:?}", error))),
        }
    }
    pub fn from_lamports(lamports_value: &str) -> Result<Self, AmountError> {
        let lamports = Self::from_u64_str(lamports_value)?;
        Ok(Self::from_u64(lamports))
    }

    pub fn from_sol(sol_value: &str) -> Result<Self, AmountError> {
        let lamports_value = to_basic_unit_u64(sol_value, Denomination::SOL.precision());
        let lamports = Self::from_u64_str(&lamports_value)?;
        Ok(Self::from_u64(lamports))
    }
}

impl Add for SolanaAmount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for SolanaAmount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for SolanaAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    fn test_from_lamports(lamports_value: &str, expected_amount: &str) {
        let amount = SolanaAmount::from_lamports(lamports_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_sol(sol_value: &str, expected_amount: &str) {
        let amount = SolanaAmount::from_sol(sol_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    pub struct AmountDenominationTestCase {
        lamports: &'static str,
        sol: &'static str,
    }

    const TEST_AMOUNTS: [AmountDenominationTestCase; 2] = [
        AmountDenominationTestCase {
            lamports: "0",
            sol: "0",
        },
        AmountDenominationTestCase {
            lamports: "1000000000",
            sol: "1",
        },
    ];

    #[test]
    fn test_lamports_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_lamports(amounts.lamports, amounts.lamports));
    }

    #[test]
    fn test_sol_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_sol(amounts.sol, amounts.lamports));
    }

    fn test_addition(a: &str, b: &str, result: &str) {
        let a = SolanaAmount::from_lamports(a).unwrap();
        let b = SolanaAmount::from_lamports(b).unwrap();
        let result = SolanaAmount::from_lamports(result).unwrap();

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &str, b: &str, result: &str) {
        let a = SolanaAmount::from_lamports(a).unwrap();
        let b = SolanaAmount::from_lamports(b).unwrap();
        let result = SolanaAmount::from_lamports(result).unwrap();

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
