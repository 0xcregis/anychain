use anychain_core::Amount;
use std::fmt;

/// 1 SUI = 10^9 MIST
pub enum Denomination {
    MIST,
    SUI,
}

impl Denomination {
    fn precision(self) -> u32 {
        match self {
            Denomination::MIST => 0,
            Denomination::SUI => 9,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::MIST => "MIST",
                Denomination::SUI => "SUI",
            }
        )
    }
}

/// Sui balance representation
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct SuiAmount(pub u64);

impl Amount for SuiAmount {}

impl fmt::Display for SuiAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let denomination = Denomination::SUI;
        let precision = 10_u64.pow(denomination.precision());
        let value = self.0 as f64 / precision as f64;
        write!(f, "{} SUI", value)
    }
}

impl AsRef<u64> for SuiAmount {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

#[test]
fn amount_display() {
    let sui = SuiAmount(12000);
    println!("amount = {}", sui);

    let sui = SuiAmount(9_000_000_004);
    println!("amount = {}", sui);

    let sui = SuiAmount(1);
    println!("amount = {}", sui);
}
