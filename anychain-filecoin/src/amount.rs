use anychain_core::to_basic_unit as to_atto_fil;

use core::fmt;
use num_bigint::BigInt;

/// Represents the amount of filecoin in attoFIL
pub type FilecoinAmount = BigInt;

pub enum Denomination {
    AttoFIL,
    FemtoFIL,
    PicoFIL,
    NanoFIL,
    MicroFIL,
    MilliFIL,
    FIL,
}

impl Denomination {
    fn precision(self) -> u32 {
        match self {
            Denomination::AttoFIL => 0,
            Denomination::FemtoFIL => 3,
            Denomination::PicoFIL => 6,
            Denomination::NanoFIL => 9,
            Denomination::MicroFIL => 12,
            Denomination::MilliFIL => 15,
            Denomination::FIL => 18,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::AttoFIL => "attoFIL",
                Denomination::FemtoFIL => "femtoFIL",
                Denomination::PicoFIL => "picoFIL",
                Denomination::NanoFIL => "nanoFIL",
                Denomination::MicroFIL => "microFIL",
                Denomination::MilliFIL => "milliFIL",
                Denomination::FIL => "FIL",
            }
        )
    }
}

pub trait FilecoinAmountConverter {
    fn from_decimal_str(val: &str) -> Self;

    fn from_atto_fil(atto_fil_value: &str) -> Self;

    fn from_femto_fil(femto_fil_value: &str) -> Self;

    fn from_pico_fil(pico_fil_value: &str) -> Self;

    fn from_nano_fil(nano_fil_value: &str) -> Self;

    fn from_micro_fil(micro_fil_value: &str) -> Self;

    fn from_milli_fil(milli_fil_value: &str) -> Self;

    fn from_fil(fil_value: &str) -> Self;

    fn add(self, b: Self) -> Self;

    fn sub(self, b: Self) -> Self;
}

impl FilecoinAmountConverter for FilecoinAmount {
    fn from_decimal_str(val: &str) -> Self {
        FilecoinAmount::parse_bytes(val.as_bytes(), 10).unwrap()
    }

    fn from_atto_fil(atto_fil_value: &str) -> Self {
        FilecoinAmount::from_decimal_str(atto_fil_value)
    }

    fn from_femto_fil(femto_fil_value: &str) -> Self {
        let atto_fil_value = to_atto_fil(femto_fil_value, Denomination::FemtoFIL.precision());
        FilecoinAmount::from_decimal_str(&atto_fil_value)
    }

    fn from_pico_fil(pico_fil_value: &str) -> Self {
        let atto_fil_value = to_atto_fil(pico_fil_value, Denomination::PicoFIL.precision());
        FilecoinAmount::from_decimal_str(&atto_fil_value)
    }

    fn from_nano_fil(nano_fil_value: &str) -> Self {
        let atto_fil_value = to_atto_fil(nano_fil_value, Denomination::NanoFIL.precision());
        FilecoinAmount::from_decimal_str(&atto_fil_value)
    }

    fn from_micro_fil(micro_fil_value: &str) -> Self {
        let atto_fil_value = to_atto_fil(micro_fil_value, Denomination::MilliFIL.precision());
        FilecoinAmount::from_decimal_str(&atto_fil_value)
    }

    fn from_milli_fil(milli_fil_value: &str) -> Self {
        let atto_fil_value = to_atto_fil(milli_fil_value, Denomination::MilliFIL.precision());
        FilecoinAmount::from_decimal_str(&atto_fil_value)
    }

    fn from_fil(fil_value: &str) -> Self {
        let atto_fil_value = to_atto_fil(fil_value, Denomination::FIL.precision());
        FilecoinAmount::from_decimal_str(&atto_fil_value)
    }

    fn add(self, b: Self) -> Self {
        &self + &b
    }

    fn sub(self, b: Self) -> Self {
        &self + &b
    }
}

#[test]
fn f() {
    let atto_fil = FilecoinAmount::from_fil("0.0001");
    println!("amount = {}", atto_fil);
}
