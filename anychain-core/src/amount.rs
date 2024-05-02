use {
    crate::no_std::{
        fmt::{Debug, Display},
        hash::Hash,
        String,
    },
    thiserror::Error,
};

/// The interface for a generic amount.
pub trait Amount:
    Copy + Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash
{
}

#[derive(Debug, Error)]
pub enum AmountError {
    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error("the amount: {0:} exceeds the supply bounds of {1:}")]
    AmountOutOfBounds(String, String),

    #[error("invalid amount: {0:}")]
    InvalidAmount(String),
}

/// Converts any available denomination to the minimum denomination
pub fn to_basic_unit(value: &str, mut denomination: u32) -> String {
    if denomination > 18 {
        println!("illegal denomination");
        return "".to_string();
    }

    let mut has_point: bool = false;
    let mut point: usize = 0;
    let mut cnt: usize = 0;

    for c in value.chars() {
        if c.is_ascii_digit() || c == '.' {
            if c == '.' {
                if has_point {
                    println!("duplicate decimal point");
                    return "".to_string();
                }
                if cnt == 0 {
                    // the decimal point is at the front, indicating the value is 0
                    return "0".to_string();
                }
                has_point = true;
                point = cnt;
            }
            cnt += 1;
        } else {
            println!("illegal decimal string");
            return "".to_string();
        }
    }

    let mut value = value.to_string();

    // the decimal string does not contain a decimal point,
    // so we add one to the end.
    if !has_point {
        value.insert(value.len(), '.');
        point = value.len() - 1;
    }

    let mut v = value.as_bytes().to_vec();

    // now we right-shift the decimal point for 'denomination' times
    while denomination > 0 {
        // the decimal point is at the end of the vec, so push '0'
        // to the end and swap it with the decimal point
        if point == v.len() - 1 {
            v.push(b'0');
        }

        // swap the decimal point with its next digit
        v.swap(point, point + 1);

        point += 1;
        denomination -= 1;
    }

    // round up or down to the nearest integer
    if point < v.len() - 1 && v[point + 1] > b'5' {
        v[point - 1] += 1;
    }

    v.truncate(point);
    String::from_utf8(v).unwrap()
}

/// Converts any available denomination to the minimum denomination
pub fn to_basic_unit_u64(value: &str, mut denomination: u64) -> String {
    if denomination > 18 {
        println!("illegal denomination");
        return "".to_string();
    }

    let mut has_point: bool = false;
    let mut point: usize = 0;
    let mut cnt: usize = 0;

    for c in value.chars() {
        if c.is_ascii_digit() || c == '.' {
            if c == '.' {
                if has_point {
                    println!("duplicate decimal point");
                    return "".to_string();
                }
                if cnt == 0 {
                    // the decimal point is at the front, indicating the value is 0
                    return "0".to_string();
                }
                has_point = true;
                point = cnt;
            }
            cnt += 1;
        } else {
            println!("illegal decimal string");
            return "".to_string();
        }
    }

    let mut value = value.to_string();

    // the decimal string does not contain a decimal point,
    // so we add one to the end.
    if !has_point {
        value.insert(value.len(), '.');
        point = value.len() - 1;
    }

    let mut v = value.as_bytes().to_vec();

    // now we right-shift the decimal point for 'denomination' times
    while denomination > 0 {
        // the decimal point is at the end of the vec, so push '0'
        // to the end and swap it with the decimal point
        if point == v.len() - 1 {
            v.push(b'0');
        }

        // swap the decimal point with its next digit
        v.swap(point, point + 1);

        point += 1;
        denomination -= 1;
    }

    // round up or down to the nearest integer
    if point < v.len() - 1 && v[point + 1] > b'5' {
        v[point - 1] += 1;
    }

    v.truncate(point);
    String::from_utf8(v).unwrap()
}

#[test]
fn test() {
    let s = to_basic_unit("0.0001037910", 7);
    println!("s = {}", s);
}
