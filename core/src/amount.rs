use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
};

/// The interface for a generic amount.
pub trait Amount: Copy + Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

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
        if c >= '0' && c <= '9' || c == '.' {
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

    // the decimal string does not contain a decimal point
    if !has_point {
        return value.to_string();
    }

    let mut v = value.as_bytes().to_vec();
    
    // now we right-shift the decimal point for 'denomination' times
    while denomination > 0 {

        // the decimal point is at the end of the vec, so push '0'
        // to the end and swap it with the decimal point
        if point == v.len() - 1 {
            v.push('0' as u8);
        }
        
        // swap the decimal point with its next digit
        let temp: u8 = v[point];
        v[point] = v[point + 1];
        v[point + 1] = temp;

        point += 1;
        denomination -= 1;
    }

    // round up or down to the nearest integer
    if point < v.len() - 1 && v[point + 1] > '5' as u8 {
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