#[cfg(not(feature = "std"))]
#[doc(hidden)]
pub use alloc::{
    borrow::ToOwned, format, string::FromUtf8Error, string::String, string::ToString, vec, vec::Vec,
};

#[cfg(not(feature = "std"))]
#[doc(hidden)]
pub use core::{
    hash, num,
    {fmt, str::FromStr},
};

#[cfg(feature = "std")]
#[doc(hidden)]
pub use std::{
    borrow::ToOwned, fmt, format, hash, num, str::FromStr, string::FromUtf8Error, string::String,
    string::ToString, vec, vec::Vec,
};

#[cfg(not(feature = "std"))]
#[doc(hidden)]
pub mod io;

#[cfg(feature = "std")]
pub use std::io;
