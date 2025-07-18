#![no_std]
#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]

pub use fixed_bigint;
pub use fixed_bigint::num_traits::cast::FromPrimitive;
pub use fixed_bigint::num_traits::Num as NumTraits;

use fixed_bigint::FixedUInt as Bn;

mod point;
pub use point::Point;

mod architecture;
use architecture::{WORD, WORD_COUNT};

pub type BigNum = Bn<WORD, WORD_COUNT>;

mod curve;
pub use curve::Curve;

mod jacobian;

#[cfg(feature = "std")]
pub fn as_hex(num: Bn<WORD, WORD_COUNT>) -> [u8; 128] {
    let mut buf = [0u8; 128];

    num.to_hex_str(&mut buf).unwrap();

    buf
}

#[cfg(not(feature = "std"))]
pub fn as_hex(num: Bn<WORD, WORD_COUNT>, buf: &mut [u8; 128]) {
    num.to_hex_str(buf).unwrap();
}
