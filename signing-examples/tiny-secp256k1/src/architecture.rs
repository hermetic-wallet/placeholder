/// 8-bit `WORD` size for small architectures like AVR, etc.
#[cfg(feature = "8-bit")]
pub type WORD = u8;

/// reserve 512 bit, needed for operations like multiplication.
#[cfg(feature = "8-bit")]
pub const WORD_COUNT: usize = 64;

/// 32-bit `WORD` size for architectures like ARM, etc.
#[cfg(feature = "32-bit")]
pub type WORD = u32;

/// reserve 512 bit, needed for operations like multiplication.
#[cfg(feature = "32-bit")]
pub const WORD_COUNT: usize = 16;
