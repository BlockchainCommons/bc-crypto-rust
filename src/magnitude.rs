use std::ops::{Shl, Shr};
use num_traits::{PrimInt, Unsigned, FromPrimitive, AsPrimitive, ops::overflowing::{OverflowingMul, OverflowingAdd}, WrappingSub};

use crate::widening::Widening;

pub trait HasMagnitude {
    type Magnitude: PrimInt
    + Unsigned
    + FromPrimitive
    + AsPrimitive<u128>
    + OverflowingMul
    + Shl<u32, Output = Self::Magnitude>
    + Shr<u32, Output = Self::Magnitude>
    + WrappingSub
    + OverflowingAdd
    + Widening;

    fn to_magnitude(&self) -> Self::Magnitude;
    fn from_magnitude(magnitude: Self::Magnitude) -> Self;
}

impl HasMagnitude for u8 {
    type Magnitude = u8;
    fn to_magnitude(&self) -> u8 { *self }
    fn from_magnitude(magnitude: u8) -> u8 { magnitude }
}

impl HasMagnitude for u16 {
    type Magnitude = u16;
    fn to_magnitude(&self) -> u16 { *self }
    fn from_magnitude(magnitude: u16) -> u16 { magnitude }
}

impl HasMagnitude for u32 {
    type Magnitude = u32;
    fn to_magnitude(&self) -> u32 { *self }
    fn from_magnitude(magnitude: u32) -> u32 { magnitude }
}

impl HasMagnitude for u64 {
    type Magnitude = u64;
    fn to_magnitude(&self) -> u64 { *self }
    fn from_magnitude(magnitude: u64) -> u64 { magnitude }
}

impl HasMagnitude for usize {
    type Magnitude = usize;
    fn to_magnitude(&self) -> usize { *self }
    fn from_magnitude(magnitude: usize) -> usize { magnitude }
}

impl HasMagnitude for i8 {
    type Magnitude = u8;
    fn to_magnitude(&self) -> u8 { self.wrapping_abs() as u8 }
    fn from_magnitude(magnitude: u8) -> i8 { magnitude as i8 }
}

impl HasMagnitude for i16 {
    type Magnitude = u16;
    fn to_magnitude(&self) -> u16 { self.wrapping_abs() as u16 }
    fn from_magnitude(magnitude: u16) -> i16 { magnitude as i16 }
}

impl HasMagnitude for i32 {
    type Magnitude = u32;
    fn to_magnitude(&self) -> u32 { self.wrapping_abs() as u32 }
    fn from_magnitude(magnitude: u32) -> i32 { magnitude as i32 }
}

impl HasMagnitude for i64 {
    type Magnitude = u64;
    fn to_magnitude(&self) -> u64 { self.wrapping_abs() as u64 }
    fn from_magnitude(magnitude: u64) -> i64 { magnitude as i64 }
}
