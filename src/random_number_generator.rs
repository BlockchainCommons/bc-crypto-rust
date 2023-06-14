use std::ops::{Shl, Shr, Range, RangeInclusive};
use num_traits::{
    cast::{AsPrimitive, FromPrimitive, NumCast},
    PrimInt, Unsigned, ops::overflowing::{OverflowingMul, OverflowingAdd}, Bounded, One, WrappingSub,
};

use crate::{magnitude::HasMagnitude, widening::Widening};

/// A type that can generate random numbers.
pub trait RandomNumberGenerator {
    /// Returns the next random `u64`.
    fn next_u64(&mut self) -> u64;

    /// Returns a vector of random bytes of the given size.
    fn random_data(&mut self, size: usize) -> Vec<u8>;

    /// Fills the given buffer with random bytes.
    fn fill_random_data(&mut self, data: &mut [u8]);

    /// Returns a random value that is less than the given upper bound.
    ///
    /// Use this method when you need random binary data to generate another
    /// value. If you need an integer value within a specific range, use the
    /// static `random(in:using:)` method on that integer type instead of this
    /// method.
    ///
    /// - Parameter upperBound: The upper bound for the randomly generated value.
    ///   Must be non-zero.
    /// - Returns: A random value of `T` in the range `0..<upperBound`. Every
    ///   value in the range `0..<upperBound` is equally likely to be returned.
    fn next_with_upper_bound<T>(&mut self, upper_bound: T) -> T
        where
            T: PrimInt
                + Unsigned
                + NumCast
                + FromPrimitive
                + AsPrimitive<u128>
                + OverflowingMul
                + Shl<usize, Output = T>
                + Shr<usize, Output = T>
                + WrappingSub
                + OverflowingAdd
                + Widening
    {
        assert!(upper_bound != T::zero());

        // We use Lemire's "nearly divisionless" method for generating random
        // integers in an interval. For a detailed explanation, see:
        // https://arxiv.org/abs/1805.10941

        let bitmask: u64 = T::max_value().to_u64().unwrap();
        let mut random: T = NumCast::from(self.next_u64() & bitmask).unwrap();
        // let mut m = multiply_full_width(random, upper_bound);
        let mut m = random.wide_mul(upper_bound);
        if m.0 < upper_bound {
            let t = (T::zero().wrapping_sub(&upper_bound)) % upper_bound;
            while m.0 < t {
                random = NumCast::from(self.next_u64() & bitmask).unwrap();
                m = random.wide_mul(upper_bound);
            }
        }
        m.1
    }

    /// Returns a random value within the specified range, using the given
    /// generator as a source for randomness.
    ///
    /// Use this method to generate an integer within a specific range when you
    /// are using a custom random number generator. This example creates three
    /// new values in the range `1...100`.
    ///
    /// - Parameters:
    ///   - range: The range in which to create a random value.
    ///   - generator: The random number generator to use when creating the
    ///     new random value.
    /// - Returns: A random value within the bounds of `range`.
    fn next_in_range<T>(&mut self, range: &Range<T>) -> T
        where T: PrimInt
            + FromPrimitive
            + AsPrimitive<u128>
            + OverflowingMul
            + Shl<usize, Output = T>
            + Shr<usize, Output = T>
            + HasMagnitude
            + OverflowingAdd
    {
        let lower_bound = range.start;
        let upper_bound = range.end;

        assert!(lower_bound < upper_bound);

        let delta = (upper_bound - lower_bound).to_magnitude();

        if delta == T::Magnitude::max_value() {
            return T::from_u64(self.next_u64()).unwrap();
        }

        let random = self.next_with_upper_bound(delta);
        lower_bound + T::from_magnitude(random)
    }

    fn next_in_closed_range<T>(&mut self, range: &RangeInclusive<T>) -> T
        where T: PrimInt
            + FromPrimitive
            + AsPrimitive<u128>
            + OverflowingMul
            + Shl<usize, Output = T>
            + Shr<usize, Output = T>
            + HasMagnitude
    {
        let lower_bound = *range.start();
        let upper_bound = *range.end();

        assert!(lower_bound <= upper_bound);

        let delta = (upper_bound - lower_bound).to_magnitude();

        if delta == T::Magnitude::max_value() {
            return T::from_u64(self.next_u64()).unwrap();
        }

        let random = self.next_with_upper_bound(delta + T::Magnitude::one());
        lower_bound + T::from_magnitude(random)
    }
}

#[cfg(test)]
mod tests {
    use crate::{make_fake_random_number_generator, RandomNumberGenerator};

    #[test]
    fn test_fake_numbers() {
        let mut rng = make_fake_random_number_generator();
        let array = (0..100).map(|_| rng.next_in_closed_range(&(-50..=50))).collect::<Vec<_>>();
        assert_eq!(format!("{:?}", array), "[-43, -6, 43, -34, -34, 17, -9, 24, 17, -29, -32, -44, 12, -15, -46, 20, 50, -31, -50, 36, -28, -23, 6, -27, -31, -45, -27, 26, 31, -23, 24, 19, -32, 43, -18, -17, 6, -13, -1, -27, 4, -48, -4, -44, -6, 17, -15, 22, 15, 20, -25, -35, -33, -27, -17, -44, -27, 15, -14, -38, -29, -12, 8, 43, 49, -42, -11, -1, -42, -26, -25, 22, -13, 14, 42, -29, -38, 17, 2, 5, 5, -31, 27, -3, 39, -12, 42, 46, -17, -25, -46, -19, 16, 2, -45, 41, 12, -22, 43, -11]");
    }
}
