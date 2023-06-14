use crate::RandomNumberGenerator;
use rand::RngCore;
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::Xoshiro256StarStar;

/// A random number generator that can be used as a source of deterministic pseudo-randomness
/// for testing purposes.
pub struct SeededRandomNumberGenerator {
    rng: Xoshiro256StarStar
}

impl SeededRandomNumberGenerator {
    /// Creates a new seeded random number generator.
    ///
    /// The seed should be a 256-bit value, represented as an array of 4 64-bit integers.
    /// For the output distribution to look random, the seed should not have any obvious
    /// patterns, like all zeroes or all ones.
    ///
    /// This is not cryptographically secure, and should only be used for testing purposes.
    pub fn new(seed: [u64; 4]) -> Self {
        let mut seed_bytes = [0u8; 32];
        for i in 0..4 {
            seed_bytes[i * 8..(i + 1) * 8].copy_from_slice(&seed[i].to_le_bytes());
        }
        Self {
            rng: Xoshiro256StarStar::from_seed(seed_bytes)
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }
}

impl RandomNumberGenerator for SeededRandomNumberGenerator {
    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn random_data(&mut self, size: usize) -> Vec<u8> {
        // This might not be the most efficient implementation,
        // but it works the same as the Swift version.
        (0..size).map(|_| self.next_u64() as u8).collect()
    }

    fn fill_random_data(&mut self, data: &mut [u8]) {
        data.iter_mut().for_each(|x| *x = self.next_u64() as u8);
    }
}

/// Creates a seeded random number generator with a fixed seed.
pub fn make_fake_random_number_generator() -> impl RandomNumberGenerator {
    SeededRandomNumberGenerator::new([17295166580085024720, 422929670265678780, 5577237070365765850, 7953171132032326923])
}

/// Creates a vector of random data with a fixed seed.
pub fn fake_random_data(size: usize) -> Vec<u8> {
    make_fake_random_number_generator().random_data(size)
}

#[cfg(test)]
mod tests {
    use crate::{fake_random_data, SeededRandomNumberGenerator, RandomNumberGenerator};

    const TEST_SEED: [u64; 4] = [17295166580085024720, 422929670265678780, 5577237070365765850, 7953171132032326923];

    #[test]
    fn test_next_u64() {
        let mut rng = SeededRandomNumberGenerator::new(TEST_SEED);
        assert_eq!(rng.next_u64(), 1104683000648959614);
    }

    #[test]
    fn test_next_50() {
        let mut rng = SeededRandomNumberGenerator::new(TEST_SEED);
        let expected_values: Vec<u64> = vec![1104683000648959614, 9817345228149227957, 546276821344993881, 15870950426333349563, 830653509032165567, 14772257893953840492, 3512633850838187726, 6358411077290857510, 7897285047238174514, 18314839336815726031, 4978716052961022367, 17373022694051233817, 663115362299242570, 9811238046242345451, 8113787839071393872, 16155047452816275860, 673245095821315645, 1610087492396736743, 1749670338128618977, 3927771759340679115, 9610589375631783853, 5311608497352460372, 11014490817524419548, 6320099928172676090, 12513554919020212402, 6823504187935853178, 1215405011954300226, 8109228150255944821, 4122548551796094879, 16544885818373129566, 5597102191057004591, 11690994260783567085, 9374498734039011409, 18246806104446739078, 2337407889179712900, 12608919248151905477, 7641631838640172886, 8421574250687361351, 8697189342072434208, 8766286633078002696, 14800090277885439654, 17865860059234099833, 4673315107448681522, 14288183874156623863, 7587575203648284614, 9109213819045273474, 11817665411945280786, 1745089530919138651, 5730370365819793488, 5496865518262805451];
        assert!(expected_values.into_iter().all(|x| x == rng.next_u64()));
    }

    #[test]
    fn test_fake_random_data() {
        assert_eq!(fake_random_data(100), hex_literal::hex!("7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed518684c556472008a67932f7c682125b50cb72e8216f6906358fdaf28d3545532daee0c5bb5023f50cd8e71ec14901ac746c576c481b893be6656b80622b3a564e59b4e2"));
    }

    #[test]
    fn test_next_with_upper_bound() {
        let mut rng = SeededRandomNumberGenerator::new(TEST_SEED);
        assert_eq!(rng.next_with_upper_bound(10000u32), 745);
    }

    #[test]
    fn test_in_range() {
        let mut rng = SeededRandomNumberGenerator::new(TEST_SEED);
        let v = (0..100).map(|_| rng.next_in_range(&(0..100))).collect::<Vec<_>>();
        let expected_values: Vec<i32> = vec![7, 44, 92, 16, 16, 67, 41, 74, 66, 20, 18, 6, 62, 34, 4, 69, 99, 19, 0, 85, 22, 27, 56, 23, 19, 5, 23, 76, 80, 27, 74, 69, 17, 92, 31, 32, 55, 36, 49, 23, 53, 2, 46, 6, 43, 66, 34, 71, 64, 69, 25, 14, 17, 23, 32, 6, 23, 65, 35, 11, 21, 37, 58, 92, 98, 8, 38, 49, 7, 24, 24, 71, 37, 63, 91, 21, 11, 66, 52, 54, 55, 19, 76, 46, 89, 38, 91, 95, 33, 25, 4, 30, 66, 51, 5, 91, 62, 27, 92, 39];
        assert_eq!(v, expected_values);
    }

    #[test]
    fn test_fill_random_data() {
        let mut rng = SeededRandomNumberGenerator::new(TEST_SEED);
        let v1 = rng.random_data(100);
        let mut rng = SeededRandomNumberGenerator::new(TEST_SEED);
        let mut v2 = [0u8; 100];
        rng.fill_random_data(&mut v2);
        assert_eq!(v1, v2);
    }
}
