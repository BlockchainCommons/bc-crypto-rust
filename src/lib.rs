#![feature(bigint_helper_methods)]

mod sha256;
pub use sha256::sha256;

mod random_number_generator;
pub use random_number_generator::RandomNumberGenerator;

mod crc32;
pub use crc32::{crc32, crc32_data, crc32_data_opt};

mod secure_random;
pub use secure_random::{SecureRandomNumberGenerator, random_data};

mod seeded_random;
pub use seeded_random::{SeededRandomNumberGenerator, fake_random_data, make_fake_random_number_generator};

mod magnitude;
mod widening;
