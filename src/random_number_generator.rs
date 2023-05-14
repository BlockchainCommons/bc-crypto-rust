pub trait RandomNumberGenerator {
    fn random_data(&mut self, size: usize) -> Vec<u8>;
}
