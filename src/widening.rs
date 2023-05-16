
pub trait Widening {
    fn wide_mul(&self, other: Self) -> (Self, Self) where Self: Sized;
}

impl Widening for u8 {
    fn wide_mul(&self, other: Self) -> (Self, Self) where Self: Sized {
        self.widening_mul(other)
    }
}

impl Widening for u16 {
    fn wide_mul(&self, other: Self) -> (Self, Self) where Self: Sized {
        self.widening_mul(other)
    }
}

impl Widening for u32 {
    fn wide_mul(&self, other: Self) -> (Self, Self) where Self: Sized {
        self.widening_mul(other)
    }
}

impl Widening for u64 {
    fn wide_mul(&self, other: Self) -> (Self, Self) where Self: Sized {
        self.widening_mul(other)
    }
}

impl Widening for usize {
    fn wide_mul(&self, other: Self) -> (Self, Self) where Self: Sized {
        self.widening_mul(other)
    }
}
