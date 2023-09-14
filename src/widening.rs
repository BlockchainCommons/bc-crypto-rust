// The below is so we don't have to use #![feature(bigint_helper_methods)]

macro_rules! private_widening_impl {
    ($SelfT:ty, $WideT:ty, $BITS:literal, unsigned) => {
        #[inline]
        fn wide_mul(self, rhs: Self) -> (Self, Self) {
            let wide = (self as $WideT) * (rhs as $WideT);
            (wide as $SelfT, (wide >> $BITS) as $SelfT)
        }
    };
}


pub trait Widening {
    fn wide_mul(self, other: Self) -> (Self, Self) where Self: Sized;
}

impl Widening for u8 {
    private_widening_impl! { u8, u16, 8, unsigned }
}

impl Widening for u16 {
    private_widening_impl! { u16, u32, 16, unsigned }
}

impl Widening for u32 {
    private_widening_impl! { u32, u64, 32, unsigned }
}

impl Widening for u64 {
    private_widening_impl! { u64, u128, 64, unsigned }
}

impl Widening for usize {
    private_widening_impl! { usize, u128, 64, unsigned }
}
