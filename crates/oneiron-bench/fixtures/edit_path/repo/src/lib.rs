pub mod math;
pub fn quote(quantity: u64, unit_price: u64) -> Option<u64> {
    math::subtotal(quantity, unit_price)?.checked_add(math::shipping(quantity))
}
pub fn currency() -> &'static str { "USD" }
