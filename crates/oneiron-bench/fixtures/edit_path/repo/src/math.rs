pub fn subtotal(quantity: u64, unit_price: u64) -> Option<u64> { quantity.checked_mul(unit_price) }
pub fn shipping(quantity: u64) -> u64 { if quantity == 0 { 0 } else { 5 } }
