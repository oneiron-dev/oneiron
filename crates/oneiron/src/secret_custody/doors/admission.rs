//! Borrowing custody admission projection, defined in the store layer.

pub(crate) use crate::secret_record::admission::{
    SecretCustodyAdmission, read_secret_custody_admission_in_txn,
};
