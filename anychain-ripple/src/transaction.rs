use anychain_core::TransactionError;

enum SerializedTypeID {
    // special types
    Unknown = -2,
    Done = -1,
    NotPresent = 0,

    // types (common)
    Uint16 = 1,
    Uint32 = 2,
    Uint64 = 3,
    Hash128 = 4,
    Hash256 = 5,
    Amount = 6,
    VL = 7,
    Account = 8,
    // 9-13 are reserved
    Object = 14,
    Array = 15,

    // types (uncommon)
    Uint8 = 16,
    Hash160 = 17,
    PathSet = 18,
    Vector256 = 19,

    // high level types
    // cannot be serialized inside other types
    Transaction = 10001,
    LedgerEntry = 10002,
    Validation = 10003,
    Metadata = 10004,
}

enum SerializedType {
    Account {
        field_value: i32,
    },

    Amount {
        field_value: i32,
    },

    Integer {
        field_value: i32,
    },

    Array {
        field_value: i32,
        arr: Vec<SerializedType>,
    },

    Object {
        field_value: i32,
        objs: Vec<SerializedType>,
    },

    Blob {
        field_value: i32,
    },

    Field {
        field_value: i32,
    },
}

impl SerializedType {
    fn type_id(&self) -> SerializedTypeID {
        match self {
            Self::Account { .. } => SerializedTypeID::Account,
            Self::Amount { .. } => SerializedTypeID::Amount,
            Self::Integer { .. } => SerializedTypeID::Uint32,
            Self::Array { .. } => SerializedTypeID::Array,
            Self::Object { .. } => SerializedTypeID::Object,
            Self::Blob { .. } => SerializedTypeID::VL,
            Self::Field { .. } => SerializedTypeID::Array,
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        match self {
            Self::Account { .. } => {}
            Self::Amount { .. } => {}
            Self::Integer { .. } => {}
            Self::Array { .. } => {}
            Self::Object { .. } => {}
            Self::Blob { .. } => {}
            Self::Field { .. } => {}
        }

        Ok(vec![])
    }
}
