// This file is generated by rust-protobuf 3.3.0. Do not edit
// .proto file is parsed by protoc --rust-out=...
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `core/contract/exchange_contract.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:protocol.ExchangeCreateContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ExchangeCreateContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.ExchangeCreateContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeCreateContract.first_token_id)
    pub first_token_id: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeCreateContract.first_token_balance)
    pub first_token_balance: i64,
    // @@protoc_insertion_point(field:protocol.ExchangeCreateContract.second_token_id)
    pub second_token_id: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeCreateContract.second_token_balance)
    pub second_token_balance: i64,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.ExchangeCreateContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ExchangeCreateContract {
    fn default() -> &'a ExchangeCreateContract {
        <ExchangeCreateContract as ::protobuf::Message>::default_instance()
    }
}

impl ExchangeCreateContract {
    pub fn new() -> ExchangeCreateContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(5);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &ExchangeCreateContract| { &m.owner_address },
            |m: &mut ExchangeCreateContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "first_token_id",
            |m: &ExchangeCreateContract| { &m.first_token_id },
            |m: &mut ExchangeCreateContract| { &mut m.first_token_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "first_token_balance",
            |m: &ExchangeCreateContract| { &m.first_token_balance },
            |m: &mut ExchangeCreateContract| { &mut m.first_token_balance },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "second_token_id",
            |m: &ExchangeCreateContract| { &m.second_token_id },
            |m: &mut ExchangeCreateContract| { &mut m.second_token_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "second_token_balance",
            |m: &ExchangeCreateContract| { &m.second_token_balance },
            |m: &mut ExchangeCreateContract| { &mut m.second_token_balance },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ExchangeCreateContract>(
            "ExchangeCreateContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ExchangeCreateContract {
    const NAME: &'static str = "ExchangeCreateContract";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.owner_address = is.read_bytes()?;
                },
                18 => {
                    self.first_token_id = is.read_bytes()?;
                },
                24 => {
                    self.first_token_balance = is.read_int64()?;
                },
                34 => {
                    self.second_token_id = is.read_bytes()?;
                },
                40 => {
                    self.second_token_balance = is.read_int64()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.owner_address.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.owner_address);
        }
        if !self.first_token_id.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.first_token_id);
        }
        if self.first_token_balance != 0 {
            my_size += ::protobuf::rt::int64_size(3, self.first_token_balance);
        }
        if !self.second_token_id.is_empty() {
            my_size += ::protobuf::rt::bytes_size(4, &self.second_token_id);
        }
        if self.second_token_balance != 0 {
            my_size += ::protobuf::rt::int64_size(5, self.second_token_balance);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if !self.first_token_id.is_empty() {
            os.write_bytes(2, &self.first_token_id)?;
        }
        if self.first_token_balance != 0 {
            os.write_int64(3, self.first_token_balance)?;
        }
        if !self.second_token_id.is_empty() {
            os.write_bytes(4, &self.second_token_id)?;
        }
        if self.second_token_balance != 0 {
            os.write_int64(5, self.second_token_balance)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> ExchangeCreateContract {
        ExchangeCreateContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.first_token_id.clear();
        self.first_token_balance = 0;
        self.second_token_id.clear();
        self.second_token_balance = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ExchangeCreateContract {
        static instance: ExchangeCreateContract = ExchangeCreateContract {
            owner_address: ::std::vec::Vec::new(),
            first_token_id: ::std::vec::Vec::new(),
            first_token_balance: 0,
            second_token_id: ::std::vec::Vec::new(),
            second_token_balance: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ExchangeCreateContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ExchangeCreateContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ExchangeCreateContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ExchangeCreateContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:protocol.ExchangeInjectContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ExchangeInjectContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.ExchangeInjectContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeInjectContract.exchange_id)
    pub exchange_id: i64,
    // @@protoc_insertion_point(field:protocol.ExchangeInjectContract.token_id)
    pub token_id: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeInjectContract.quant)
    pub quant: i64,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.ExchangeInjectContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ExchangeInjectContract {
    fn default() -> &'a ExchangeInjectContract {
        <ExchangeInjectContract as ::protobuf::Message>::default_instance()
    }
}

impl ExchangeInjectContract {
    pub fn new() -> ExchangeInjectContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(4);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &ExchangeInjectContract| { &m.owner_address },
            |m: &mut ExchangeInjectContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "exchange_id",
            |m: &ExchangeInjectContract| { &m.exchange_id },
            |m: &mut ExchangeInjectContract| { &mut m.exchange_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "token_id",
            |m: &ExchangeInjectContract| { &m.token_id },
            |m: &mut ExchangeInjectContract| { &mut m.token_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "quant",
            |m: &ExchangeInjectContract| { &m.quant },
            |m: &mut ExchangeInjectContract| { &mut m.quant },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ExchangeInjectContract>(
            "ExchangeInjectContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ExchangeInjectContract {
    const NAME: &'static str = "ExchangeInjectContract";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.owner_address = is.read_bytes()?;
                },
                16 => {
                    self.exchange_id = is.read_int64()?;
                },
                26 => {
                    self.token_id = is.read_bytes()?;
                },
                32 => {
                    self.quant = is.read_int64()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.owner_address.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.owner_address);
        }
        if self.exchange_id != 0 {
            my_size += ::protobuf::rt::int64_size(2, self.exchange_id);
        }
        if !self.token_id.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.token_id);
        }
        if self.quant != 0 {
            my_size += ::protobuf::rt::int64_size(4, self.quant);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if self.exchange_id != 0 {
            os.write_int64(2, self.exchange_id)?;
        }
        if !self.token_id.is_empty() {
            os.write_bytes(3, &self.token_id)?;
        }
        if self.quant != 0 {
            os.write_int64(4, self.quant)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> ExchangeInjectContract {
        ExchangeInjectContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.exchange_id = 0;
        self.token_id.clear();
        self.quant = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ExchangeInjectContract {
        static instance: ExchangeInjectContract = ExchangeInjectContract {
            owner_address: ::std::vec::Vec::new(),
            exchange_id: 0,
            token_id: ::std::vec::Vec::new(),
            quant: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ExchangeInjectContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ExchangeInjectContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ExchangeInjectContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ExchangeInjectContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:protocol.ExchangeWithdrawContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ExchangeWithdrawContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.ExchangeWithdrawContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeWithdrawContract.exchange_id)
    pub exchange_id: i64,
    // @@protoc_insertion_point(field:protocol.ExchangeWithdrawContract.token_id)
    pub token_id: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeWithdrawContract.quant)
    pub quant: i64,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.ExchangeWithdrawContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ExchangeWithdrawContract {
    fn default() -> &'a ExchangeWithdrawContract {
        <ExchangeWithdrawContract as ::protobuf::Message>::default_instance()
    }
}

impl ExchangeWithdrawContract {
    pub fn new() -> ExchangeWithdrawContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(4);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &ExchangeWithdrawContract| { &m.owner_address },
            |m: &mut ExchangeWithdrawContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "exchange_id",
            |m: &ExchangeWithdrawContract| { &m.exchange_id },
            |m: &mut ExchangeWithdrawContract| { &mut m.exchange_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "token_id",
            |m: &ExchangeWithdrawContract| { &m.token_id },
            |m: &mut ExchangeWithdrawContract| { &mut m.token_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "quant",
            |m: &ExchangeWithdrawContract| { &m.quant },
            |m: &mut ExchangeWithdrawContract| { &mut m.quant },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ExchangeWithdrawContract>(
            "ExchangeWithdrawContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ExchangeWithdrawContract {
    const NAME: &'static str = "ExchangeWithdrawContract";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.owner_address = is.read_bytes()?;
                },
                16 => {
                    self.exchange_id = is.read_int64()?;
                },
                26 => {
                    self.token_id = is.read_bytes()?;
                },
                32 => {
                    self.quant = is.read_int64()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.owner_address.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.owner_address);
        }
        if self.exchange_id != 0 {
            my_size += ::protobuf::rt::int64_size(2, self.exchange_id);
        }
        if !self.token_id.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.token_id);
        }
        if self.quant != 0 {
            my_size += ::protobuf::rt::int64_size(4, self.quant);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if self.exchange_id != 0 {
            os.write_int64(2, self.exchange_id)?;
        }
        if !self.token_id.is_empty() {
            os.write_bytes(3, &self.token_id)?;
        }
        if self.quant != 0 {
            os.write_int64(4, self.quant)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> ExchangeWithdrawContract {
        ExchangeWithdrawContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.exchange_id = 0;
        self.token_id.clear();
        self.quant = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ExchangeWithdrawContract {
        static instance: ExchangeWithdrawContract = ExchangeWithdrawContract {
            owner_address: ::std::vec::Vec::new(),
            exchange_id: 0,
            token_id: ::std::vec::Vec::new(),
            quant: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ExchangeWithdrawContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ExchangeWithdrawContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ExchangeWithdrawContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ExchangeWithdrawContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:protocol.ExchangeTransactionContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ExchangeTransactionContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.ExchangeTransactionContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeTransactionContract.exchange_id)
    pub exchange_id: i64,
    // @@protoc_insertion_point(field:protocol.ExchangeTransactionContract.token_id)
    pub token_id: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.ExchangeTransactionContract.quant)
    pub quant: i64,
    // @@protoc_insertion_point(field:protocol.ExchangeTransactionContract.expected)
    pub expected: i64,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.ExchangeTransactionContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ExchangeTransactionContract {
    fn default() -> &'a ExchangeTransactionContract {
        <ExchangeTransactionContract as ::protobuf::Message>::default_instance()
    }
}

impl ExchangeTransactionContract {
    pub fn new() -> ExchangeTransactionContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(5);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &ExchangeTransactionContract| { &m.owner_address },
            |m: &mut ExchangeTransactionContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "exchange_id",
            |m: &ExchangeTransactionContract| { &m.exchange_id },
            |m: &mut ExchangeTransactionContract| { &mut m.exchange_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "token_id",
            |m: &ExchangeTransactionContract| { &m.token_id },
            |m: &mut ExchangeTransactionContract| { &mut m.token_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "quant",
            |m: &ExchangeTransactionContract| { &m.quant },
            |m: &mut ExchangeTransactionContract| { &mut m.quant },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "expected",
            |m: &ExchangeTransactionContract| { &m.expected },
            |m: &mut ExchangeTransactionContract| { &mut m.expected },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ExchangeTransactionContract>(
            "ExchangeTransactionContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ExchangeTransactionContract {
    const NAME: &'static str = "ExchangeTransactionContract";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.owner_address = is.read_bytes()?;
                },
                16 => {
                    self.exchange_id = is.read_int64()?;
                },
                26 => {
                    self.token_id = is.read_bytes()?;
                },
                32 => {
                    self.quant = is.read_int64()?;
                },
                40 => {
                    self.expected = is.read_int64()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.owner_address.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.owner_address);
        }
        if self.exchange_id != 0 {
            my_size += ::protobuf::rt::int64_size(2, self.exchange_id);
        }
        if !self.token_id.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.token_id);
        }
        if self.quant != 0 {
            my_size += ::protobuf::rt::int64_size(4, self.quant);
        }
        if self.expected != 0 {
            my_size += ::protobuf::rt::int64_size(5, self.expected);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if self.exchange_id != 0 {
            os.write_int64(2, self.exchange_id)?;
        }
        if !self.token_id.is_empty() {
            os.write_bytes(3, &self.token_id)?;
        }
        if self.quant != 0 {
            os.write_int64(4, self.quant)?;
        }
        if self.expected != 0 {
            os.write_int64(5, self.expected)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> ExchangeTransactionContract {
        ExchangeTransactionContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.exchange_id = 0;
        self.token_id.clear();
        self.quant = 0;
        self.expected = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ExchangeTransactionContract {
        static instance: ExchangeTransactionContract = ExchangeTransactionContract {
            owner_address: ::std::vec::Vec::new(),
            exchange_id: 0,
            token_id: ::std::vec::Vec::new(),
            quant: 0,
            expected: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ExchangeTransactionContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ExchangeTransactionContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ExchangeTransactionContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ExchangeTransactionContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n%core/contract/exchange_contract.proto\x12\x08protocol\"\xed\x01\n\x16\
    ExchangeCreateContract\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cow\
    nerAddress\x12$\n\x0efirst_token_id\x18\x02\x20\x01(\x0cR\x0cfirstTokenI\
    d\x12.\n\x13first_token_balance\x18\x03\x20\x01(\x03R\x11firstTokenBalan\
    ce\x12&\n\x0fsecond_token_id\x18\x04\x20\x01(\x0cR\rsecondTokenId\x120\n\
    \x14second_token_balance\x18\x05\x20\x01(\x03R\x12secondTokenBalance\"\
    \x8f\x01\n\x16ExchangeInjectContract\x12#\n\rowner_address\x18\x01\x20\
    \x01(\x0cR\x0cownerAddress\x12\x1f\n\x0bexchange_id\x18\x02\x20\x01(\x03\
    R\nexchangeId\x12\x19\n\x08token_id\x18\x03\x20\x01(\x0cR\x07tokenId\x12\
    \x14\n\x05quant\x18\x04\x20\x01(\x03R\x05quant\"\x91\x01\n\x18ExchangeWi\
    thdrawContract\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cownerAddre\
    ss\x12\x1f\n\x0bexchange_id\x18\x02\x20\x01(\x03R\nexchangeId\x12\x19\n\
    \x08token_id\x18\x03\x20\x01(\x0cR\x07tokenId\x12\x14\n\x05quant\x18\x04\
    \x20\x01(\x03R\x05quant\"\xb0\x01\n\x1bExchangeTransactionContract\x12#\
    \n\rowner_address\x18\x01\x20\x01(\x0cR\x0cownerAddress\x12\x1f\n\x0bexc\
    hange_id\x18\x02\x20\x01(\x03R\nexchangeId\x12\x19\n\x08token_id\x18\x03\
    \x20\x01(\x0cR\x07tokenId\x12\x14\n\x05quant\x18\x04\x20\x01(\x03R\x05qu\
    ant\x12\x1a\n\x08expected\x18\x05\x20\x01(\x03R\x08expectedBE\n\x18org.t\
    ron.protos.contractZ)github.com/tronprotocol/grpc-gateway/coreJ\xb1\n\n\
    \x06\x12\x04\0\0$\x01\n\x08\n\x01\x0c\x12\x03\0\0\x12\n\x08\n\x01\x02\
    \x12\x03\x02\0\x11\n\x08\n\x01\x08\x12\x03\x04\01\nH\n\x02\x08\x01\x12\
    \x03\x04\01\"=Specify\x20the\x20name\x20of\x20the\x20package\x20that\x20\
    generated\x20the\x20Java\x20file\n\n\x08\n\x01\x08\x12\x03\x06\0@\nw\n\
    \x02\x08\x0b\x12\x03\x06\0@\x1aloption\x20java_outer_classname\x20=\x20\
    \"ExchangeCreateContract\";\x20//Specify\x20the\x20class\x20name\x20of\
    \x20the\x20generated\x20Java\x20file\n\n\n\n\x02\x04\0\x12\x04\x08\0\x0e\
    \x01\n\n\n\x03\x04\0\x01\x12\x03\x08\x08\x1e\n\x0b\n\x04\x04\0\x02\0\x12\
    \x03\t\x02\x1a\n\x0c\n\x05\x04\0\x02\0\x05\x12\x03\t\x02\x07\n\x0c\n\x05\
    \x04\0\x02\0\x01\x12\x03\t\x08\x15\n\x0c\n\x05\x04\0\x02\0\x03\x12\x03\t\
    \x18\x19\n\x0b\n\x04\x04\0\x02\x01\x12\x03\n\x02\x1b\n\x0c\n\x05\x04\0\
    \x02\x01\x05\x12\x03\n\x02\x07\n\x0c\n\x05\x04\0\x02\x01\x01\x12\x03\n\
    \x08\x16\n\x0c\n\x05\x04\0\x02\x01\x03\x12\x03\n\x19\x1a\n\x0b\n\x04\x04\
    \0\x02\x02\x12\x03\x0b\x02\x20\n\x0c\n\x05\x04\0\x02\x02\x05\x12\x03\x0b\
    \x02\x07\n\x0c\n\x05\x04\0\x02\x02\x01\x12\x03\x0b\x08\x1b\n\x0c\n\x05\
    \x04\0\x02\x02\x03\x12\x03\x0b\x1e\x1f\n\x0b\n\x04\x04\0\x02\x03\x12\x03\
    \x0c\x02\x1c\n\x0c\n\x05\x04\0\x02\x03\x05\x12\x03\x0c\x02\x07\n\x0c\n\
    \x05\x04\0\x02\x03\x01\x12\x03\x0c\x08\x17\n\x0c\n\x05\x04\0\x02\x03\x03\
    \x12\x03\x0c\x1a\x1b\n\x0b\n\x04\x04\0\x02\x04\x12\x03\r\x02!\n\x0c\n\
    \x05\x04\0\x02\x04\x05\x12\x03\r\x02\x07\n\x0c\n\x05\x04\0\x02\x04\x01\
    \x12\x03\r\x08\x1c\n\x0c\n\x05\x04\0\x02\x04\x03\x12\x03\r\x1f\x20\n\n\n\
    \x02\x04\x01\x12\x04\x10\0\x15\x01\n\n\n\x03\x04\x01\x01\x12\x03\x10\x08\
    \x1e\n\x0b\n\x04\x04\x01\x02\0\x12\x03\x11\x02\x1a\n\x0c\n\x05\x04\x01\
    \x02\0\x05\x12\x03\x11\x02\x07\n\x0c\n\x05\x04\x01\x02\0\x01\x12\x03\x11\
    \x08\x15\n\x0c\n\x05\x04\x01\x02\0\x03\x12\x03\x11\x18\x19\n\x0b\n\x04\
    \x04\x01\x02\x01\x12\x03\x12\x02\x18\n\x0c\n\x05\x04\x01\x02\x01\x05\x12\
    \x03\x12\x02\x07\n\x0c\n\x05\x04\x01\x02\x01\x01\x12\x03\x12\x08\x13\n\
    \x0c\n\x05\x04\x01\x02\x01\x03\x12\x03\x12\x16\x17\n\x0b\n\x04\x04\x01\
    \x02\x02\x12\x03\x13\x02\x15\n\x0c\n\x05\x04\x01\x02\x02\x05\x12\x03\x13\
    \x02\x07\n\x0c\n\x05\x04\x01\x02\x02\x01\x12\x03\x13\x08\x10\n\x0c\n\x05\
    \x04\x01\x02\x02\x03\x12\x03\x13\x13\x14\n\x0b\n\x04\x04\x01\x02\x03\x12\
    \x03\x14\x02\x12\n\x0c\n\x05\x04\x01\x02\x03\x05\x12\x03\x14\x02\x07\n\
    \x0c\n\x05\x04\x01\x02\x03\x01\x12\x03\x14\x08\r\n\x0c\n\x05\x04\x01\x02\
    \x03\x03\x12\x03\x14\x10\x11\n\n\n\x02\x04\x02\x12\x04\x17\0\x1c\x01\n\n\
    \n\x03\x04\x02\x01\x12\x03\x17\x08\x20\n\x0b\n\x04\x04\x02\x02\0\x12\x03\
    \x18\x02\x1a\n\x0c\n\x05\x04\x02\x02\0\x05\x12\x03\x18\x02\x07\n\x0c\n\
    \x05\x04\x02\x02\0\x01\x12\x03\x18\x08\x15\n\x0c\n\x05\x04\x02\x02\0\x03\
    \x12\x03\x18\x18\x19\n\x0b\n\x04\x04\x02\x02\x01\x12\x03\x19\x02\x18\n\
    \x0c\n\x05\x04\x02\x02\x01\x05\x12\x03\x19\x02\x07\n\x0c\n\x05\x04\x02\
    \x02\x01\x01\x12\x03\x19\x08\x13\n\x0c\n\x05\x04\x02\x02\x01\x03\x12\x03\
    \x19\x16\x17\n\x0b\n\x04\x04\x02\x02\x02\x12\x03\x1a\x02\x15\n\x0c\n\x05\
    \x04\x02\x02\x02\x05\x12\x03\x1a\x02\x07\n\x0c\n\x05\x04\x02\x02\x02\x01\
    \x12\x03\x1a\x08\x10\n\x0c\n\x05\x04\x02\x02\x02\x03\x12\x03\x1a\x13\x14\
    \n\x0b\n\x04\x04\x02\x02\x03\x12\x03\x1b\x02\x12\n\x0c\n\x05\x04\x02\x02\
    \x03\x05\x12\x03\x1b\x02\x07\n\x0c\n\x05\x04\x02\x02\x03\x01\x12\x03\x1b\
    \x08\r\n\x0c\n\x05\x04\x02\x02\x03\x03\x12\x03\x1b\x10\x11\n\n\n\x02\x04\
    \x03\x12\x04\x1e\0$\x01\n\n\n\x03\x04\x03\x01\x12\x03\x1e\x08#\n\x0b\n\
    \x04\x04\x03\x02\0\x12\x03\x1f\x02\x1a\n\x0c\n\x05\x04\x03\x02\0\x05\x12\
    \x03\x1f\x02\x07\n\x0c\n\x05\x04\x03\x02\0\x01\x12\x03\x1f\x08\x15\n\x0c\
    \n\x05\x04\x03\x02\0\x03\x12\x03\x1f\x18\x19\n\x0b\n\x04\x04\x03\x02\x01\
    \x12\x03\x20\x02\x18\n\x0c\n\x05\x04\x03\x02\x01\x05\x12\x03\x20\x02\x07\
    \n\x0c\n\x05\x04\x03\x02\x01\x01\x12\x03\x20\x08\x13\n\x0c\n\x05\x04\x03\
    \x02\x01\x03\x12\x03\x20\x16\x17\n\x0b\n\x04\x04\x03\x02\x02\x12\x03!\
    \x02\x15\n\x0c\n\x05\x04\x03\x02\x02\x05\x12\x03!\x02\x07\n\x0c\n\x05\
    \x04\x03\x02\x02\x01\x12\x03!\x08\x10\n\x0c\n\x05\x04\x03\x02\x02\x03\
    \x12\x03!\x13\x14\n\x0b\n\x04\x04\x03\x02\x03\x12\x03\"\x02\x12\n\x0c\n\
    \x05\x04\x03\x02\x03\x05\x12\x03\"\x02\x07\n\x0c\n\x05\x04\x03\x02\x03\
    \x01\x12\x03\"\x08\r\n\x0c\n\x05\x04\x03\x02\x03\x03\x12\x03\"\x10\x11\n\
    \x0b\n\x04\x04\x03\x02\x04\x12\x03#\x02\x15\n\x0c\n\x05\x04\x03\x02\x04\
    \x05\x12\x03#\x02\x07\n\x0c\n\x05\x04\x03\x02\x04\x01\x12\x03#\x08\x10\n\
    \x0c\n\x05\x04\x03\x02\x04\x03\x12\x03#\x13\x14b\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(0);
            let mut messages = ::std::vec::Vec::with_capacity(4);
            messages.push(ExchangeCreateContract::generated_message_descriptor_data());
            messages.push(ExchangeInjectContract::generated_message_descriptor_data());
            messages.push(ExchangeWithdrawContract::generated_message_descriptor_data());
            messages.push(ExchangeTransactionContract::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
