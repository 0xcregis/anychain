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

//! Generated file from `core/contract/account_contract.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:protocol.AccountCreateContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct AccountCreateContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.AccountCreateContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.AccountCreateContract.account_address)
    pub account_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.AccountCreateContract.type)
    pub type_: ::protobuf::EnumOrUnknown<super::Tron::AccountType>,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.AccountCreateContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a AccountCreateContract {
    fn default() -> &'a AccountCreateContract {
        <AccountCreateContract as ::protobuf::Message>::default_instance()
    }
}

impl AccountCreateContract {
    pub fn new() -> AccountCreateContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(3);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &AccountCreateContract| { &m.owner_address },
            |m: &mut AccountCreateContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "account_address",
            |m: &AccountCreateContract| { &m.account_address },
            |m: &mut AccountCreateContract| { &mut m.account_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "type",
            |m: &AccountCreateContract| { &m.type_ },
            |m: &mut AccountCreateContract| { &mut m.type_ },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<AccountCreateContract>(
            "AccountCreateContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for AccountCreateContract {
    const NAME: &'static str = "AccountCreateContract";

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
                    self.account_address = is.read_bytes()?;
                },
                24 => {
                    self.type_ = is.read_enum_or_unknown()?;
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
        if !self.account_address.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.account_address);
        }
        if self.type_ != ::protobuf::EnumOrUnknown::new(super::Tron::AccountType::Normal) {
            my_size += ::protobuf::rt::int32_size(3, self.type_.value());
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if !self.account_address.is_empty() {
            os.write_bytes(2, &self.account_address)?;
        }
        if self.type_ != ::protobuf::EnumOrUnknown::new(super::Tron::AccountType::Normal) {
            os.write_enum(3, ::protobuf::EnumOrUnknown::value(&self.type_))?;
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

    fn new() -> AccountCreateContract {
        AccountCreateContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.account_address.clear();
        self.type_ = ::protobuf::EnumOrUnknown::new(super::Tron::AccountType::Normal);
        self.special_fields.clear();
    }

    fn default_instance() -> &'static AccountCreateContract {
        static instance: AccountCreateContract = AccountCreateContract {
            owner_address: ::std::vec::Vec::new(),
            account_address: ::std::vec::Vec::new(),
            type_: ::protobuf::EnumOrUnknown::from_i32(0),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for AccountCreateContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("AccountCreateContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for AccountCreateContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for AccountCreateContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

///  Update account name. Account name is not unique now.
// @@protoc_insertion_point(message:protocol.AccountUpdateContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct AccountUpdateContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.AccountUpdateContract.account_name)
    pub account_name: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.AccountUpdateContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.AccountUpdateContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a AccountUpdateContract {
    fn default() -> &'a AccountUpdateContract {
        <AccountUpdateContract as ::protobuf::Message>::default_instance()
    }
}

impl AccountUpdateContract {
    pub fn new() -> AccountUpdateContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "account_name",
            |m: &AccountUpdateContract| { &m.account_name },
            |m: &mut AccountUpdateContract| { &mut m.account_name },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &AccountUpdateContract| { &m.owner_address },
            |m: &mut AccountUpdateContract| { &mut m.owner_address },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<AccountUpdateContract>(
            "AccountUpdateContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for AccountUpdateContract {
    const NAME: &'static str = "AccountUpdateContract";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.account_name = is.read_bytes()?;
                },
                18 => {
                    self.owner_address = is.read_bytes()?;
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
        if !self.account_name.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.account_name);
        }
        if !self.owner_address.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.owner_address);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.account_name.is_empty() {
            os.write_bytes(1, &self.account_name)?;
        }
        if !self.owner_address.is_empty() {
            os.write_bytes(2, &self.owner_address)?;
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

    fn new() -> AccountUpdateContract {
        AccountUpdateContract::new()
    }

    fn clear(&mut self) {
        self.account_name.clear();
        self.owner_address.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static AccountUpdateContract {
        static instance: AccountUpdateContract = AccountUpdateContract {
            account_name: ::std::vec::Vec::new(),
            owner_address: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for AccountUpdateContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("AccountUpdateContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for AccountUpdateContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for AccountUpdateContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

///  Set account id if the account has no id. Account id is unique and case insensitive.
// @@protoc_insertion_point(message:protocol.SetAccountIdContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct SetAccountIdContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.SetAccountIdContract.account_id)
    pub account_id: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.SetAccountIdContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.SetAccountIdContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a SetAccountIdContract {
    fn default() -> &'a SetAccountIdContract {
        <SetAccountIdContract as ::protobuf::Message>::default_instance()
    }
}

impl SetAccountIdContract {
    pub fn new() -> SetAccountIdContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "account_id",
            |m: &SetAccountIdContract| { &m.account_id },
            |m: &mut SetAccountIdContract| { &mut m.account_id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &SetAccountIdContract| { &m.owner_address },
            |m: &mut SetAccountIdContract| { &mut m.owner_address },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<SetAccountIdContract>(
            "SetAccountIdContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for SetAccountIdContract {
    const NAME: &'static str = "SetAccountIdContract";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.account_id = is.read_bytes()?;
                },
                18 => {
                    self.owner_address = is.read_bytes()?;
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
        if !self.account_id.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.account_id);
        }
        if !self.owner_address.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.owner_address);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.account_id.is_empty() {
            os.write_bytes(1, &self.account_id)?;
        }
        if !self.owner_address.is_empty() {
            os.write_bytes(2, &self.owner_address)?;
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

    fn new() -> SetAccountIdContract {
        SetAccountIdContract::new()
    }

    fn clear(&mut self) {
        self.account_id.clear();
        self.owner_address.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static SetAccountIdContract {
        static instance: SetAccountIdContract = SetAccountIdContract {
            account_id: ::std::vec::Vec::new(),
            owner_address: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for SetAccountIdContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("SetAccountIdContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for SetAccountIdContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SetAccountIdContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:protocol.AccountPermissionUpdateContract)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct AccountPermissionUpdateContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.AccountPermissionUpdateContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.AccountPermissionUpdateContract.owner)
    pub owner: ::protobuf::MessageField<super::Tron::Permission>,
    // @@protoc_insertion_point(field:protocol.AccountPermissionUpdateContract.witness)
    pub witness: ::protobuf::MessageField<super::Tron::Permission>,
    // @@protoc_insertion_point(field:protocol.AccountPermissionUpdateContract.actives)
    pub actives: ::std::vec::Vec<super::Tron::Permission>,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.AccountPermissionUpdateContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a AccountPermissionUpdateContract {
    fn default() -> &'a AccountPermissionUpdateContract {
        <AccountPermissionUpdateContract as ::protobuf::Message>::default_instance()
    }
}

impl AccountPermissionUpdateContract {
    pub fn new() -> AccountPermissionUpdateContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(4);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &AccountPermissionUpdateContract| { &m.owner_address },
            |m: &mut AccountPermissionUpdateContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::Tron::Permission>(
            "owner",
            |m: &AccountPermissionUpdateContract| { &m.owner },
            |m: &mut AccountPermissionUpdateContract| { &mut m.owner },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::Tron::Permission>(
            "witness",
            |m: &AccountPermissionUpdateContract| { &m.witness },
            |m: &mut AccountPermissionUpdateContract| { &mut m.witness },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "actives",
            |m: &AccountPermissionUpdateContract| { &m.actives },
            |m: &mut AccountPermissionUpdateContract| { &mut m.actives },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<AccountPermissionUpdateContract>(
            "AccountPermissionUpdateContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for AccountPermissionUpdateContract {
    const NAME: &'static str = "AccountPermissionUpdateContract";

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
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.owner)?;
                },
                26 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.witness)?;
                },
                34 => {
                    self.actives.push(is.read_message()?);
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
        if let Some(v) = self.owner.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let Some(v) = self.witness.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        for value in &self.actives {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if let Some(v) = self.owner.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(2, v, os)?;
        }
        if let Some(v) = self.witness.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(3, v, os)?;
        }
        for v in &self.actives {
            ::protobuf::rt::write_message_field_with_cached_size(4, v, os)?;
        };
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> AccountPermissionUpdateContract {
        AccountPermissionUpdateContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.owner.clear();
        self.witness.clear();
        self.actives.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static AccountPermissionUpdateContract {
        static instance: AccountPermissionUpdateContract = AccountPermissionUpdateContract {
            owner_address: ::std::vec::Vec::new(),
            owner: ::protobuf::MessageField::none(),
            witness: ::protobuf::MessageField::none(),
            actives: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for AccountPermissionUpdateContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("AccountPermissionUpdateContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for AccountPermissionUpdateContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for AccountPermissionUpdateContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n$core/contract/account_contract.proto\x12\x08protocol\x1a\x0fcore/Tron\
    .proto\"\x90\x01\n\x15AccountCreateContract\x12#\n\rowner_address\x18\
    \x01\x20\x01(\x0cR\x0cownerAddress\x12'\n\x0faccount_address\x18\x02\x20\
    \x01(\x0cR\x0eaccountAddress\x12)\n\x04type\x18\x03\x20\x01(\x0e2\x15.pr\
    otocol.AccountTypeR\x04type\"_\n\x15AccountUpdateContract\x12!\n\x0cacco\
    unt_name\x18\x01\x20\x01(\x0cR\x0baccountName\x12#\n\rowner_address\x18\
    \x02\x20\x01(\x0cR\x0cownerAddress\"Z\n\x14SetAccountIdContract\x12\x1d\
    \n\naccount_id\x18\x01\x20\x01(\x0cR\taccountId\x12#\n\rowner_address\
    \x18\x02\x20\x01(\x0cR\x0cownerAddress\"\xd2\x01\n\x1fAccountPermissionU\
    pdateContract\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cownerAddres\
    s\x12*\n\x05owner\x18\x02\x20\x01(\x0b2\x14.protocol.PermissionR\x05owne\
    r\x12.\n\x07witness\x18\x03\x20\x01(\x0b2\x14.protocol.PermissionR\x07wi\
    tness\x12.\n\x07actives\x18\x04\x20\x03(\x0b2\x14.protocol.PermissionR\
    \x07activesBE\n\x18org.tron.protos.contractZ)github.com/tronprotocol/grp\
    c-gateway/coreJ\xf2\r\n\x06\x12\x04\x0f\00\x01\n\xf4\x04\n\x01\x0c\x12\
    \x03\x0f\0\x122\xe9\x04\n\x20java-tron\x20is\x20free\x20software:\x20you\
    \x20can\x20redistribute\x20it\x20and/or\x20modify\n\x20it\x20under\x20th\
    e\x20terms\x20of\x20the\x20GNU\x20General\x20Public\x20License\x20as\x20\
    published\x20by\n\x20the\x20Free\x20Software\x20Foundation,\x20either\
    \x20version\x203\x20of\x20the\x20License,\x20or\n\x20(at\x20your\x20opti\
    on)\x20any\x20later\x20version.\n\n\x20java-tron\x20is\x20distributed\
    \x20in\x20the\x20hope\x20that\x20it\x20will\x20be\x20useful,\n\x20but\
    \x20WITHOUT\x20ANY\x20WARRANTY;\x20without\x20even\x20the\x20implied\x20\
    warranty\x20of\n\x20MERCHANTABILITY\x20or\x20FITNESS\x20FOR\x20A\x20PART\
    ICULAR\x20PURPOSE.\x20\x20See\x20the\n\x20GNU\x20General\x20Public\x20Li\
    cense\x20for\x20more\x20details.\n\n\x20You\x20should\x20have\x20receive\
    d\x20a\x20copy\x20of\x20the\x20GNU\x20General\x20Public\x20License\n\x20\
    along\x20with\x20this\x20program.\x20\x20If\x20not,\x20see\x20<http://ww\
    w.gnu.org/licenses/>.\n\n\x08\n\x01\x02\x12\x03\x11\0\x11\n\x08\n\x01\
    \x08\x12\x03\x13\01\nH\n\x02\x08\x01\x12\x03\x13\01\"=Specify\x20the\x20\
    name\x20of\x20the\x20package\x20that\x20generated\x20the\x20Java\x20file\
    \n\n\x08\n\x01\x08\x12\x03\x15\0@\ni\n\x02\x08\x0b\x12\x03\x15\0@\x1a^op\
    tion\x20java_outer_classname\x20=\x20\"Contract\";\x20//Specify\x20the\
    \x20class\x20name\x20of\x20the\x20generated\x20Java\x20file\n\n\t\n\x02\
    \x03\0\x12\x03\x17\0\x19\n\n\n\x02\x04\0\x12\x04\x19\0\x1d\x01\n\n\n\x03\
    \x04\0\x01\x12\x03\x19\x08\x1d\n\x0b\n\x04\x04\0\x02\0\x12\x03\x1a\x02\
    \x1a\n\x0c\n\x05\x04\0\x02\0\x05\x12\x03\x1a\x02\x07\n\x0c\n\x05\x04\0\
    \x02\0\x01\x12\x03\x1a\x08\x15\n\x0c\n\x05\x04\0\x02\0\x03\x12\x03\x1a\
    \x18\x19\n\x0b\n\x04\x04\0\x02\x01\x12\x03\x1b\x02\x1c\n\x0c\n\x05\x04\0\
    \x02\x01\x05\x12\x03\x1b\x02\x07\n\x0c\n\x05\x04\0\x02\x01\x01\x12\x03\
    \x1b\x08\x17\n\x0c\n\x05\x04\0\x02\x01\x03\x12\x03\x1b\x1a\x1b\n\x0b\n\
    \x04\x04\0\x02\x02\x12\x03\x1c\x02\x17\n\x0c\n\x05\x04\0\x02\x02\x06\x12\
    \x03\x1c\x02\r\n\x0c\n\x05\x04\0\x02\x02\x01\x12\x03\x1c\x0e\x12\n\x0c\n\
    \x05\x04\0\x02\x02\x03\x12\x03\x1c\x15\x16\nB\n\x02\x04\x01\x12\x04\x20\
    \0#\x01\x1a6\x20Update\x20account\x20name.\x20Account\x20name\x20is\x20n\
    ot\x20unique\x20now.\n\n\n\n\x03\x04\x01\x01\x12\x03\x20\x08\x1d\n\x0b\n\
    \x04\x04\x01\x02\0\x12\x03!\x02\x19\n\x0c\n\x05\x04\x01\x02\0\x05\x12\
    \x03!\x02\x07\n\x0c\n\x05\x04\x01\x02\0\x01\x12\x03!\x08\x14\n\x0c\n\x05\
    \x04\x01\x02\0\x03\x12\x03!\x17\x18\n\x0b\n\x04\x04\x01\x02\x01\x12\x03\
    \"\x02\x1a\n\x0c\n\x05\x04\x01\x02\x01\x05\x12\x03\"\x02\x07\n\x0c\n\x05\
    \x04\x01\x02\x01\x01\x12\x03\"\x08\x15\n\x0c\n\x05\x04\x01\x02\x01\x03\
    \x12\x03\"\x18\x19\na\n\x02\x04\x02\x12\x04&\0)\x01\x1aU\x20Set\x20accou\
    nt\x20id\x20if\x20the\x20account\x20has\x20no\x20id.\x20Account\x20id\
    \x20is\x20unique\x20and\x20case\x20insensitive.\n\n\n\n\x03\x04\x02\x01\
    \x12\x03&\x08\x1c\n\x0b\n\x04\x04\x02\x02\0\x12\x03'\x02\x17\n\x0c\n\x05\
    \x04\x02\x02\0\x05\x12\x03'\x02\x07\n\x0c\n\x05\x04\x02\x02\0\x01\x12\
    \x03'\x08\x12\n\x0c\n\x05\x04\x02\x02\0\x03\x12\x03'\x15\x16\n\x0b\n\x04\
    \x04\x02\x02\x01\x12\x03(\x02\x1a\n\x0c\n\x05\x04\x02\x02\x01\x05\x12\
    \x03(\x02\x07\n\x0c\n\x05\x04\x02\x02\x01\x01\x12\x03(\x08\x15\n\x0c\n\
    \x05\x04\x02\x02\x01\x03\x12\x03(\x18\x19\n\n\n\x02\x04\x03\x12\x04+\00\
    \x01\n\n\n\x03\x04\x03\x01\x12\x03+\x08'\n\x0b\n\x04\x04\x03\x02\0\x12\
    \x03,\x02\x1a\n\x0c\n\x05\x04\x03\x02\0\x05\x12\x03,\x02\x07\n\x0c\n\x05\
    \x04\x03\x02\0\x01\x12\x03,\x08\x15\n\x0c\n\x05\x04\x03\x02\0\x03\x12\
    \x03,\x18\x19\n!\n\x04\x04\x03\x02\x01\x12\x03-\x02\x17\"\x14Empty\x20is\
    \x20invalidate\n\n\x0c\n\x05\x04\x03\x02\x01\x06\x12\x03-\x02\x0c\n\x0c\
    \n\x05\x04\x03\x02\x01\x01\x12\x03-\r\x12\n\x0c\n\x05\x04\x03\x02\x01\
    \x03\x12\x03-\x15\x16\n\x1a\n\x04\x04\x03\x02\x02\x12\x03.\x02\x19\"\rCa\
    n\x20be\x20empty\n\n\x0c\n\x05\x04\x03\x02\x02\x06\x12\x03.\x02\x0c\n\
    \x0c\n\x05\x04\x03\x02\x02\x01\x12\x03.\r\x14\n\x0c\n\x05\x04\x03\x02\
    \x02\x03\x12\x03.\x17\x18\n!\n\x04\x04\x03\x02\x03\x12\x03/\x02\"\"\x14E\
    mpty\x20is\x20invalidate\n\n\x0c\n\x05\x04\x03\x02\x03\x04\x12\x03/\x02\
    \n\n\x0c\n\x05\x04\x03\x02\x03\x06\x12\x03/\x0b\x15\n\x0c\n\x05\x04\x03\
    \x02\x03\x01\x12\x03/\x16\x1d\n\x0c\n\x05\x04\x03\x02\x03\x03\x12\x03/\
    \x20!b\x06proto3\
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
            let mut deps = ::std::vec::Vec::with_capacity(1);
            deps.push(super::Tron::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(4);
            messages.push(AccountCreateContract::generated_message_descriptor_data());
            messages.push(AccountUpdateContract::generated_message_descriptor_data());
            messages.push(SetAccountIdContract::generated_message_descriptor_data());
            messages.push(AccountPermissionUpdateContract::generated_message_descriptor_data());
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
