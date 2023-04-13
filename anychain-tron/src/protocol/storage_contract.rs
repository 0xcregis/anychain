// This file is generated by rust-protobuf 3.2.0. Do not edit
// .proto file is parsed by protoc --rust-out=...
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `core/contract/storage_contract.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_2_0;

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:protocol.BuyStorageBytesContract)
pub struct BuyStorageBytesContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.BuyStorageBytesContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.BuyStorageBytesContract.bytes)
    pub bytes: i64,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.BuyStorageBytesContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a BuyStorageBytesContract {
    fn default() -> &'a BuyStorageBytesContract {
        <BuyStorageBytesContract as ::protobuf::Message>::default_instance()
    }
}

impl BuyStorageBytesContract {
    pub fn new() -> BuyStorageBytesContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &BuyStorageBytesContract| { &m.owner_address },
            |m: &mut BuyStorageBytesContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "bytes",
            |m: &BuyStorageBytesContract| { &m.bytes },
            |m: &mut BuyStorageBytesContract| { &mut m.bytes },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<BuyStorageBytesContract>(
            "BuyStorageBytesContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for BuyStorageBytesContract {
    const NAME: &'static str = "BuyStorageBytesContract";

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
                    self.bytes = is.read_int64()?;
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
        if self.bytes != 0 {
            my_size += ::protobuf::rt::int64_size(2, self.bytes);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if self.bytes != 0 {
            os.write_int64(2, self.bytes)?;
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

    fn new() -> BuyStorageBytesContract {
        BuyStorageBytesContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.bytes = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static BuyStorageBytesContract {
        static instance: BuyStorageBytesContract = BuyStorageBytesContract {
            owner_address: ::std::vec::Vec::new(),
            bytes: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for BuyStorageBytesContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("BuyStorageBytesContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for BuyStorageBytesContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BuyStorageBytesContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:protocol.BuyStorageContract)
pub struct BuyStorageContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.BuyStorageContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.BuyStorageContract.quant)
    pub quant: i64,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.BuyStorageContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a BuyStorageContract {
    fn default() -> &'a BuyStorageContract {
        <BuyStorageContract as ::protobuf::Message>::default_instance()
    }
}

impl BuyStorageContract {
    pub fn new() -> BuyStorageContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &BuyStorageContract| { &m.owner_address },
            |m: &mut BuyStorageContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "quant",
            |m: &BuyStorageContract| { &m.quant },
            |m: &mut BuyStorageContract| { &mut m.quant },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<BuyStorageContract>(
            "BuyStorageContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for BuyStorageContract {
    const NAME: &'static str = "BuyStorageContract";

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
        if self.quant != 0 {
            my_size += ::protobuf::rt::int64_size(2, self.quant);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if self.quant != 0 {
            os.write_int64(2, self.quant)?;
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

    fn new() -> BuyStorageContract {
        BuyStorageContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.quant = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static BuyStorageContract {
        static instance: BuyStorageContract = BuyStorageContract {
            owner_address: ::std::vec::Vec::new(),
            quant: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for BuyStorageContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("BuyStorageContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for BuyStorageContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BuyStorageContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:protocol.SellStorageContract)
pub struct SellStorageContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.SellStorageContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.SellStorageContract.storage_bytes)
    pub storage_bytes: i64,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.SellStorageContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a SellStorageContract {
    fn default() -> &'a SellStorageContract {
        <SellStorageContract as ::protobuf::Message>::default_instance()
    }
}

impl SellStorageContract {
    pub fn new() -> SellStorageContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &SellStorageContract| { &m.owner_address },
            |m: &mut SellStorageContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "storage_bytes",
            |m: &SellStorageContract| { &m.storage_bytes },
            |m: &mut SellStorageContract| { &mut m.storage_bytes },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<SellStorageContract>(
            "SellStorageContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for SellStorageContract {
    const NAME: &'static str = "SellStorageContract";

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
                    self.storage_bytes = is.read_int64()?;
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
        if self.storage_bytes != 0 {
            my_size += ::protobuf::rt::int64_size(2, self.storage_bytes);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if self.storage_bytes != 0 {
            os.write_int64(2, self.storage_bytes)?;
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

    fn new() -> SellStorageContract {
        SellStorageContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.storage_bytes = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static SellStorageContract {
        static instance: SellStorageContract = SellStorageContract {
            owner_address: ::std::vec::Vec::new(),
            storage_bytes: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for SellStorageContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("SellStorageContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for SellStorageContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SellStorageContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:protocol.UpdateBrokerageContract)
pub struct UpdateBrokerageContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.UpdateBrokerageContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.UpdateBrokerageContract.brokerage)
    pub brokerage: i32,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.UpdateBrokerageContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a UpdateBrokerageContract {
    fn default() -> &'a UpdateBrokerageContract {
        <UpdateBrokerageContract as ::protobuf::Message>::default_instance()
    }
}

impl UpdateBrokerageContract {
    pub fn new() -> UpdateBrokerageContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &UpdateBrokerageContract| { &m.owner_address },
            |m: &mut UpdateBrokerageContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "brokerage",
            |m: &UpdateBrokerageContract| { &m.brokerage },
            |m: &mut UpdateBrokerageContract| { &mut m.brokerage },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<UpdateBrokerageContract>(
            "UpdateBrokerageContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for UpdateBrokerageContract {
    const NAME: &'static str = "UpdateBrokerageContract";

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
                    self.brokerage = is.read_int32()?;
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
        if self.brokerage != 0 {
            my_size += ::protobuf::rt::int32_size(2, self.brokerage);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        if self.brokerage != 0 {
            os.write_int32(2, self.brokerage)?;
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

    fn new() -> UpdateBrokerageContract {
        UpdateBrokerageContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.brokerage = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static UpdateBrokerageContract {
        static instance: UpdateBrokerageContract = UpdateBrokerageContract {
            owner_address: ::std::vec::Vec::new(),
            brokerage: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for UpdateBrokerageContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("UpdateBrokerageContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for UpdateBrokerageContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UpdateBrokerageContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n$core/contract/storage_contract.proto\x12\x08protocol\"T\n\x17BuyStora\
    geBytesContract\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cownerAddr\
    ess\x12\x14\n\x05bytes\x18\x02\x20\x01(\x03R\x05bytes\"O\n\x12BuyStorage\
    Contract\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cownerAddress\x12\
    \x14\n\x05quant\x18\x02\x20\x01(\x03R\x05quant\"_\n\x13SellStorageContra\
    ct\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cownerAddress\x12#\n\rs\
    torage_bytes\x18\x02\x20\x01(\x03R\x0cstorageBytes\"\\\n\x17UpdateBroker\
    ageContract\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cownerAddress\
    \x12\x1c\n\tbrokerage\x18\x02\x20\x01(\x05R\tbrokerageBE\n\x18org.tron.p\
    rotos.contractZ)github.com/tronprotocol/grpc-gateway/coreJ\xd8\x06\n\x06\
    \x12\x04\0\0\x1a\x01\n\x08\n\x01\x0c\x12\x03\0\0\x12\n\x08\n\x01\x02\x12\
    \x03\x02\0\x11\n\x08\n\x01\x08\x12\x03\x04\01\nH\n\x02\x08\x01\x12\x03\
    \x04\01\"=Specify\x20the\x20name\x20of\x20the\x20package\x20that\x20gene\
    rated\x20the\x20Java\x20file\n\n\x08\n\x01\x08\x12\x03\x06\0@\nx\n\x02\
    \x08\x0b\x12\x03\x06\0@\x1amoption\x20java_outer_classname\x20=\x20\"Buy\
    StorageBytesContract\";\x20//Specify\x20the\x20class\x20name\x20of\x20th\
    e\x20generated\x20Java\x20file\n\n\n\n\x02\x04\0\x12\x04\x08\0\x0b\x01\n\
    \n\n\x03\x04\0\x01\x12\x03\x08\x08\x1f\n\x0b\n\x04\x04\0\x02\0\x12\x03\t\
    \x02\x1a\n\x0c\n\x05\x04\0\x02\0\x05\x12\x03\t\x02\x07\n\x0c\n\x05\x04\0\
    \x02\0\x01\x12\x03\t\x08\x15\n\x0c\n\x05\x04\0\x02\0\x03\x12\x03\t\x18\
    \x19\n$\n\x04\x04\0\x02\x01\x12\x03\n\x02\x12\"\x17\x20storage\x20bytes\
    \x20for\x20buy\n\n\x0c\n\x05\x04\0\x02\x01\x05\x12\x03\n\x02\x07\n\x0c\n\
    \x05\x04\0\x02\x01\x01\x12\x03\n\x08\r\n\x0c\n\x05\x04\0\x02\x01\x03\x12\
    \x03\n\x10\x11\n\n\n\x02\x04\x01\x12\x04\r\0\x10\x01\n\n\n\x03\x04\x01\
    \x01\x12\x03\r\x08\x1a\n\x0b\n\x04\x04\x01\x02\0\x12\x03\x0e\x02\x1a\n\
    \x0c\n\x05\x04\x01\x02\0\x05\x12\x03\x0e\x02\x07\n\x0c\n\x05\x04\x01\x02\
    \0\x01\x12\x03\x0e\x08\x15\n\x0c\n\x05\x04\x01\x02\0\x03\x12\x03\x0e\x18\
    \x19\n1\n\x04\x04\x01\x02\x01\x12\x03\x0f\x02\x12\"$\x20trx\x20quantity\
    \x20for\x20buy\x20storage\x20(sun)\n\n\x0c\n\x05\x04\x01\x02\x01\x05\x12\
    \x03\x0f\x02\x07\n\x0c\n\x05\x04\x01\x02\x01\x01\x12\x03\x0f\x08\r\n\x0c\
    \n\x05\x04\x01\x02\x01\x03\x12\x03\x0f\x10\x11\n\n\n\x02\x04\x02\x12\x04\
    \x12\0\x15\x01\n\n\n\x03\x04\x02\x01\x12\x03\x12\x08\x1b\n\x0b\n\x04\x04\
    \x02\x02\0\x12\x03\x13\x02\x1a\n\x0c\n\x05\x04\x02\x02\0\x05\x12\x03\x13\
    \x02\x07\n\x0c\n\x05\x04\x02\x02\0\x01\x12\x03\x13\x08\x15\n\x0c\n\x05\
    \x04\x02\x02\0\x03\x12\x03\x13\x18\x19\n\x0b\n\x04\x04\x02\x02\x01\x12\
    \x03\x14\x02\x1a\n\x0c\n\x05\x04\x02\x02\x01\x05\x12\x03\x14\x02\x07\n\
    \x0c\n\x05\x04\x02\x02\x01\x01\x12\x03\x14\x08\x15\n\x0c\n\x05\x04\x02\
    \x02\x01\x03\x12\x03\x14\x18\x19\n\n\n\x02\x04\x03\x12\x04\x17\0\x1a\x01\
    \n\n\n\x03\x04\x03\x01\x12\x03\x17\x08\x1f\n\x0b\n\x04\x04\x03\x02\0\x12\
    \x03\x18\x02\x1a\n\x0c\n\x05\x04\x03\x02\0\x05\x12\x03\x18\x02\x07\n\x0c\
    \n\x05\x04\x03\x02\0\x01\x12\x03\x18\x08\x15\n\x0c\n\x05\x04\x03\x02\0\
    \x03\x12\x03\x18\x18\x19\n\x18\n\x04\x04\x03\x02\x01\x12\x03\x19\x02\x16\
    \"\x0b\x201\x20mean\x201%\n\n\x0c\n\x05\x04\x03\x02\x01\x05\x12\x03\x19\
    \x02\x07\n\x0c\n\x05\x04\x03\x02\x01\x01\x12\x03\x19\x08\x11\n\x0c\n\x05\
    \x04\x03\x02\x01\x03\x12\x03\x19\x14\x15b\x06proto3\
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
            messages.push(BuyStorageBytesContract::generated_message_descriptor_data());
            messages.push(BuyStorageContract::generated_message_descriptor_data());
            messages.push(SellStorageContract::generated_message_descriptor_data());
            messages.push(UpdateBrokerageContract::generated_message_descriptor_data());
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
