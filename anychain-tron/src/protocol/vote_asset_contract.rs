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

//! Generated file from `core/contract/vote_asset_contract.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_2_0;

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:protocol.VoteAssetContract)
pub struct VoteAssetContract {
    // message fields
    // @@protoc_insertion_point(field:protocol.VoteAssetContract.owner_address)
    pub owner_address: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:protocol.VoteAssetContract.vote_address)
    pub vote_address: ::std::vec::Vec<::std::vec::Vec<u8>>,
    // @@protoc_insertion_point(field:protocol.VoteAssetContract.support)
    pub support: bool,
    // @@protoc_insertion_point(field:protocol.VoteAssetContract.count)
    pub count: i32,
    // special fields
    // @@protoc_insertion_point(special_field:protocol.VoteAssetContract.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a VoteAssetContract {
    fn default() -> &'a VoteAssetContract {
        <VoteAssetContract as ::protobuf::Message>::default_instance()
    }
}

impl VoteAssetContract {
    pub fn new() -> VoteAssetContract {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(4);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_address",
            |m: &VoteAssetContract| { &m.owner_address },
            |m: &mut VoteAssetContract| { &mut m.owner_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "vote_address",
            |m: &VoteAssetContract| { &m.vote_address },
            |m: &mut VoteAssetContract| { &mut m.vote_address },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "support",
            |m: &VoteAssetContract| { &m.support },
            |m: &mut VoteAssetContract| { &mut m.support },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "count",
            |m: &VoteAssetContract| { &m.count },
            |m: &mut VoteAssetContract| { &mut m.count },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<VoteAssetContract>(
            "VoteAssetContract",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for VoteAssetContract {
    const NAME: &'static str = "VoteAssetContract";

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
                    self.vote_address.push(is.read_bytes()?);
                },
                24 => {
                    self.support = is.read_bool()?;
                },
                40 => {
                    self.count = is.read_int32()?;
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
        for value in &self.vote_address {
            my_size += ::protobuf::rt::bytes_size(2, &value);
        };
        if self.support != false {
            my_size += 1 + 1;
        }
        if self.count != 0 {
            my_size += ::protobuf::rt::int32_size(5, self.count);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.owner_address.is_empty() {
            os.write_bytes(1, &self.owner_address)?;
        }
        for v in &self.vote_address {
            os.write_bytes(2, &v)?;
        };
        if self.support != false {
            os.write_bool(3, self.support)?;
        }
        if self.count != 0 {
            os.write_int32(5, self.count)?;
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

    fn new() -> VoteAssetContract {
        VoteAssetContract::new()
    }

    fn clear(&mut self) {
        self.owner_address.clear();
        self.vote_address.clear();
        self.support = false;
        self.count = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static VoteAssetContract {
        static instance: VoteAssetContract = VoteAssetContract {
            owner_address: ::std::vec::Vec::new(),
            vote_address: ::std::vec::Vec::new(),
            support: false,
            count: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for VoteAssetContract {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("VoteAssetContract").unwrap()).clone()
    }
}

impl ::std::fmt::Display for VoteAssetContract {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for VoteAssetContract {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n'core/contract/vote_asset_contract.proto\x12\x08protocol\"\x8b\x01\n\
    \x11VoteAssetContract\x12#\n\rowner_address\x18\x01\x20\x01(\x0cR\x0cown\
    erAddress\x12!\n\x0cvote_address\x18\x02\x20\x03(\x0cR\x0bvoteAddress\
    \x12\x18\n\x07support\x18\x03\x20\x01(\x08R\x07support\x12\x14\n\x05coun\
    t\x18\x05\x20\x01(\x05R\x05countBE\n\x18org.tron.protos.contractZ)github\
    .com/tronprotocol/grpc-gateway/coreJ\xf0\x03\n\x06\x12\x04\0\0\r\x01\n\
    \x08\n\x01\x0c\x12\x03\0\0\x12\n\x08\n\x01\x02\x12\x03\x02\0\x11\n\x08\n\
    \x01\x08\x12\x03\x04\01\nH\n\x02\x08\x01\x12\x03\x04\01\"=Specify\x20the\
    \x20name\x20of\x20the\x20package\x20that\x20generated\x20the\x20Java\x20\
    file\n\n\x08\n\x01\x08\x12\x03\x06\0@\nr\n\x02\x08\x0b\x12\x03\x06\0@\
    \x1agoption\x20java_outer_classname\x20=\x20\"VoteAssetContract\";\x20//\
    Specify\x20the\x20class\x20name\x20of\x20the\x20generated\x20Java\x20fil\
    e\n\n\n\n\x02\x04\0\x12\x04\x08\0\r\x01\n\n\n\x03\x04\0\x01\x12\x03\x08\
    \x08\x19\n\x0b\n\x04\x04\0\x02\0\x12\x03\t\x02\x1a\n\x0c\n\x05\x04\0\x02\
    \0\x05\x12\x03\t\x02\x07\n\x0c\n\x05\x04\0\x02\0\x01\x12\x03\t\x08\x15\n\
    \x0c\n\x05\x04\0\x02\0\x03\x12\x03\t\x18\x19\n\x0b\n\x04\x04\0\x02\x01\
    \x12\x03\n\x02\"\n\x0c\n\x05\x04\0\x02\x01\x04\x12\x03\n\x02\n\n\x0c\n\
    \x05\x04\0\x02\x01\x05\x12\x03\n\x0b\x10\n\x0c\n\x05\x04\0\x02\x01\x01\
    \x12\x03\n\x11\x1d\n\x0c\n\x05\x04\0\x02\x01\x03\x12\x03\n\x20!\n\x0b\n\
    \x04\x04\0\x02\x02\x12\x03\x0b\x02\x13\n\x0c\n\x05\x04\0\x02\x02\x05\x12\
    \x03\x0b\x02\x06\n\x0c\n\x05\x04\0\x02\x02\x01\x12\x03\x0b\x07\x0e\n\x0c\
    \n\x05\x04\0\x02\x02\x03\x12\x03\x0b\x11\x12\n\x0b\n\x04\x04\0\x02\x03\
    \x12\x03\x0c\x02\x12\n\x0c\n\x05\x04\0\x02\x03\x05\x12\x03\x0c\x02\x07\n\
    \x0c\n\x05\x04\0\x02\x03\x01\x12\x03\x0c\x08\r\n\x0c\n\x05\x04\0\x02\x03\
    \x03\x12\x03\x0c\x10\x11b\x06proto3\
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
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(VoteAssetContract::generated_message_descriptor_data());
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
