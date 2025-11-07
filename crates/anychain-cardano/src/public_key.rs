use {
    crate::{address::CardanoAddress, format::CardanoFormat},
    anychain_core::{AddressError, PublicKey, PublicKeyError},
    cml_chain::{
        address::{EnterpriseAddress, RewardAddress},
        certs::StakeCredential,
    },
    cml_crypto::{blake2b224, Ed25519KeyHash},
    core::{fmt, str::FromStr},
    curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE as G, Scalar},
    group::GroupEncoding,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoPublicKey(pub ed25519_dalek::VerifyingKey);

impl PublicKey for CardanoPublicKey {
    type SecretKey = Scalar;
    type Address = CardanoAddress;
    type Format = CardanoFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let pk = secret_key * G;
        let pk = pk.to_bytes();
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        Self(pk)
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        let bytes = self.0.as_bytes();
        let hash = blake2b224(bytes);
        let hash = Ed25519KeyHash::from(hash);
        let cred = StakeCredential::new_pub_key(hash);

        match format {
            CardanoFormat::Enterprise(network) => {
                let address =
                    EnterpriseAddress::new(network.info().network_id(), cred).to_address();
                Ok(CardanoAddress(address))
            }
            CardanoFormat::Reward(network) => {
                let address = RewardAddress::new(network.info().network_id(), cred).to_address();
                Ok(CardanoAddress(address))
            }
            _ => Err(AddressError::Message("unsupported format".to_string())),
        }
    }
}

impl FromStr for CardanoPublicKey {
    type Err = PublicKeyError;

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl fmt::Display for CardanoPublicKey {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
