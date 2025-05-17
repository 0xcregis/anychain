use {
    crate::{format::CardanoFormat, public_key::CardanoPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    curve25519_dalek::Scalar,
    std::hash::Hash,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CardanoAddress(pub cml_chain::address::Address);

impl Address for CardanoAddress {
    type SecretKey = Scalar;
    type Format = CardanoFormat;
    type PublicKey = CardanoPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        public_key.to_address(format)
    }
}

impl FromStr for CardanoAddress {
    type Err = AddressError;

    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        let address = cml_chain::address::Address::from_bech32(addr)
            .map_err(|error| AddressError::InvalidAddress(format!("{:?}", error)))?;
        Ok(Self(address))
    }
}

impl Display for CardanoAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0.to_bech32(None).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::CardanoAddress;
    use crate::{format::CardanoFormat, network::CardanoNetwork};
    use anychain_core::Address;
    use curve25519_dalek::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test() {
        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);

        let network = CardanoNetwork::Mainnet;
        let enterprise = CardanoFormat::Enterprise(network.clone());
        let reward = CardanoFormat::Reward(network);

        let addr1 = CardanoAddress::from_secret_key(&sk, &enterprise).unwrap();
        let addr2 = CardanoAddress::from_secret_key(&sk, &reward).unwrap();

        println!("Enterprise address: {}\nReward address: {}", addr1, addr2);
    }
}
