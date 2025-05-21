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
        let sk = [104u8, 78, 102, 228, 174, 250, 35, 99, 180, 223, 45, 40, 124, 22, 12, 130, 70, 82, 183, 48, 195, 95, 207, 80, 47, 5, 201, 222, 157, 148, 168, 13];
        let sk = Scalar::from_bytes_mod_order(sk);

        let sk_to = [189, 149, 70, 173, 231, 111, 65, 210, 164, 15, 24, 21, 180, 45, 148, 78, 252, 149, 36, 168, 70, 107, 84, 229, 47, 5, 213, 243, 253, 249, 19, 11u8];
        let sk_to = Scalar::from_bytes_mod_order(sk_to);

        let format = CardanoNetwork::Preprod;
        let format = CardanoFormat::Enterprise(format);
        
        let from = CardanoAddress::from_secret_key(&sk, &format).unwrap();
        let to = CardanoAddress::from_secret_key(&sk_to, &format).unwrap();

        println!("from: {}\nto: {}\n", from, to);
    }
}
