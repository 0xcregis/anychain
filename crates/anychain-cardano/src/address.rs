use {
    crate::{format::CardanoFormat, public_key::CardanoPublicKey},
    anychain_core::{Address, AddressError},
    cml_chain::{
        address::{BaseAddress, EnterpriseAddress, RewardAddress},
        byron::AddressContent,
        certs::StakeCredential,
    },
    cml_core::serialization::ToBytes,
    cml_crypto::{Bip32PrivateKey, Bip32PublicKey},
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    std::hash::Hash,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CardanoAddress(pub cml_chain::address::Address);

impl CardanoAddress {}

impl Address for CardanoAddress {
    type SecretKey = Bip32PrivateKey;
    type Format = CardanoFormat;
    type PublicKey = CardanoPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        match format {
            CardanoFormat::Base(network) => {
                // Derive spend and stake keys
                let spend = derive_key(secret_key, 0, 0, 0);
                let stake = derive_key(secret_key, 0, 2, 0);

                // Create base address
                let spend_cred = StakeCredential::new_pub_key(spend.to_raw_key().hash());
                let stake_cred = StakeCredential::new_pub_key(stake.to_raw_key().hash());

                let address = BaseAddress::new(network.info().network_id(), spend_cred, stake_cred)
                    .to_address();

                Ok(Self(address))
            }
            CardanoFormat::Enterprise(network) => {
                // Derive spend key
                let spend = derive_key(secret_key, 0, 0, 0);
                let spend_cred = StakeCredential::new_pub_key(spend.to_raw_key().hash());

                let address =
                    EnterpriseAddress::new(network.info().network_id(), spend_cred).to_address();
                Ok(Self(address))
            }
            CardanoFormat::Reward(network) => {
                // Derive stake key
                let stake = derive_key(secret_key, 0, 2, 0);
                let stake_cred = StakeCredential::new_pub_key(stake.to_raw_key().hash());

                let address =
                    RewardAddress::new(network.info().network_id(), stake_cred).to_address();
                Ok(Self(address))
            }
            CardanoFormat::Byron(network) => {
                let byron_key = secret_key
                    .derive(harden(44))
                    .derive(harden(1815))
                    .derive(harden(0))
                    .derive(0)
                    .derive(0)
                    .to_public();

                let byron_addr = AddressContent::icarus_from_key(
                    byron_key,
                    network.info().protocol_magic().into(),
                );
                // round-trip from generic address type and back
                let generic_addr = cml_chain::address::Address::from_raw_bytes(
                    &byron_addr.to_address().to_bytes(),
                )
                .unwrap();
                Ok(Self(generic_addr))
            }
        }
    }

    fn from_public_key(
        _public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, AddressError> {
        todo!()
    }

    fn is_valid(address: &str) -> bool {
        cml_chain::address::Address::is_valid(address)
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

fn derive_key(
    private_key: &Bip32PrivateKey,
    account: u32,
    chain: u32,
    index: u32,
) -> Bip32PublicKey {
    private_key
        .derive(harden(1852))
        .derive(harden(1815))
        .derive(harden(account))
        .derive(chain)
        .derive(index)
        .to_public()
}

fn harden(index: u32) -> u32 {
    index | 0x80_00_00_00
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::CardanoNetwork;

    static PRIVATE_KEY_ALICE: &str = "xprv1pzvlzlh4c7x9uxr0tw90hy7mpazk9eq3kv7mfzmjytxfff9zuf0ls7vzzu5qcdzjq8v8mqnsu0d3p8ks90wfl8egpa545tgk5ycvmakgq2uj58p7s9qt6f9z8dlhcdm5lc0nycf8meqfa3gqu0s3mq69mv5se9za";
    static BASE_ADDR_ALICE: &str = "addr_test1qp5tjpeph2su74qrg60se276u6zvd90umxmctufxr0jf8gr7dsy677qxztemp72yqgu3xv35w2fts5c5k2c9szlrn5fqttkd5z";
    static BASE_ADDR_ALICE_MAINNET: &str = "addr1q95tjpeph2su74qrg60se276u6zvd90umxmctufxr0jf8gr7dsy677qxztemp72yqgu3xv35w2fts5c5k2c9szlrn5fqgatdca";
    static BASE_ADDR_BOB: &str = "addr_test1qz68r5889sfly48tvr3kmlcf2uc8dxvyk598mkt8qd200z8r8yuyp7vaas4ezh9pdn5vu3wzlntj0h6qdnt4mrmqu0pqt62yar";
    //
    #[test]
    fn test_from_secret_key() {
        let bip32_private_key = Bip32PrivateKey::from_bech32(PRIVATE_KEY_ALICE).unwrap();

        let format = CardanoFormat::Base(CardanoNetwork::Preprod);
        let address_alice = CardanoAddress::from_secret_key(&bip32_private_key, &format);
        assert!(address_alice.is_ok());
        let address_alice = address_alice.unwrap();
        assert_eq!(address_alice.to_string(), BASE_ADDR_ALICE);

        let format = CardanoFormat::Base(CardanoNetwork::Mainnet);
        let address_alice = CardanoAddress::from_secret_key(&bip32_private_key, &format);
        assert!(address_alice.is_ok());
        let address_alice = address_alice.unwrap();
        assert_eq!(address_alice.to_string(), BASE_ADDR_ALICE_MAINNET);

        let format = CardanoFormat::Enterprise(CardanoNetwork::Mainnet);
        let address_alice = CardanoAddress::from_secret_key(&bip32_private_key, &format);
        assert!(address_alice.is_ok());
        let address_alice = address_alice.unwrap();
        assert_eq!(
            "addr1v95tjpeph2su74qrg60se276u6zvd90umxmctufxr0jf8gqcl79cr",
            address_alice.to_string()
        );
    }
    #[test]
    fn test_is_valid_address() {
        assert!(CardanoAddress::is_valid(BASE_ADDR_ALICE));
        assert!(CardanoAddress::is_valid(BASE_ADDR_BOB));
        assert!(!CardanoAddress::is_valid("addr_test1_foo"));
    }

    #[test]
    fn test_from_address() {
        let address_alice = CardanoAddress::from_str(BASE_ADDR_ALICE);
        assert!(address_alice.is_ok());
        let address_bob = CardanoAddress::from_str(BASE_ADDR_ALICE);
        assert!(address_bob.is_ok());
    }
}
