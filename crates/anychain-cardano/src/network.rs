/// Mainnet: This is the primary network where actual transactions occur and real ADA is used.
/// It is the live network used by end-users and applications.
///
/// Preview: This is a testing environment that mimics the mainnet but uses test ADA.
/// It is used for testing new features and updates before they are deployed to the mainnet.
///
/// Preprod: This is another testing environment similar to TestnetPreview, but it may be used for pre-production testing.
/// It allows developers to test their applications in an environment that closely resembles the mainnet before final deployment.

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CardanoNetwork {
    #[default]
    Mainnet,
    Preprod,
    Preview,
}

impl CardanoNetwork {
    pub fn info(&self) -> CardanoNetworkInfo {
        match self {
            CardanoNetwork::Mainnet => CardanoNetworkInfo::mainnet(),
            CardanoNetwork::Preprod => CardanoNetworkInfo::preprod(),
            CardanoNetwork::Preview => CardanoNetworkInfo::preview(),
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CardanoNetworkInfo {
    network_id: u8,
    protocol_magic: u32,
}
impl CardanoNetworkInfo {
    pub fn new(network_id: u8, protocol_magic: u32) -> Self {
        Self {
            network_id,
            protocol_magic,
        }
    }
    pub fn network_id(&self) -> u8 {
        self.network_id
    }
    pub fn protocol_magic(&self) -> u32 {
        self.protocol_magic
    }
    pub fn mainnet() -> CardanoNetworkInfo {
        CardanoNetworkInfo {
            network_id: 0b0001,
            protocol_magic: 764824073,
        }
    }
    pub fn preprod() -> CardanoNetworkInfo {
        CardanoNetworkInfo {
            network_id: 0b0000,
            protocol_magic: 1,
        }
    }
    pub fn preview() -> CardanoNetworkInfo {
        CardanoNetworkInfo {
            network_id: 0b0000,
            protocol_magic: 2,
        }
    }
}
