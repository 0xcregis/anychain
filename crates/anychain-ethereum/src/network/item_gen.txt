generating rust code from a provided item:

{
    item:
    HuobiEco = 128

    code:
    #[derive(Copy, Clone, Debug)]
    pub struct HuobiEco;

    impl EthereumNetwork for HuobiEco {
        const CHAIN_ID: u32 = 128;
    }
}

generating rust code from a provided item with annotation:

{
    item:
    Kotti = 6 // ETC testnet

    code:
    #[derive(Copy, Clone, Debug)]
    pub struct Kotti; // ETC testnet

    // ETC testnet
    impl EthereumNetwork for Goerli {
        const CHAIN_ID: u32 = 5;
    }
}