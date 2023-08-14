use super::crypto::pbkdf2;
use super::Mnemonic;
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// The secret value used to derive HD wallet addresses from a [`Mnemonic`][Mnemonic] phrase.
///
/// Because it is not possible to create a [`Mnemonic`][Mnemonic] instance that is invalid, it is
/// therefore impossible to have a [`Seed`][Seed] instance that is invalid. This guarantees that only
/// a valid, intact mnemonic phrase can be used to derive HD wallet addresses.
///
/// To get the raw byte value use [`Seed::as_bytes()`][Seed::as_bytes()]. These can be used to derive
/// HD wallet addresses using another crate (deriving HD wallet addresses is outside the scope of this
/// crate and the BIP39 standard).
///
/// [`Seed`][Seed] implements [`Zeroize`][Zeroize], so it's bytes will be zeroed when it's dropped.
///
/// [Mnemonic]: ./mnemonic/struct.Mnemonic.html
/// [Seed]: ./seed/struct.Seed.html
/// [Seed::as_bytes()]: ./seed/struct.Seed.html#method.as_bytes

#[derive(Clone)]
pub struct Seed {
    bytes: Vec<u8>,
}

impl Seed {
    /// Generates the seed from the [`Mnemonic`][Mnemonic] and the password.
    ///
    /// [Mnemonic]: ./mnemonic/struct.Mnemonic.html
    pub fn new(mnemonic: &Mnemonic, password: &str) -> Self {
        let salt = format!("mnemonic{}", password);
        let normalized_salt = salt.nfkd().to_string();
        let bytes = pbkdf2(&mnemonic.as_bytes(), &normalized_salt);

        Self { bytes }
    }

    /// Get the seed value as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#X}", self)
    }
}

impl fmt::LowerHex for Seed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }

        for byte in &self.bytes {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for Seed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }

        for byte in &self.bytes {
            write!(f, "{:02X}", byte)?;
        }

        Ok(())
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bip39::Language;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    fn seed_hex_format() {
        let entropy = &[
            0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84,
            0x6A, 0x79,
        ];

        let mnemonic = Mnemonic::from_entropy(entropy, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "password");

        assert_eq!(format!("{:x}", seed), "0bde96f14c35a66235478e0c16c152fcaf6301e4d9a81d3febc50879fe7e5438e6a8dd3e39bdf3ab7b12d6b44218710e17d7a2844ee9633fab0e03d9a6c8569b");
        assert_eq!(format!("{:X}", seed), "0BDE96F14C35A66235478E0C16C152FCAF6301E4D9A81D3FEBC50879FE7E5438E6A8DD3E39BDF3AB7B12D6B44218710E17D7A2844EE9633FAB0E03D9A6C8569B");
        assert_eq!(format!("{:#x}", seed), "0x0bde96f14c35a66235478e0c16c152fcaf6301e4d9a81d3febc50879fe7e5438e6a8dd3e39bdf3ab7b12d6b44218710e17d7a2844ee9633fab0e03d9a6c8569b");
        assert_eq!(format!("{:#X}", seed), "0x0BDE96F14C35A66235478E0C16C152FCAF6301E4D9A81D3FEBC50879FE7E5438E6A8DD3E39BDF3AB7B12D6B44218710E17D7A2844EE9633FAB0E03D9A6C8569B");
    }

    fn test_unicode_normalization(
        lang: Language,
        phrase: &str,
        password: &str,
        expected_seed_hex: &str,
    ) {
        let mnemonic = Mnemonic::from_phrase(phrase, lang).unwrap();
        let seed = Seed::new(&mnemonic, password);
        assert_eq!(format!("{:x}", seed), expected_seed_hex);
    }

    #[cfg_attr(all(target_arch = "wasm32"), wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    /// Test vector is derived from https://github.com/infincia/bip39-rs/issues/26#issuecomment-586476647
    #[cfg(feature = "spanish")]
    fn issue_26() {
        test_unicode_normalization(
            Language::Spanish,
            "camello pomelo toque oponer urgente lástima merengue cutis tirón pudor pomo barco",
            "el español se habla en muchos países",
            "67a2cf87b9d110dd5210275fd4d7a107a0a0dd9446e02f3822f177365786ae440b8873693c88f732834af90785753d989a367f7094230901b204c567718ce6be",
        );
    }

    #[cfg_attr(all(target_arch = "wasm32"), wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    /// https://github.com/MetacoSA/NBitcoin/blob/master/NBitcoin.Tests/data/bip39_vectors.en.json
    fn password_is_unicode_normalized() {
        test_unicode_normalization(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "nullius　à　nym.zone ¹teſts² English",
            "61f3aa13adcf5f4b8661fc062501d67eca3a53fc0ed129076ad7a22983b6b5ed0e84e47b24cff23b7fca57e127f62f28c1584ed487872d4bfbc773257bdbc434",
        );
    }

    #[cfg_attr(all(target_arch = "wasm32"), wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    /// https://github.com/bip32JP/bip32JP.github.io/commit/360c05a6439e5c461bbe5e84c7567ec38eb4ac5f
    #[cfg(feature = "japanese")]
    fn japanese_normalization_1() {
        test_unicode_normalization(
            Language::Japanese,
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
        );
    }

    #[cfg_attr(all(target_arch = "wasm32"), wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg(feature = "japanese")]
    fn japanese_normalization_2() {
        test_unicode_normalization(
            Language::Japanese,
            "うちゅう　ふそく　ひしょ　がちょう　うけもつ　めいそう　みかん　そざい　いばる　うけとる　さんま　さこつ　おうさま　ぱんつ　しひょう　めした　たはつ　いちぶ　つうじょう　てさぎょう　きつね　みすえる　いりぐち　かめれおん",
            "㍍ガバヴァぱばぐゞちぢ十人十色",
            "346b7321d8c04f6f37b49fdf062a2fddc8e1bf8f1d33171b65074531ec546d1d3469974beccb1a09263440fc92e1042580a557fdce314e27ee4eabb25fa5e5fe",
        );
    }

    #[cfg_attr(all(target_arch = "wasm32"), wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg(feature = "french")]
    fn french_normalization() {
        test_unicode_normalization(
            Language::French,
            "paternel xénon curatif séparer docile capable exigence boulon styliste plexus surface embryon crayon gorge exister",
            "nullius　à　nym.zone ¹teſts² Français",
            "cff9ffd2b23549e73601db4129a334c81b28a40f0ee819b5d6a54c409999f0dfb6b89df17cae6408c96786165c205403d283baadc03ffdd391a490923b7d9493",
        );
    }
}
