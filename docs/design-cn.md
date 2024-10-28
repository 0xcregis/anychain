# 设计 AnyChain Wallet SDK 的出发点

1. 支持市值 TVL Top100 Token 的转账交易，包括：BTC、ETH、USDT、BNB、SOL、USDC、TON 等。相应地，需要接入的区块链包括：比特币、以太坊、索拉纳，以及各条链上的 L2 网络。
2. 实现跨平台编译，确保跨平台兼容性。考虑到源代码兼容性和工具链兼容性，编程语言选择限定为 C/C++/Rust。

## 公链的特性抽象

### 大多数公链需要支持的核心特性

- PublicKey（公钥）
- PrivateKey（私钥）
- Address（地址）
- Amount（金额）
- Transaction（交易）
- Network（网络）
- Format（格式）

anychain-core 作为一个全面的抽象 Trait，定义了以下通用方法：

```rust
pub trait PublicKey {
    fn from_private_key(private_key: &Self::PrivateKey) -> Self;
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

pub trait Address {
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Result<Self, AddressError>;
    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, AddressError>;
}

pub trait Amount {}

pub trait Format {}

pub trait Transaction {
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError>;
    fn sign();
    fn from_bytes();
    fn to_bytes(&self);
    fn to_transaction_id(&self);
}
```

### 各条链实现 Trait 的具体方法

以 anychain-tron 的 TronAddress 为例：

```rust
pub struct TronAddress([u8; 21]);

impl Address for TronAddress {
    type Format = TronFormat;
    type PrivateKey = TronPrivateKey;
    type PublicKey = TronPublicKey;

    fn from_private_key(
        private_key: &Self::PrivateKey, 
        format: &Self::Format
    ) -> Result<Self, AddressError> {
        todo!()
    }

    fn from_public_key(
        public_key: &Self::PublicKey, 
        format: &Self::Format
    ) -> Result<Self, AddressError> {
        todo!()
    }
}
```

通过引入 anychain-core 的抽象层和 anychain-bitcoin、anychain-tron 等链的具体实现，上层应用可以使用统一的代码和接口来调用 anychain SDK。

## 跨平台编译和技术栈

| 平台 | 目标文件格式 |
| --- | --- |
| iOS | .a（静态库） |
| Android | .so（共享对象） |
| Web/Wasm | .wasm（WebAssembly） |
| Windows | .dll（动态链接库） |
| macOS | .dylib（动态库） |
| 嵌入式设备 | ELF（可执行与可链接格式） |
| 可信执行环境（TEE） | .eif（加密镜像文件） |

### 以 iOS 平台为例，其调用层级结构

```
+-------------------+
| iOS Application   |
+-------------------+
        |
        | Link
        v
+-------------------+
| C Library (.dylib)|
+-------------------+
        |
        | FFI
        v
+-------------------+
| Rust Library      |
+-------------------+
        |
        | Compile
        v
+-------------------+
| Rust Source Code  |
+-------------------+
```

### 以 iOS 平台编译为例，其实现步骤包括：

1. 创建 Rust 库
2. 在 Rust 中使用 FFI（外部函数接口）
3. 定义 C-ABI 函数
4. 编译库文件
5. 将库文件链接到 iOS 应用
6. 处理数据类型
7. 测试和调试

### 最终编译目标的存储空间占用

| **平台/格式** | **文件名** | **大小** |
| --- | --- | --- |
| Docker 镜像 | enclave-server | < 17M |
| WebAssembly 包 | anychain_wasm_bg.wasm | 81K |
| STM32 | ROM | < 10M |
| iOS | anychain-ethereum-cli | 7.4M |

相比之下，web3.js/node_modules 需要引入高达 29M 的第三方包

## Anychain-KMS

### Anychain 基于 BIP32/BIP39 标准提供的工具函数集合

- 私钥（Private Key）
- 公钥（Public Key）
- 助记词（Mnemonic）
- 种子（Seed）
- 扩展密钥（Extended Key）
- 扩展私钥（Extended Private Key）
- 扩展公钥（Extended Public Key）
- 派生路径（Derivation Path）

这些工具函数用于支持各条区块链的钱包生成。