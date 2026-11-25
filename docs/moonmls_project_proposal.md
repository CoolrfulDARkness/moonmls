# moonmls 项目申报书

## 基本信息

- **项目名称**：MoonMLS：纯 MoonBit 零 FFI Sans-I/O IETF RFC 9420 MLS（Messaging Layer Security）端到端群组加密协议栈
- **参赛者**：CoolrfulDARkness
- **联系方式**：通过参赛申报表 / GitHub Issues 提供（公开仓库不留个人手机号）
- **GitHub 仓库链接**：https://github.com/CoolrfulDARkness/moonmls.git
- **项目方向**：工具库 / 密码学与安全通信基础设施（端到端群组加密与多端安全通信）
- **是否为移植项目**：否（基于 IETF RFC 9420 / RFC 9180 / RFC 7748 / RFC 8032 / RFC 8439 等正式国际标准规范原创实现的纯 MoonBit 协议栈）

---

## 项目简介

MoonMLS 在 MoonBit 生态中从零构建首个**纯 MoonBit、零 C/FFI 依赖、零 `unsafe`、零外部依赖、严格 Sans-I/O 架构**的下一代端到端群组加密协议栈（**IETF RFC 9420 Messaging Layer Security, MLS 1.0**），完整集成 **RFC 9180 HPKE（Hybrid Public Key Encryption）**、**Left-Balanced Binary Tree（TreeMath）**、**Ratchet Tree / TreeKEM**、**Epoch Key Schedule** 与 **Secret Tree**，并原生支持 **CS1（`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`）** 与 **CS3（`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`）** 双完整标准密码套件。

目前 `mooncakes.io` 与 GitHub 生态均尚无 RFC 9420 MLS 或 RFC 9180 HPKE 的纯 MoonBit 完整实现。MoonMLS 面向需要在 MoonBit（尤其是 Wasm 浏览器/边缘节点、跨平台即时通讯客户端、去中心化协作工具与多 Agent 安全通信总线）中构建**大规模异步端到端加密群聊、前向安全（FS）与事后安全（PCS）动态密钥协商、强原子性安全状态机**的开发者，提供一套代码零修改跨 **Wasm-GC / JavaScript / Native** 三端运行且 `-d` 零警告的工业级安全协议基础组件。

---

## 核心功能范围

- 提供严格 **IETF RFC 9420 §2.1.2 TLS Presentation Language 编解码器与 Left-Balanced Binary Tree 数学基座**（`tls`、`treemath`），强制 MLS Varint 最小编码并拒绝非法 `0xC0..0xFF` 前缀与尾随垃圾字节，完整实现 `root`/`left`/`right`/`parent`/`sibling`/`direct_path`/`copath`/`common_ancestor` 及安全溢出边界保护；
- 提供零 FFI、零 `unsafe` 纯 MoonBit 底层密码原语库（`crypto`），完整实现 **FIPS 180-4 SHA-256 / SHA-512**、**RFC 2104 HMAC-SHA256**、**RFC 5869 HKDF-SHA256**、**NIST SP 800-38D AES-128-GCM**、**RFC 8439 ChaCha20-Poly1305**、**RFC 7748 X25519**（含全 7 类低阶点拒绝）、**RFC 8032 Ed25519**（含严格 $S < L$ 规范性防签名延展性与 8 阶小阶/单位元公钥拒绝）、常时间字节比较（`ct_equal`）及前向安全 ChaCha20 确定性 CSPRNG（`DeterministicRng`）；
- 提供完整 **IETF RFC 9180 HPKE Core（Mode Base）与双 MLS 标准密码套件**（`ciphersuite`），支持 **DHKEM(X25519, HKDF-SHA256)** + **AES-128-GCM（CS1 `0x0001`）** / **ChaCha20-Poly1305（CS3 `0x0003`）**，完整实现 `DeriveKeyPair`、`ExpandWithLabel`、`DeriveSecret`、`DeriveTreeSecret`、`RefHash`、`SignWithLabel`/`VerifyWithLabel` 与 `EncryptWithLabel`/`DecryptWithLabel`；
- 提供完整 **RFC 9420 线协议二进制帧类型库**（`types`），覆盖全部 17 类标准 Wire Struct（`KeyPackage`、`Welcome`、`GroupInfo`、`GroupSecrets`、`RatchetTree`、7 类 `Proposal`、`Commit`、`UpdatePath`、3 类 `PublicMessage`、`PrivateMessage` 与强制全零尾部 padding 的 `PrivateMessageContent`）；
- 提供 **Ratchet Tree 状态机、TreeKEM 与真树状按需擦除 Secret Tree 引擎**（`tree`），实现 Add（含空白叶复用与 `unmerged_leaves` 维护）/ Update / Remove（含右空子树自动截半）、TreeHash、ParentHash 链覆盖验证、叶子签名验证、TreeKEM 路径加解密与合并后全树结构/密钥轮换/非低阶点强校验，以及按 RFC 9420 §9.2 按需分裂即删父节点、带 `O(1)` 原子试探、滑动乱序窗口、消费即毁前向安全与防前跳 DoS 保护的 Secret Tree 棘轮；
- 提供 **Epoch Key Schedule、PSK 与消息保护核心**（`schedule`），完整实现 14 项 Epoch 密钥派生、链式 PSK Secret、Confirmed/Interim Transcript Hash、ConfirmationTag / MembershipTag、MLS-Exporter 及 PublicMessage / PrivateMessage 端到端加解密与验签（含 `group_id`/`epoch`/`sender` 上下文强校验）；
- 提供严格 **Sans-I/O 强原子群组引擎与统一顶层门面**（`group`、`CoolrfulDARkness/moonmls`），实现 `KeyPackageBundle` 生成与能力/扩展去重校验、`MlsGroup::create` / `from_welcome` / `propose_add` / `propose_update` / `propose_remove` / `commit`（含 RFC 9420 §12.4.1 并发 `pending_proposals` 三趟确定性冲突过滤防死锁）/ `protect_application` / `process_message` / `export_secret`，所有校验均在克隆状态上完成后才原子提交，失败保证**零状态污染**；
- 提供一键可运行的 **7 阶段 5 人群组全生命周期 CLI 演示**（`moon run cmd/main --target wasm-gc|js|native`），实时演示 Alice/Bob/Charlie/Dave/Eve 5 人动态加人、乱序加密群聊、同代与跨 Epoch 重放拦截、前向安全（FS）实证、TreeKEM 密钥轮换事后安全（PCS）实证、动态踢人与被踢者隔离，以及 CS3 双套件自检；
- 提供面向 **IETF `mlswg/mls-implementations` 全部 11 份官方测试向量文件**的零文件 I/O 内置逐字节验证闭环：其中全量通过 `tree-math.json`（全 10 规模 `1..512` 叶）、`crypto-basics.json`（CS1 & CS3）、`psk_secret.json`（CS1 & CS3 全 22 组）、`key-schedule.json`（CS1 & CS3 全 5 Epochs × 14 字段）、`secret-tree.json`（CS1 & CS3 全 6 组 164 代密钥）、`message-protection.json`（CS1 & CS3 全 5 项）、`tree-operations.json`（官方仅定义 CS1 全 5 组）与 `welcome.json`（CS1 & CS3），并覆盖 `tree-validation.json`（CS1 & CS3 16 组代表树）、`treekem.json`（CS1 & CS3 8 组代表路径）与 `messages.json`（6 组 102 样本全 17 类线协议往返）；
- 提供覆盖 **Wasm-GC / JS / Native（MSVC）** 三端的 **160 项 `-d` 零警告回归测试**（含 `vectors/` 中 **32 项独立编号红队对抗安全测试 `SEC-01` ~ `SEC-32`** 与 **11 项跨包 IETF 集成校验**）、**15 项 `moon bench` 三端实测性能基准**（`wasm-gc` 下 5 人群组消息端到端加解密验签 **`952.22 µs`**、1 KiB ChaCha20-Poly1305 `21.11 µs`、X25519 `131.18 µs`、5 人完整 TreeKEM PCS 轮换 `34.63 ms`），以及三端全量测试/基准构建/CLI 冒烟零警告 GitHub Actions CI（`.github/workflows/ci.yml`）。

---

## 移植或参考说明

- **非代码移植项目**：全部 **30,384 行**纯 MoonBit 代码（其中核心实现源码 **12,229 行**，测试与内置官方向量/基准 **18,155 行**，57 个 `.mbt` 文件，零 FFI、零 `unsafe`）均为基于 IETF 正式 RFC 标准规范原创编写。
- **遵循的技术标准**：
  - **IETF RFC 9420**：The Messaging Layer Security (MLS) Protocol
  - **IETF RFC 9180**：Hybrid Public Key Encryption (HPKE)
  - **IETF RFC 7748 / RFC 8032**：Elliptic Curves for Security（X25519）与 Edwards-Curve Digital Signature Algorithm（Ed25519）
  - **IETF RFC 8439 / RFC 5869 / RFC 2104 / FIPS 180-4 / NIST SP 800-38D**：ChaCha20-Poly1305、HKDF-SHA256、HMAC-SHA256、SHA-256/512、AES-128-GCM
- **权威测试向量参考基线**：
  - **原项目名称**：mlswg/mls-implementations（IETF MLS 工作组 RFC 9420 官方互操作测试向量集，包含 `tree-math.json`、`crypto-basics.json`、`key-schedule.json`、`secret-tree.json`、`message-protection.json`、`tree-operations.json`、`tree-validation.json`、`treekem.json`、`welcome.json`、`psk_secret.json`、`messages.json` 共 11 份官方 JSON 向量）
  - **原项目链接**：https://github.com/mlswg/mls-implementations
  - **原项目说明**：IETF MLS Working Group 公开互操作测试向量仓库（仅用于逐字节对齐验证 RFC 9420 协议行为，未移植其任何实现代码）
