# kcp-cpp 移植计划 v5.12（参考 xtaci/kcp-go v5）

> 状态：**实施中**（v5.12，累计 20 轮对抗分析（75 条）+ 命名合规审计 + 源码逐行核验 + 用户决策；**P0 ~ P7 已完成**，P8 已定义待开工，仅剩 Linux 实机回归（E1），见 §6）  
> 目标：将 D:\work\kcp-go（Go）完整移植为 C++17 库，输出到 D:\work\kcp-cpp，零第三方依赖。  
> 已确认决策：① 加密层自包含实现；② Reed-Solomon 自实现；③ 验收含跨语言互通；  
> ④ **定位 = 全量独立库**（含 session 层，与 kcp-proxy-cpp 解耦，集成另行议）；  
> ⑤ **v1 = Windows + Linux 双平台**（不是仅 Windows，工期已含）；  
> ⑥ **AES = AES-NI intrinsics + T 表回退**（cpuid 运行时检测；见 §3 决策表）；  
> ⑦ **API 命名 = Google C++ Style**（函数 CamelCase、类型 CamelCase 无下划线、成员 snake_case + 尾下划线、常量 `k`+CamelCase；I/O 家族与廉价存取器按 Google 明文例外保持 snake_case；**v5.4 已修正 v5.2 把"函数 snake_case"误标为 Google 的错误**；映射表见 §3.3）。  
> 环境：Go 1.27.2 @ `C:\Program Files\Go\bin\go.exe`（不在 PATH，脚本用绝对路径）；MSVC `/W4` + GCC/Clang `-Wall -Wextra`；Windows x64 / Linux x64。

## 移植总原则（#36）

> **除并发原语与资源管理外，一律照抄 Go 行为（wire 格式、错误语义、边界判定、默认值全部一致）；并发与资源管理按 C++ 惯用法重写，并在 §3 逐条记录差异。**

理由：互通要求的是字节级与行为级一致，任何"顺手优化"都可能变成不可见的分叉。

## v4 → v5 修订摘要（第 11~15 轮，攻击面：运行时段语义 / FEC 恢复链 / 加密边角 / 测试可执行性）

| 轮  | 编号 | 修订                                                                                                                                             | 依据                              |
| -- | -- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 11 | 37 | 新增 **§3.6 Read/Write 运行时段语义**：Read 三路径（bufptr 残留 / DMA 直读 / recvbuf 中转）+ **消息边界语义**（返回一条消息而非填满 b）                                              | sess.go:296-334                 |
| 11 | 38 | output 回调补**非阻塞投递 + 队列满则丢 + recycle，靠 KCP 重传**语义                                                                                               | sess.go:229-245                 |
| 11 | 39 | **写死 `writeDelay` 默认 false**（Go 零值）→ 默认 Write 立即 `flush(FULL)`；`SetWriteDelay(true)` 才开聚合                                                      | sess.go:143,417,525             |
| 11 | 40 | **撤回 v3 #3"AEAD MTU quirk"误判**：`SetMtu` 有双重减头 `min(mtuLimit,mtu) - headerSize - aead.Overhead()`，构造路径同样走（sess.go:248）→ 包不超限。改写为 §3.7 SetMtu 契约 | sess.go:248,537-547             |
| 12 | 41 | **RS 补齐契约**：解码前全部 shard 补齐到 maxlen + **尾部清零**，仅缺失的数据分片（k<dataShards）分配空 buffer。P3 接口改为"调用方保证等长"，P4 负责补齐；P3 测试增变长场景                             | fec.go:278-290                  |
| 12 | 42 | recovered 缓冲**所有权转移**：成功归调用者、失败自回收。C++ 用 `vector<unique_ptr<Buffer>>`（P4 改为 owning `FecPacket`，见 D11）                                          | fec.go:293-307                  |
| 13 | 43 | **CFB 残字节纯 XOR 语义**：尾部不足一块只 XOR、不更新反馈寄存器、不再次加密；encrypt16 的宽切片 `dst[base:]` 是 Go slice 写法，等价 16B 块推进，直译必错                                       | crypt.go:421,466-501            |
| 13 | 44 | **BlockCrypt 接口分裂**：AEAD 的 `Encrypt/Decrypt` 是 panic 空操作，统一虚接口假设错误 → 拆 `BlockCrypt`(CFB) + `AeadCrypt`(Seal/Open) 双接口（v5.4 去 `I` 前缀）           | crypt.go:74-80                  |
| 13 | 45 | 常量值钉死：`initialVector` / `saltxor` 具体字节                                                                                                         | crypt.go:50-51                  |
| 13 | 46 | AEAD Seal：容量不足 panic（"increase MTU size"）、AAD=nil、每包 fillRand nonce（CFB 16B / GCM 12B）                                                         | crypt.go:82-87; sess.go:706-737 |
| 14 | 47 | SetDSCP 平台差异记录：Go 走 x/net/ipv4+ipv6，`dscp<<2` 进 TOS；Windows 仅部分支持，Linux 走 `IP_TOS`/`IPV6_TCLASS`                                               | sess.go:586-618                 |
| 14 | 48 | `SetReadBuffer/SetWriteBuffer` 对 Listener 接受的 session 返回 `errInvalidOperation`（`s.l == nil` 守卫）                                                | sess.go:621-642                 |
| 15 | 49 | 新增 **§6.2 丢包中继规格**（位置/模型/延迟注入/对照方式），P5 门禁否则不可判定                                                                                                | —                               |
| 15 | 50 | 新增 **§6.3 性能基线测量方法**（指标/流数/样本/统计量），P6 门禁否则不可判定                                                                                                 | —                               |
| 15 | 51 | snmp 计数器（FECRecovered/FECErrs/FECFullShardSet）升格为**测试断言手段**                                                                                    | fec.go:276,301,310              |
| 15 | 52 | IKCP_OVERHEAD 值、bufferpool mtuLimit 粒度、discardShards/shardHeap.Has 去重等边角补入 §4.7                                                                | 待查证项已列                          |

工期（v5 当时）：P2 1.5→2d，P3 1.5→2d，P4 1→1.5d，P5 3→3.5d，P6 4→4.5d，总量 18~~20d。\*\*已被 v5.1 的 20~~22.5d 取代，以 §7 为准。\**

### v5.1/v5.2 决策落地（用户拍板）

- **v5.1**：定位 = 全量独立库；双平台（platform/socket + 双熵源 + 双 preset，P0/P6 门禁双平台）；AES-NI + T 表回退（P2 门禁两条路径交叉互验）；工期 20~22.5d；新增 R16 平台分叉风险。
- **v5.2**：命名 = Google C++ Style（决策⑦）。§3.3 增补 Go→C++ 映射总表（session/listener/包级/crypt 工厂/KCP 内部/常量共 40+ 条）；**新增系统调用名遮蔽硬规则**（成员 read/write/close/recv/send/shutdown 与 POSIX 同名 → session/listener 只准调 platform 层封装，从架构上消灭遮蔽）；§3.4 错误码改 `k`+PascalCase 枚举 + `error_category`；§3.6/§3.7/§3.8/§4.6/§4.7 全部同步为 Google 风格命名。**（其中"函数 snake_case"是对 Google Naming 的误读——Google 函数规则是 CamelCase，仅存取器可小写；v5.4 已全面纠正，见下方修订摘要）**

### v5.2 → v5.3 修订摘要（第 16~20 轮，攻击面：修复自身引入的矛盾 / 未验证源码区 / 验收可判定性 / 文档完整性）

本轮 **4 条致命**，其中 1 条从 v1 一直错到 v5.2（段头重复计 conv），2 条是**编造/记错的 API**。

| 轮  | 编号     | 修订                                                                                                                                           | 依据                   |
| -- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| 16 | 53     | 常量命名**二分规则**：`IKCP_*`→`kIcp`+PascalCase，sess/crypt/fec 常量→`k`+PascalCase（消除 v5.2 的 `kIcp*` vs `kRtoDef` 自相矛盾）                                | 自查                   |
| 16 | 54     | 新增 **§3.4.1 偏离登记表 D1~D7**（总原则 #36 的强制配套：任何不照抄 Go 的点必须登记理由）                                                                                   | Go panic→错误码         |
| 16 | 55     | 工期行加"以 §7 为准"消歧（18~~20d 与 20~~22.5d 曾并存）                                                                                                     | —                    |
| 16 | 56     | 映射表格式统一（`KCP::input`→`input`）                                                                                                                | —                    |
| 17 | **57** | **【致命】段头定义错**：`kOverhead=24` **已含 conv**（kcp.go:58 注释 + mss=mtu−24，kcp.go:198）；旧文"conv4 + 24B 段头"重复计 conv，会让 `len` 字段与 `kcp.json` 全错         | kcp.go:58,198        |
| 17 | **58** | **【致命】crypt 工厂名错+漏项**：实名 `NewAESGCMCrypt`（非 `NewAESGCMBlockCrypt`）；**补漏 `NewAEADCrypt`**（包装外部 AEAD，crypt.go:103）                             | crypt.go:103,113,273 |
| 17 | **74** | **【致命】`DialWithOptionsConn` 系编造**，真实为 `NewConn/NewConn2/NewConn3/NewConn4`（sess.go:1511-1528）；`DialWithOptions` 无 key 参数（key 在 BlockCrypt 内） | sess.go:1511-1528    |
| 17 | 59     | §3.3 补 **API 全集核对表**（UDPSession 29 / Listener 11 / 包级 8 / 工厂 13，全部 grep 实测）；此后 API 条目必须附源码行号                                                 | 源码 grep              |
| 17 | 60     | **OOB 帧完整规格**：布局 `FEC头8‖conv4‖payload`、接收端 payload 偏移 12、`oob_max_size = kcp.mtu − 4`、复用 FEC 头但不进 FEC 编解码、超长/队列满/关闭三态                        | sess.go:872-935,1100 |
| 17 | 61     | 分流表标注**作用于解密后明文**（CFB 下 `data[4:6]` 是密文，对着密文找 0xf1 永远找不到）                                                                                    | §4.1 顺序              |
| 18 | 62     | 删除悬空编号 `E2`，展开为具体描述                                                                                                                          | 文档重写导致编号丢失           |
| 18 | 63     | 补**核心签名**（read/write/write_buffers/close/set_mtu/dial_with_options/listen_with_options/accept）+ `set_mtu` 返回值语义反转说明                          | —                    |
| 18 | 64     | §2 目录结构补 `lossy_relay.{hpp,cpp}` / `json_reader.{hpp,cpp}`                                                                                   | §6.2/§5.6 要求         |
| 18 | 65     | 新增 **§0.1 术语表**（KCP 段/FEC 头/shard/shard set/UDP 包/消息）                                                                                        | 文档内混用                |
| 18 | 66     | `fec.json` 字段 `rto_ms`→`encode_latency_ms`（原名误导为 RTO）                                                                                        | —                    |
| 19 | 67     | 互通矩阵 **8B 块 CFB 分支（TEA/XTEA）覆盖缺口显式记录**为已知且接受（理由：与 16B 共用实现，仅块长参数不同）                                                                          | 矩阵仅 4 种加密            |
| 19 | 68     | §6.3 补 **Go 基线参数必须与 C++ 完全一致**（不得依赖 kcp-go 默认值）+ 阈值来源说明 + 双平台各测                                                                              | 基线不可比                |
| 19 | 69     | P5 30% 丢包场景加 **120s 时限 + dead_link 处置规则**（超时不得无限等待）                                                                                          | RTO 退避/假失败           |
| 19 | 70     | P6 并发门禁补 **FEC(0,0)** 组（裸路径并发未验）                                                                                                             | —                    |
| 20 | 71     | §4.2 补**六种配置的 mtu/mss 计算表**（原文只举 GCM 一例）                                                                                                     | —                    |
| 20 | 72     | 编号断层说明：**#1~#18 的清单在 v3 重写时未保留**，正文不再引用这些编号；现引用范围 #19~#74 均有定义                                                                               | 文档完整性                |
| 20 | 73     | 偏离登记表兼作"Go 事实 vs 工程折中"索引，读者可一眼区分                                                                                                             | —                    |
| 20 | 75     | `listen_with_options` 返回类型改为 `std::unique_ptr<Listener>`（内含线程+socket，值返回不安全）；session 持 raw `Listener*` 防循环引用                                 | §3.1 所有权             |

### v5.3 → v5.4 修订摘要（第 21 轮，攻击面：**命名合规性**——拿 Google C++ Style Guide 的 Naming 各节逐条核 v5.3）

结论：类型/成员/常量/命名空间基本合规，**但"函数一律 snake_case"是 Chromium/LLVM 惯例，不是 Google**（Google 函数须 CamelCase，仅两类例外可小写）。这是 v5.2 的误读，影响面覆盖全部签名，故单开一轮全量纠正。

| 轮  | 编号     | 修订                                                                                                                                                                                                                                                                                                                                                          | 依据                                        |
| -- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| 21 | **76** | **【致命·风格】函数名按 Google 改 CamelCase**：动作/设置/工厂/包级函数全部 `Send`/`SetNoDelay`/`DialWithOptions`/`NewAesGcmCrypt`/`PeekSize`；仅两类保留 snake_case——(a) I/O 家族 `read`/`write`/`write_buffers`/`close`（"模仿既有 C++/POSIX 实体"例外），(b) 11 个廉价取值存取器 `conv()/rto()/srtt()/srtt_var()/local_addr()/remote_addr()/addr()/oob_max_size()/is_aead()/wait_snd()/mtu()`（"存取器可命名如变量"例外） | Google C++ Style: Function Names          |
| 21 | 77     | **类型名收干净**：`KCP`→`Kcp`、`UDPSession`→`UdpSession`、`IBlockCrypt`→`BlockCrypt`、`IAeadCrypt`→`AeadCrypt`、`const_buffer`→`ConstBuffer`（Google camel case 缩写只大写首字母；匈牙利式 `I` 接口前缀不鼓励）                                                                                                                                                                              | Google: Type Names / General Naming Rules |
| 21 | 78     | **常量去 `kIcp` 双前缀**：`kIcpOverhead`→`kOverhead`、`kIcpMtuDef`→`kMtuDef`、`kIcpRtoDef`→`kRtoDef`。`namespace kcp` 已限定作用域，再加 `Icp` 前缀属匈牙利记法；**原 #53 的"二分规则"作废**                                                                                                                                                                                                    | Google: Constant Names                    |
| 21 | 79     | **文件规则改全套 Google**：`.hpp`/`.cpp`→`.h`/`.cc`；`session.h`→`udp_session.h`（Google 要求文件名具体）；`detail/`→`internal/`（Google 代码库惯例，`detail` 是 Boost/STL 惯例）；**补 `#define` guard 规则** `KCP_<PATH>_<FILE>_H_`，禁用 `#pragma once`                                                                                                                                       | Google: File Names / The #define Guard    |
| 21 | 80     | **原"系统调用遮蔽硬规则"重写**：函数改 CamelCase 后 `Read/Write/Close` 与 POSIX 大小写不同、不再遮蔽，遮蔽面从 6 个缩到 3 个（仅保留小写的 `read`/`write`/`close`）；platform 层保留，但立论从"防遮蔽"改为"跨平台收敛 + 错误码归一"                                                                                                                                                                                              | 自查                                        |
| 21 | 81     | **修三处内部矛盾**：§3 决策表 `int Read(...)` 与 §3.3 `read` 冲突；§3.1 `Errc::closed_pipe` 与 §3.4 `kClosedPipe` 冲突；`Errc` 与 `ErrorCode` 两名并存 → 统一 `ErrorCode` + `k`+CamelCase                                                                                                                                                                                             | 自查                                        |
| 21 | 82     | 新增偏离 **D8：行宽 80 → 100**。Google 硬性要求 80 列，但密码学 T 表、hex 黄金向量、wire 布局注释在 80 列内不可读；`.clang-format` 用 `BasedOnStyle: Google, ColumnLimit: 100`                                                                                                                                                                                                                   | Google: Line Length                       |
| 21 | 83     | P0 增 `.clang-format` + `clang-format --dry-run --Werror` 门禁 + guard 命名检查；`json_reader` / `lossy_relay` 扩展名同步                                                                                                                                                                                                                                                | —                                         |
| 21 | 84     | §3.3 &#x589E;**"包"命名四层说明**（C++ 无包概念）：命名空间 `kcp` / `kcp::internal`、目录 `include/kcp/internal/`、文件名+扩展名、include 写法 `#include "kcp/udp_session.h"`                                                                                                                                                                                                              | 用户提问                                      |

### v5.4 → v5.5 修订摘要（P0 实施，非分析轮次）

| 编号     | 修订                                                                                                                                                        | 依据                                |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| **85** | **P0 完成**：脚手架、CMake 双 preset、platform socket 层、5 个黄金向量、Go 互通工具、两条命名门禁全部落地；门禁勾选见 §6 P0                                                                     | 实施                                |
| 86     | **向量生成改用 `go test -overlay` 注入**：`tools/golden/ref/golden_ref.go.txt` 以 `package kcp` 注入参考仓库（不落文件、不改仓库），换取 `fecEncoder`/`fecDecoder`/`initialVector` 的访问权 | 实施发现（原计划 `main.go` 直调不可行，这些符号未导出） |
| 87     | **`rs.json` 的 `matrix_head` 改为单位向量反解**：对 `e_c` 编码后读 parity 行首字节；由线性性等价于内部矩阵前若干行                                                                           | `genMatrix` 未导出                   |
| 88     | **`tools/interop` 目录分离**：`goserver/` + `goclient/` + `kcpcrypt/`；同目录两个 `main` 会让 `go build ./...` 失败                                                      | 实施                                |
| 89     | **`build.bat` 增 Windows SDK 回退**：`vcvars64.bat` 依赖 `reg.exe`，受限 shell 下静默失败，表现为 `LNK1104: kernel32.lib`；回退到标准 SDK 根下最新版本                                  | 实施发现                              |
| 90     | **新增环境阻塞 E1**：本机 WSL 被禁用且无独立 g++，Linux 侧 `build.sh` 冒烟未执行；Windows 侧 Debug/Release 全绿                                                                      | 环境                                |
| 91     | §4.7 常量表补齐 `convSize=4` 并逐条补行号（sess.go/fec.go）                                                                                                            | P0 门禁                             |

### v5.5 → v5.6 修订摘要（P1 + P2 实施，非分析轮次）

| 编号     | 修订                                                                                                                                                     | 依据                                   |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| **92** | **P1 完成**：crc32/sha1/hmac/pbkdf2、双后端 `FillRand`、30 项 snmp、定长 bufferpool；`primitives_test`/`foundation_test`/`entropy_test` 全绿                          | 实施                                   |
| **93** | **P2 完成**：AES(双路径)/GCM/Salsa20/TEA/XTEA/SimpleXOR/None + CFB + 双接口工厂；新增 `include/kcp/error.h`（§3.4 的 `ErrorCode` + `error_category`）——P1 遗留但 P2 工厂立即需要 | 实施                                   |
| **94** | **GHASH 位序判定**：块内是"首字节 MSB = x^0"、右移、归约 `0xE1` 入 byte 0；错解会让**密文全对而 tag 全错**（详见 §6 P2 实施记录 #1）                                                         | `crypt.json` aesgcm + NIST TC2 双仲裁   |
| **95** | **XTEA 表推进一次/对轮**，多推一次即全错（§6 P2 实施记录 #2）                                                                                                               | `crypt.json` xtea 向量                 |
| 96     | **TEA 轮数钉死为 16**（`tea.NewCipherWithRounds(key, 16)`，crypt.go:246），不是 x/crypto 默认 64；此前只在 §3.3 提了工厂名                                                    | crypt.go:246                         |
| 97     | **Salsa20 计数器每调用重启**：`salsa20.XORKeyStream` 每次重建 16B 输入块，跨包不复用 keystream，安全性依赖每包随机 nonce 头                                                             | salsa20.go:56-57, salsa20_ref.go:207 |
| 98     | **新增偏离 D9**：CFB 反馈寄存器用栈上数组，`BlockCrypt` 无可变状态 → `Encrypt/Decrypt` 为 `const`，**L1 锁取消**（§3.2 表同步）                                                       | 实施                                   |
| 99     | 风险表补 R17/R18（GHASH 约定、XTEA 节奏），两者均为 P2 实际踩中的"静默错密文"级问题                                                                                                 | 实施                                   |

### v5.6 → v5.7 修订摘要（P3 实施，非分析轮次）

| 编号      | 修订                                                                                                                                                                                       | 依据        |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| **100** | **P3 完成**：`internal/galois.{h,cc}`（0x11D 域、exp/log/64 KiB 乘法表）+ `internal/rs.{h,cc}`（系统性 Vandermonde、Gauss-Jordan 求逆、`Encode`/`ReconstructData`/`Reconstruct`）；`rs_test` 全绿              | 实施        |
| 101     | **RS 构造对齐 `klauspost/reedsolomon@v1.12.0` 的默认路径**：`vm[r][c] = r^c`（r 为域元素）→ 取顶部 `d×d` 方阵求逆 → `vm × topInv`（reedsolomon.go:220-244）。`matrix_head` 逐字节命中 (3,1)/(10,3)/(20,10)/(128,128) 四组 | `rs.json` |
| 102     | **`ReconstructData` 的 parity 语义显式化**：数据片齐全时它**不**补 parity（reedsolomon.go:1186 的 `dataOnly` 提前返回）；需补 parity 必须调 `Reconstruct`。P4 解码器只关心数据片，故用前者                                           | 实施 + 测试踩中 |
| 103     | 风险表补 R19：RS 层**不做**补齐/清零，长度不齐一律 `kInvalidArgument`（#41 的落地形态）——若把这层职责下沉到 RS，P4 的 padding bug 会被静默吸收                                                                                      | 实施        |


### v5.8 → v5.9 修订摘要（P5 实施，非分析轮次）

| 编号      | 修订                                                                                                                                         | 依据                      |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| **110** | **P5 完成**：`kcp.h` / `kcp.cc`（Kcp 状态机）+ `internal/{ringbuffer,kcp_segment,clock}.h` + `internal/clock.cc`；新增 `kcp_test` / `ringbuffer_test` | 实施                      |
| 111     | **§6.2 丢包中继落地为进程内 `Relay` + 注入式虚拟时钟**，UDP socket 形态推迟到 P6                                                                                  | 实施（新增偏离 D13）            |
| 112     | **新增偏离 D12**：段载荷改为 owning `std::vector`，取消 `newSegment` / `recycleSegment` 的池化契约                                                           | 实施                      |
| 113     | **`Kcp::Flush` 返回 `void`**：Go 的 `nextUpdate` 在三处调用（Input / Update / close）全被丢弃                                                             | 源码核验                    |
| 114     | **新增 `Kcp::IsDead()`**：Go 的 `state` 全仓只写不读；C++ 侧 dead_link 门禁与 P6 判活需要它                                                                    | 源码核验 + 实施               |
| 115     | 记录并测试 **flush 首帧空转**（`cwnd` 初值 0 → 首帧不发段，Phase 6 抬到 1 后下一 tick 才发）                                                                         | 实施（`TestCwndBootstrap`） |

### v5.7 → v5.8 修订摘要（P4 实施，非分析轮次）

| 编号      | 修订                                                                                                                            | 依据                                                                      |
| ------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **104** | **P4 完成**：`internal/fec.{h,cc}`（FecEncoder / FecDecoder / ShardHeap）+ `internal/byteorder.h`（LE 读写与 `TimeDiff`）；`fec_test` 全绿 | 实施                                                                      |
| 105     | **`fec.json` 新增 `encode-varlen` 向量**：同一 encoder 的**第二轮**，10 个 shard 载荷 200/187/…/83 字节                                        | 等长向量下 `maxSize − len == 0`，尾补零规则零覆盖；漏清零的变异测试此前是越界崩溃而非断言失败（§6 P4 实施记录末行） |
| 106     | **FEC 长度字段含自身 2 字节**（`size = len(buf) − payloadOffset`，fec.go:406），注释里的 `PAYLOAD(SIZE-2)` 易误读                                 | 源码核验                                                                    |
| 107     | **新增偏离 D11**：`FecPacket` 为 owning vector，恢复分片直接 move 移交，取消 #42 的池化所有权协议                                                       | 实施（RAII 消除一整类泄漏路径）                                                      |
| 108     | **autotune 从“仅挂点”降为“不实现”**：P4 不存在 `shouldTune` 分支                                                                             | Go 该分支会 `return nil` 丢包；参数变更（含 sampler）统一放 P8，否则验证不了重调后的恢复链             |
| 109     | 风险表补 R20（RS owning 接口多一跳 memcpy，视图化以 P6/P7 实测为触发条件）                                                                           | 实施                                                                      |

### v5.9 → v5.10 修订摘要（P6 实施，非分析轮次）

| 编号      | 修订                                                                                                                                                                              | 依据                                             |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **116** | **P6 完成**：`udp_session` / `listener` / `internal/{frame,blocking_queue,timedsched,rate_limiter}` + `platform/socket` 补 `ParseHostPort`/`SysWaitReadable`/`SysSetDscp`/`IsIgnorableRecvError`；测试 `frame_test`/`session_test`/`relay_test` | 实施                                             |
| 117     | **缺陷 1（致命）**：`Listener::Monitor` 把 `recvfrom` 错误当作致命错误，`return` 后整个 listener 上**所有**会话同时饿死。Windows 上对端关闭引发的 ICMP 端口不可达会在下一次 `recvfrom` 报 `WSAECONNRESET`(10054)，而这正是"传输正常结束"的场景。改为照抄 kcp-go：计数后继续读（§6 P6 缺陷记录 #1） | `WSAECONNRESET` 复现 + 变异测试双重确认                |
| 118     | **缺陷 2（致命）**：`Listener::close()` 未关闭子会话，`sessions_` 里的 `shared_ptr` 在析构 map 之后才析构会话，会话析构又回调 `CloseSession()` 擦除**已释放**的 map → `STATUS_HEAP_CORRUPTION`（约 1/10 概率）。改为 `Listener.Close` 语义：关闭全部子会话（listener.go:1158-1176） | `session_test` 堆损坏复现 12/12 转绿 + 变异测试确认            |
| 119     | **新增偏离 D14~D19**：有界 `select` 唤醒式读循环 / 批量读 / 队列关闭后可排干 / 发送缓冲逻辑长与容量分离 / `IsDead()` 可见 / 令牌桶替代 `x/time/rate`                                                                    | 实施                                             |
| 120     | **§6.2 补真 UDP 中继**：`tests/lossy_relay.{h,cc}`（双 socket 双线程，均匀 + Gilbert-Elliott，不重排不改字节）；与 P5 的虚拟时钟中继并存——前者验 socket 语义，后者验协议 | 实施                                             |
| 121     | **性能基线归因改为"每数据报 I/O 成本"**：此前"83% 平台往返上限"的算法把成批流水的段按单包往返折算，是错的。实测两点：窗口 32/128/512 吞吐不变（13.1/13.5/12.2 MB/s）→ 不是窗口×RTT；单流 12.8 MB/s ↔ 4.07 万数据报/秒 ≈ 24.6 µs/数据报，Go 侧 120 MB/s ≈ 5.5 µs/数据报 | `run_bench.py` + 窗口扫描 + `-discard` 对照（§6.3 归因表） |
| 122     | **已知单向缺口**：`-discard`（纯单向）只有 2.48 MB/s，因为接收侧无数据可捎带 ACK，只能走 `interval`=10 ms 的 flush tick，再被 Windows 定时器粒度放大到 ≈17 ms。属 KCP 协议本身的性质，非本实现缺陷；记录在 §6.3 以免被误读为回归 | `-discard` 对照                                   |
| 123     | 风险表更新 R7（实测比值 + 具体杠杆）、新增 R22（"接收错误被当作致命错误"这一类移植陷阱）                                                                                                            | 实施                                             |

### v5.10 → v5.11 修订摘要（P7 实施，非分析轮次）

| 编号      | 修订                                                                                                                                                                                  | 依据                                     |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| **124** | **P7 完成**：`tools/interop/run_matrix.py`（16 格 × 3 轮全绿，产出 `matrix.md`）+ `tools/interop/dump_packet.py`（按 §4 布局解码 / 逐字节 diff）+ `tools/interop/kcptap/`（Go 侧抓包） | 实施                                     |
| 125     | **每格加"首包逐字节对拍"断言**：发送侧抓的首个数据报与接收侧抓到的必须完全相同，48 次全一致。这把 P7 的证据从"校验和一致"升级为"线上字节一致"                                                                                    | 实施（`--dump-dir`）                       |
| 126     | **校验和由 Python 独立算出**（`payload[i] = i*7+11`），不用实现里的常量：两端实现同时错到"彼此一致"的情况抓不到，这样能抓到                                                                                                             | 实施                                     |
| 127     | **新增偏离 D20**：`SetPacketTrace`（session 与 listener 各一个）。Go 侧靠包装 `net.PacketConn` 即可，C++ 侧的 listener 自持 fd、`Dial` 自建 socket，库内不开洞就没法抓包                                                                  | 实施                                     |
| 128     | **澄清一处易误读**：`crypt=none` 仍是 **20 字节头**（`NoneBlockCrypt` 只是 Encrypt 空转，nonce+CRC32 照写）；真正的 0 字节头只在"不装 crypt 对象"时（`kcp::Listen`/`Dial`），与 Go 的 `Dial` 行为一致。抓包实测确认，写进 `dump_packet.py` 的注释 | 实测（`none` 抓到 20 字节头）                    |

### v5.11 → v5.12 修订摘要（P8 定义，非分析轮次）

| 编号      | 修订                                                                                                                        |
| ------- | ------------------------------------------------------------------------------------------------------------------------- |
| **129** | **新增 `bench/syscall_cost`**：逐调用定价，墙钟 + 进程 CPU 双时钟。测得 `sendto` 41~46 µs 而 `WSASendTo`（含 null OVERLAPPED 的同步语义）2.6 µs |
| **130** | **新增 `tools/interop/syscallprobe`**：Go 侧同构对照（未连接 `WriteTo` 2.9 µs），加上 Python `sendto` 45 µs，三方一致 ⇒ 与语言运行时无关，是 API 行为               |
| **131** | **勘误**：§6.3.1 旧写的"4.07 万数据报/秒 ≈ 24.6 µs/包"与 12.2 MB/s ÷ 1376 自相矛盾，改为 8.9k 包/秒/方向 ≈ 112 µs/包；Go 侧同步从 5.5 µs 改为 11.5 µs  |
| **132** | **新增 P8 阶段定义**（P8.0 仪器化 → P8.1 `WSASendTo` → P8.2 读路径 → P8.3 IOCP → P8.4 Linux 批量 → P8.5 GHASH → P8.6 RS），含每项门禁、触发条件、止损与 §6.3.2 台账  |
| **133** | 风险表补 R23（"per-call 系统调用成本随 API 变化 15 倍"这类平台陷阱）                                                                            |

### v5.12 → v5.13 修订摘要（P8.0 实施，非分析轮次）

| 编号      | 修订                                                                                                                                                                                                                                                                            | 依据    |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| **134** | **P8.0 完成，结论是 P8 的立论前提不成立**：§6.3.1 的 12.2 MB/s / 112 µs/包 / `sendto` 41~46 µs 是当时机器状态的测量，**当前不可复现**。判定实验：`git stash` 掉全部仪器化后用已提交代码跑同一基准得 109.5 MB/s——不是仪器化回归（仪器化版同参数 108.5 MB/s），是机器状态差异。§6.3.1 整体标注为"历史记录"                                     | 实测    |
| **135** | **新增 `platform/profile`（`include/kcp/platform/profile.h` + `src/platform/profile.cc`）与 `UdpSession::EnableProfiling()/profile()`**：五本 CPU 账（read 线程 / post 线程 / update 回调 / writer / reader）+ `SysSendTo`/`SysRecvFrom`/`SysWaitReadable` 调用计数与墙钟。默认关闭（每数据报一次 relaxed atomic load，`bench/syscall_cost` 的 CLOCK 行给出两种时钟读的价格：wall 0.019 µs、thread CPU 0.089 µs）        | 实施    |
| **136** | **新增 `tools/bench/profile_split.py`**：折叠 `PROFILE` 行为 §6.3.2 分解表并执行门禁。两处门禁口径按实测修正：① CPU 闭合 ±10%（Windows `GetThreadTimes` 粒度 15.6 ms，短跑量化失败——4 MiB/120 ms 误差 +33%，运行须 ≥1 s）；② 定价对照从"±5% 相等"改为两级（>50% 警告 / >150% 失败）——会话内 `sendto` 发给另一进程的存活对端，含跨进程唤醒，与同进程微基准不可能相等；说谎的计数器落在 10x，不与 2x 混淆 | 实施    |
| **137** | **§6.3.2 台账填入当前状态分解表**：三配置全部门禁通过（CPU 闭合 -0.8~-2.5%）。单流 `none` 148.6 MB/s（P8 目标线 25 MB/s 已超额 4.5 倍达成）；每数据报 CPU 13.3 µs，系统调用只占约 4.7 µs 墙钟，工作量均匀分布于 read/post/reader 三线程（33/33/30%）                                                                                              | 实测    |
| **138** | **P8.1 触发条件失效**："换 API 省 15~17 倍"在当前状态是 **1.3 倍**（`sendto` 3.4 µs vs `WSASendTo` 2.7 µs），按每数据报算只值 ~1 µs（<10% CPU）。按 P8 通用规则 4 记录为"当前不是主要瓶颈"，**不在当前状态实施**                                                                                                                                       | 实测    |
| **139** | **P8.2/P8.3/P8.5/P8.6 触发条件按新表重算均未满足**（读路径系统调用 <15% CPU、无 >30% I/O 等待可省、P8.5 的前置链"P8.1/P8.3 先压下每包成本"未发生）。P8.4 仍依赖 E1                                                                                                                                                                        | 实测    |
| **140** | **机器状态漂移写入方法论（§6.3）**：同一工作负载多次干净全量基线，`none` 单流 109.5 / 111.7 / 160.5 MB/s——run 内 min/max 很紧（±1%），run 间差 45%。旧基线恰逢一次"机器忙"窗口（当日 relay_test 同窗口 111 次重传），C++ 客户端 4 线程在该窗口塌到 12.8 MB/s 而 Go 的 IOCP 客户端同窗口仍有 122 MB/s——**线程多的实现在机器忙时先塌**。规则：跨会话基线结论必须来自同机会话内多轮中位数，单次测量不足以支撑 P8 排序                                            | 实测    |

---

## 0.1 术语表（#65，消除"段/帧/包/shard/消息"混用）

| 术语                              | 定义                                                                                   | 字节量级                      |
| ------------------------------- | ------------------------------------------------------------------------------------ | ------------------------- |
| **KCP 段**（segment）              | KCP 协议单位：**24B 段头**（含 conv）+ payload                                                 | 24 ~ mtu                  |
| **FEC 头**（FEC header）           | `seqid(4) + type(2) + size(2)`，即 `kFecHeaderSizePlus2=8`                             | 8                         |
| **shard**（分片）                   | FEC 编解码单元，data shard 或 parity shard                                                  | ≤ ~1400                   |
| **shard set**（分片组）              | 同一 `shardId = seqid / shardSize` 下的 data+parity 集合                                   | dataShards+parityShards 个 |
| **UDP 包**（packet）/ **帧**（frame） | 最终上线的字节序列 = 加密头 + FEC 头 + KCP 段（依配置，§4.2）。本文件"帧"与"UDP 包"同义；"OOB 帧/FEC 帧"特指其 type 字段值 | ≤ 1500                    |
| **消息**（message）                 | `write()` 一次写入、`read()` 一次读出的逻辑单元；可被 `frg` 拆成多个 KCP 段                                | 任意（受窗口限制）                 |

---

## 1. 范围

| Go 源文件              | 行数   | C++ 输出                                           | 复杂度 |
| ------------------- | ---- | ------------------------------------------------ | --- |
| kcp.go              | 1147 | kcp.h / kcp.cc                                   | 高   |
| sess.go             | 1534 | udp_session.h / udp_session.cc（+ listener.h/.cc） | 高   |
| crypt.go            | 696  | crypt.h + internal/{aes,gcm,salsa20,tea,cfb}     | 高   |
| fec.go              | 512  | internal/fec.h / internal/fec.cc                 | 中   |
| ringbuffer.go       | 244  | internal/ringbuffer.h                            | 中   |
| snmp.go             | 216  | snmp.h / snmp.cc                                 | 低   |
| timedsched.go       | 184  | internal/timedsched.h/.cc                        | 中   |
| entropy.go          | 171  | internal/entropy.h                               | 低   |
| autotune.go         | 157  | P8 可选                                            | 低   |
| bufferpool.go       | 79   | internal/bufferpool.h                            | 低   |
| readloop.go / tx.go | 126  | 并入 udp_session.cc                                | 中   |

**不移植**：批量收发（`recvmmsg/sendmmsg`，见 R7 性能差距）；3DES/Blowfish/CAST5/Twofish/SM4；`x/time/rate`（自实现令牌桶）。

**自实现密码学范围（对照 crypt.go import 面核实，#52）**：pbkdf2 / salsa20 / tea / xtea / sha1 / crc32 自实现；aes / aesgcm 自实现；sm4 / blowfish / cast5 / twofish 留占位工厂报 `unsupported_cipher`。

---

## 2. 目录结构

```
D:\work\kcp-cpp\
├── CMakeLists.txt / CMakePresets.json / .clang-format / build.bat / build.sh
├── PORTING-PLAN.md / LICENSE / README.md / .gitignore
├── bench.md / matrix.md         # 生成物：§6.3 性能基线 / P7 互通矩阵（脚本产出，入库便于对照）
├── include/kcp/{kcp,crypt,udp_session,listener,snmp,error}.h
├── include/kcp/internal/{primitives,entropy,clock,byteorder,aes,gcm,salsa20,tea,cfb,
│                        bufferpool,galois,rs,fec,frame,ringbuffer,kcp_segment,
│                        blocking_queue,timedsched,rate_limiter}.h
├── include/kcp/platform/{socket,entropy_backend}.h   # 决策⑤：WinSock2/POSIX 双实现
├── src/...                      # 与 include 同名 .cc，文件头注释含 MIT 出处
├── tests/                       # 集成测试串行执行；端口 = base + (pid % 1000)
│   ├── lossy_relay.{h,cc}       # 丢包中继（§6.2：均匀 + Gilbert-Elliott，真 UDP 双线程）
│   └── json_reader.{h,cc}       # 黄金向量扁平解析器（§5.6）
├── tools\
│   ├── golden\                  # 黄金向量生成器
│   │   ├── go.mod  main.go  gen.bat
│   │   └── out\{crypt,rs,fec,kcp,frame}.json
│   ├── interop\
│   │   ├── go.mod               # replace → D:/work/kcp-go（与 golden 相同）
│   │   ├── goserver\            # Go echo 服务端（互通 + 性能基线）
│   │   ├── goclient\            # Go echo 客户端（反向互通 + 基线对拍）
│   │   ├── kcptap\               # 包装 net.PacketConn 抓首包（不改 kcp-go）
│   │   ├── syscallprobe\         # Go 侧 sendto/WriteTo 单位成本（§6.3.1 旁证）
│   │   ├── run_matrix.py        # 16 格编排：2 方向 × 4 加密 × 2 FEC
│   │   └── dump_packet.py       # 互通失败定位：抓首包 hexdump + 二进制 diff
│   └── bench\run_bench.py       # §6.3 基线驱动：cpp / go 两侧同参数，5 轮取中位数，产 bench.md
├── examples\                    # 不属库，供 P6/P7 与手工测真实链路
│   ├── echo_common.{h,cc}       # 参数解析 + 与 kcpcrypt.Make 同名的 crypt 表 + SHA-256
│   └── {echo_server,echo_client}.cc
└── bench\                       # 归因用微基准（§6.3）
    ├── kcp_pump.cc              # 纯 KCP 状态机吞吐（无 I/O、无加密）
    ├── udp_pingpong.cc          # 跨线程 UDP 往返延迟（平台每数据报握手成本）
    ├── syscall_cost.cc          # 逐调用定价：sendto/WSASendTo/recvfrom/select(0)，墙钟 + CPU 双时钟
    └── aes_bench.cc             # AES-NI vs T 表两条后端
```

**文件与 include 规则（Google）**：文件名全小写 + 下划线，**头 `.h` / 源 `.cc`**；每个头文件用 `#define` guard（格式 `<PROJECT>_<PATH>_<FILE>_H_`：`KCP_UDP_SESSION_H_`、`KCP_INTERNAL_AES_H_`、`KCP_PLATFORM_SOCKET_H_`），**禁用 `#pragma once`**；include 一律从项目根写 `#include "kcp/udp_session.h"`，内部头写 `#include "kcp/internal/aes.h"`；include 顺序 = 对应头 → C 系统 → C++ 标准库 → 本项目 → 第三方（本项目零第三方，此级恒空）。

**平台抽象（决策⑤）**：`platform/socket.h` 统一 `sys_socket/sys_close/sys_sendto/sys_recvfrom/sys_setsockopt/sys_shutdown` 与 `last_error()`（内部映射 `WSAGetLastError`/`errno`）；`platform/entropy_backend.h` 统一 `FillRand`（Windows `BCryptGenRandom` / Linux `getrandom(2)`，均无需链接第三方库——Linux 走 glibc）。CMake：Windows 链 `ws2_32`；Linux 链 `Threads::Threads`。

**网络策略（#30）**：所有回环与互通测试走 `127.0.0.1` 双进程，不使用外部地址，因此**不涉及 Windows 防火墙放行**。示例程序支持 `--addr` 覆盖以便用户手工测真实链路。

---

## 3. 设计决策

| 决策点      | 方案                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 错误处理     | 核心层返回 `ErrorCode` 不抛异常；会话层 `int read(void*, size_t, std::error_code* = nullptr)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 时间       | `steady_clock`；KCP 内部 uint32 毫秒 + `itimediff`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 命名（决策⑦）  | **Google C++ Style**（v5.4 修正）。函数 CamelCase：`Send`/`SetNoDelay`/`DialWithOptions`/`NewAesGcmCrypt`/`PeekSize`；**两类例外保持 snake_case**——① I/O 家族 `read`/`write`/`write_buffers`/`close`，② 11 个廉价取值存取器（`conv()`/`rto()`/`srtt()`/`srtt_var()`/`local_addr()`/`remote_addr()`/`addr()`/`oob_max_size()`/`is_aead()`/`wait_snd()`/`mtu()`）。类型 CamelCase 无下划线、**缩写只大写首字母**、接口无 `I` 前缀：`Kcp`/`UdpSession`/`FecEncoder`/`BlockCrypt`/`AeadCrypt`/`ConstBuffer`。成员 snake_case + 尾下划线（`snd_wnd_`/`mu_`）；wire 结构体字段 snake_case 无后缀（`cmd`/`frg`/`sn`）；常量与枚举值 `k`+CamelCase（`kMtuDef`/`kOverhead`/`kTimeout`），**无 `kIcp` 前缀**；命名空间 `kcp` / `kcp::internal`；文件 `.h`/`.cc` + `#define` guard。详见 §3.3 |
| 格式化      | `.clang-format`：`BasedOnStyle: Google`，**`ColumnLimit: 100`（偏离 D8，Google 为 80 列）**；`clang-format --dry-run --Werror` 入门禁                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 警告       | MSVC `/W4` + GCC/Clang `-Wall -Wextra`；移植代码允许带原因注释的 pragma 抑制                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 平台（决策⑤）  | **Windows + Linux 双平台**：socket 层双实现（WinSock2 / POSIX），`std::thread`+condvar 跨平台，熵源双后端（BCryptGenRandom / getrandom）；CMake 双 preset                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| AES（决策⑥） | **AES-NI intrinsics + T 表回退**：cpuid 运行时检测；AES-NI 路径比 T 表快 2~3 倍且指令级恒定时间；无 AES-NI 的老 CPU 回退 T 表（README 记录该路径的 cache-timing 差距，R5）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

### 3.1 所有权与生命周期（#19/#20/#21）

```
DialWithOptions / Listener::AcceptKcp → std::shared_ptr<UdpSession>
Listener::sessions_        → unordered_map<string /*源地址*/, shared_ptr<UdpSession>>
TimedSched 延迟回调        → std::weak_ptr<UdpSession>（回调内 lock() 失败即跳过）
```

`close()` 契约（跟随 Go + C++ 必需修正）：

1. **幂等但重复调用返回错误**：首次 `close()` 置 `closed_` 并返回成功；再次调用返回 `ErrorCode::kClosedPipe`（照抄 sess.go:470-472）
2. **`close()` 前 `kcp_->Flush(kFlushFull)`**：持 L2 冲出尾部数据（sess.go:477-479）
3. **必须 join 两个线程**：读线程与 `PostProcess` 线程。Go 靠 goroutine 自然退出，C++ 不 join 会 `std::terminate()`（#20）。join 前置条件：`die_` 置位 + 队列关闭 + socket shutdown，保证线程可退出
4. Listener 侧 session 的 `close()` **不关共享 socket**，只移除自身表项（sess.go:481-484）
5. `close()` 后 `write` 返回 `kClosedPipe`；`read` 返回 `kClosedPipe`；socket 错误返回原始错误

### 3.2 锁层级与并发规则

| 级别     | 锁                                                       | 保护对象                           |
| ------ | ------------------------------------------------------- | ------------------------------ |
| L0     | 原子                                                      | Snmp 计数、状态位                    |
| ~~L1~~ | ~~`BlockCrypt` 工作缓冲互斥 `enc_mu_`/`dec_mu_`~~ **已取消（D9）** | CFB 反馈寄存器改栈上局部变量，实现无共享可变状态     |
| L2     | `UdpSession::mu_`                                       | KCP 状态、recv_buf\_、FEC 编解码器、写队列 |
| L3     | `Listener::session_lock_`                               | sessions 映射、accept 队列          |

通道/队列成员（Go channel → C++ 封装）：`chReadEvent`→`read_event_`、`chWriteEvent`→`write_event_`、`chSocketReadError`→`socket_read_error_`、`chSocketWriteError`→`socket_write_error_`、`chPostProcessing`→`post_processing_`（BlockingQueue，满则丢，#38）。

1. 加锁顺序 **L3 → L2**（原 L3→L2→L1 的 L1 已由 D9 取消）
2. **阻塞等待必须释放 L2**：`cv_.wait_until(lk, deadline, pred)`；禁止持 L2 调 sleep/join/sendto
3. `PostProcess` 调平台层发送前已释放 L2
4. 回调（TimedSched/accept/OOB handler）**不得持锁调用用户代码**；OOB handler 由 KCP 输入路径同步调用，文档要求"MUST 快速返回、不得阻塞"（照抄 sess.go:845-848）
5. `PacketInput`（读线程）与 `Update`（调度线程）对 KCP 的访问全在 L2 内

**与 Go 的已知并发差异（#22）**：Go 的 `TimedSched` 是两阶段并行调度器（1 prepend + `max(NumCPU,2)` 个 worker，timedsched.go:34,95），多个 worker 可能**并发**调用同一 session 的 `Update()`，靠 L2 串行化。C++ v1 采用**单线程定时堆**（回调永不并发），语义等价（`Update` 本身是幂等的状态机推进）但少了并行唤醒；差异记录在 README，不影响互通。


### 3.3 API 覆盖清单与命名映射（验收 100%）

**命名规则（Google C++ Style，决策⑦ / v5.4 修正）**：

| 类别                     | 规则                                                                      | 示例                                                                                                                               |
| ---------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 类型                     | CamelCase、无下划线、**缩写只大写首字母**、接口**不加 `I` 前缀**                             | `Kcp`、`UdpSession`、`FecEncoder`、`BlockCrypt`、`AeadCrypt`、`ConstBuffer`                                                           |
| 函数（动作/设置/工厂/包级）        | CamelCase                                                               | `Send`、`SetNoDelay`、`DialWithOptions`、`NewAesGcmCrypt`、`PeekSize`、`PostProcess`                                                  |
| 函数 · **例外 1**：I/O 语义家族 | snake_case（Google "Exceptions to Naming Rules"：模仿既有 C++/POSIX 实体时沿用原命名） | `read`、`write`、`write_buffers`、`close`                                                                                           |
| 函数 · **例外 2**：廉价取值存取器  | snake_case（Google "Accessors may be named like variables"）              | `conv()`、`rto()`、`srtt()`、`srtt_var()`、`local_addr()`、`remote_addr()`、`addr()`、`oob_max_size()`、`is_aead()`、`wait_snd()`、`mtu()` |
| 成员 / 参数 / 局部           | snake_case；**类成员加尾下划线**                                                 | `snd_wnd_`、`mu_`、`recv_buf_`、`buf_ptr_`                                                                                          |
| wire 结构体字段             | snake_case，**无尾下划线**                                                    | `cmd`、`frg`、`sn`、`len`                                                                                                           |
| 常量 / 枚举值               | `k` + CamelCase；**不加 `kIcp` 前缀**（`namespace kcp` 已限定作用域）                | `kMtuDef`、`kOverhead`、`kRtoDef`、`kClosedPipe`、`kTypeData`                                                                        |
| 命名空间                   | 全小写、顶层用项目名；内部实现用 `internal`（Google 惯例，**不用 `detail`**）                  | `kcp`、`kcp::internal`                                                                                                            |
| 宏（仅 guard 与平台宏）        | `KCP_` + 全大写                                                            | `KCP_UDP_SESSION_H_`                                                                                                             |

**"包"的命名（用户提问 #84：C++ 无包概念，对应四层，逐层定死）**：

| 层          | 规则                                   | 落地                                                                           |
| ---------- | ------------------------------------ | ---------------------------------------------------------------------------- |
| 命名空间       | 顶层 = 项目名、全小写；内部实现置于 `internal` 子命名空间 | `namespace kcp {}` / `namespace kcp::internal {}`；关闭时写 `}  // namespace kcp` |
| 目录         | 全小写，公开头与内部头物理分离                      | `include/kcp/`（公开）、`include/kcp/internal/`（内部）、`include/kcp/platform/`（平台抽象） |
| 文件名 / 扩展名  | 全小写 + 下划线，**须具体**；头 `.h`、源 `.cc`     | `udp_session.h`、`blocking_queue.cc`（不写 `session.h`、`queue.cc`）               |
| include 写法 | 从项目根起算，不写相对路径                        | `#include "kcp/udp_session.h"`                                               |

**Go → C++ 映射总表**（实现时对照源码用，验收逐条核对）：

| Go（kcp-go）                        | C++（kcp-cpp）                                       |   | Go                          | C++                      |
| --------------------------------- | -------------------------------------------------- | - | --------------------------- | ------------------------ |
| `UDPSession.Read`                 | `UdpSession::read`                                 |   | `SetReadBuffer`             | `SetReadBuffer`          |
| `UDPSession.Write`                | `write`                                            |   | `SetWriteBuffer`            | `SetWriteBuffer`         |
| `WriteBuffers`                    | `write_buffers`                                    |   | `SetRateLimit`              | `SetRateLimit`           |
| `Close`                           | `close`                                            |   | `SetLogger`                 | `SetLogger`              |
| `LocalAddr`                       | `local_addr()`                                     |   | `Control`                   | `Control`                |
| `RemoteAddr`                      | `remote_addr()`                                    |   | `GetConv`                   | `conv()`                 |
| `SetDeadline`                     | `SetDeadline`                                      |   | `GetRTO`                    | `rto()`                  |
| `SetReadDeadline`                 | `SetReadDeadline`                                  |   | `GetSRTT`                   | `srtt()`                 |
| `SetWriteDeadline`                | `SetWriteDeadline`                                 |   | `GetSRTTVar`                | `srtt_var()`             |
| `SetWriteDelay`                   | `SetWriteDelay`                                    |   | `SetOOBHandler`             | `SetOobHandler`          |
| `SetWindowSize`                   | `SetWindowSize`                                    |   | `GetOOBMaxSize`             | `oob_max_size()`         |
| `SetMtu`                          | `SetMtu`                                           |   | `SendOOB`                   | `SendOob`                |
| `SetStreamMode`                   | `SetStreamMode`                                    |   | `Listener.Accept`           | `Listener::Accept`       |
| `SetACKNoDelay`                   | `SetAckNoDelay`                                    |   | `Listener.AcceptKCP`        | `AcceptKcp`              |
| `SetDUP`                          | `SetDup`                                           |   | `Listener.Addr`             | `addr()`                 |
| `SetNoDelay`                      | `SetNoDelay`                                       |   | `Listen`                    | `Listen`                 |
| `SetDSCP`                         | `SetDscp`                                          |   | `ListenWithOptions`         | `ListenWithOptions`      |
| `Dial`                            | `Dial`                                             |   | `DialWithOptions`           | `DialWithOptions`        |
| `NewConn`                         | `NewConn`                                          |   | `NewConn2`                  | `NewConn2`               |
| `NewConn3`                        | `NewConn3`                                         |   | `NewConn4`                  | `NewConn4`               |
| `NewNoneBlockCrypt`               | `NewNoneBlockCrypt`                                |   | `NewSimpleXORBlockCrypt`    | `NewSimpleXorBlockCrypt` |
| `NewTEABlockCrypt`                | `NewTeaBlockCrypt`                                 |   | `NewXTEABlockCrypt`         | `NewXteaBlockCrypt`      |
| `NewSalsa20BlockCrypt`            | `NewSalsa20BlockCrypt`                             |   | `NewAESBlockCrypt`          | `NewAesBlockCrypt`       |
| **`NewAESGCMCrypt`**              | `NewAesGcmCrypt`                                   |   | **`NewAEADCrypt`**          | `NewAeadCrypt`           |
| `KCP.Input`                       | `Kcp::Input`                                       |   | `KCP.Send`                  | `Send`                   |
| `KCP.Recv`                        | `Recv`                                             |   | `KCP.Flush`                 | `Flush`                  |
| `KCP.Update`                      | `Update`                                           |   | `KCP.Check`                 | `Check`                  |
| `KCP.NoDelay`                     | `NoDelay`                                          |   | `KCP.WndSize`               | `WndSize`                |
| `KCP.WaitSnd`                     | `wait_snd()`（存取器）                                  |   | `KCP.PeekSize`              | `PeekSize`               |
| `IKCP_*` 宏                        | `k`+CamelCase，去 `Icp` 前缀（`IKCP_RTO_DEF`→`kRtoDef`） |   | `_itimediff`                | `itimediff`              |
| `SystemTimedSched`                | `TimedSched`（`Shutdown()`）                         |   | `DefaultSnmp.BytesSent`     | `snmp::bytes_sent`（原子）   |
| `fecEncoder/fecDecoder/shardHeap` | `FecEncoder/FecDecoder/ShardHeap`                  |   | `UDPSession.recvbuf/bufptr` | `recv_buf_`/`buf_ptr_`   |
| `BlockCrypt.Encrypt/Decrypt`      | `Encrypt`/`Decrypt`                                |   | `BlockCrypt.Seal/Open`      | `Seal`/`Open`            |
| `fillRand`                        | `FillRand`                                         |   | `postProcess`               | `PostProcess`            |

**常量命名规则（#78，取代原 #53 的"二分规则"）**：一律 `k` + CamelCase，**不保留 `IKCP_` 的 `Icp` 前缀**——`namespace kcp` 已限定作用域，再加一层库名前缀属匈牙利记法（Google: Constant Names 只要求 `k` + 混合大小写）：

- kcp.go 的 `IKCP_*` 宏：`IKCP_MTU_DEF`→`kMtuDef`、`IKCP_OVERHEAD`→`kOverhead`、`IKCP_RTO_DEF`→`kRtoDef`
- sess.go / crypt.go / fec.go 的常量：`mtuLimit`→`kMtuLimit`、`devBacklog`→`kDevBacklog`、`initialVector`→`kInitialVector`

**API 全集核对（#58/#59/#74，源码 grep 实测，防止编造/漏项）**：

| 类别                | 实测数量   | 清单                                                                                                                                                                                                                                                                                                                         |
| ----------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UDPSession` 导出方法 | **29** | Read Write WriteBuffers Close LocalAddr RemoteAddr SetDeadline SetReadDeadline SetWriteDeadline SetWriteDelay SetWindowSize SetMtu SetStreamMode SetACKNoDelay SetDUP SetNoDelay SetDSCP SetReadBuffer SetWriteBuffer SetRateLimit SetLogger Control GetConv GetRTO GetSRTT GetSRTTVar SetOOBHandler GetOOBMaxSize SendOOB |
| `Listener` 导出方法   | **11** | Accept AcceptKCP Close Addr SetDeadline **SetReadDeadline SetWriteDeadline** SetReadBuffer SetWriteBuffer SetDSCP **Control**                                                                                                                                                                                              |
| 包级函数              | **8**  | Listen ListenWithOptions Dial DialWithOptions **NewConn NewConn2 NewConn3 NewConn4**                                                                                                                                                                                                                                       |
| Crypt 工厂          | **13** | **NewAEADCrypt NewAESGCMCrypt** NewSalsa20BlockCrypt NewAESBlockCrypt NewTEABlockCrypt NewXTEABlockCrypt NewSimpleXORBlockCrypt NewNoneBlockCrypt + 5 占位（NewTripleDESBlockCrypt NewBlowfishBlockCrypt NewCast5BlockCrypt NewTwofishBlockCrypt NewSM4BlockCrypt）                                                            |

**⚠️ 已修正的 v5 错误**：`DialWithOptionsConn` **不存在**（系编造），真实为 `NewConn/NewConn2/NewConn3/NewConn4`（sess.go:1511-1528）；`NewAESGCMBlockCrypt` 实名 `NewAESGCMCrypt`（crypt.go:113）；`NewAEADCrypt`（crypt.go:103，包装外部 `cipher.AEAD`）此前完全遗漏；Listener 少列 3 个方法。**根因：早期凭印象写 API 清单未 grep 核对。此后任何 API 条目必须附源码行号。**

**核心签名（#63，参数/返回类型钉死，避免实现时各写各的）**：

```cpp
// UdpSession
int  read(void* buf, size_t len, std::error_code* ec = nullptr);   // 返回消息字节数；可短读（§3.6）；<0 表示错误
int  write(const void* data, size_t len, std::error_code* ec = nullptr);
int  write_buffers(const std::vector<ConstBuffer>& bufs, std::error_code* ec = nullptr); // ConstBuffer = 指针+长度视图
void close();                                                       // 二次调用置 ec = kClosedPipe
bool SetMtu(int mtu);                                               // true = 成功（Go 是 ret == 0，见下）

// 包级（block 已含 key —— Go 的 DialWithOptions 没有 key 参数）
std::shared_ptr<UdpSession> DialWithOptions(
    const std::string& raddr, std::shared_ptr<BlockCrypt> block,
    int data_shards, int parity_shards, std::error_code* ec = nullptr);
std::unique_ptr<Listener> ListenWithOptions(
    const std::string& laddr, std::shared_ptr<BlockCrypt> block,
    int data_shards, int parity_shards, std::error_code* ec = nullptr);
// Listener 独占所有权（内含线程+socket，不可值返回）；session 内持 raw Listener*（对应 Go 的 s.l，非拥有，避免循环引用）
std::shared_ptr<UdpSession> Listener::Accept(std::error_code* ec = nullptr);
// NewConn/NewConn2/NewConn3/NewConn4 额外接受 conv 与现成 socket 句柄（对应 net.PacketConn）
```

**`SetMtu` 返回值语义（#54 衍生）**：Go 返回 `bool` 且实现为 `ret == 0`（kcp 的 SetMtu 返回 0 表示成功），**容易翻车**——C++ 保持"true = 成功"的直觉语义，实现写 `return kcp_->SetMtu(mtu) == 0;` 并在注释标注与 Go 的对应关系。

**⚠️ platform 层封装与残留遮蔽（#80，重写 v5.2 的"系统调用遮蔽"规则）**：函数改 CamelCase 后，`Read`/`Write`/`Close` 与 POSIX `read`/`write`/`close` 大小写不同、**不再构成遮蔽**，遮蔽面从 6 个缩到 3 个。但 **`read`/`write`/`close` 三个保留小写的成员仍与 POSIX 同名**，风险未完全消失，故 platform 层规则必须保留：

1. `platform/socket.h` 内封装统一 `sys_` 前缀并刻意模仿 POSIX 命名（`sys_socket`/`sys_bind`/`sys_sendto`/`sys_recvfrom`/`sys_close`/`sys_shutdown`/`last_error()`），便于一眼识别系统调用；属 Google "Exceptions to Naming Rules" 明示范围
2. `udp_session.cc`/`listener.cc` **只准调 platform 层**，不准直接调 `::recv`/`::sendto`——从架构上消灭遮蔽（同时完成 Winsock2/POSIX 差异收敛与错误码归一）
3. 内部类（`Kcp`/FEC）不碰 socket，无此问题
4. 实现 `read`/`write`/`close` 成员函数体时**禁止出现非限定的 `read(`/`write(`/`close(`**（会命中成员自身）；需要系统调用时一律走 `sys_*`

**行为差异（#47/#48，验收须逐条测）**：

- `SetReadBuffer` / `SetWriteBuffer`：仅 Dial 创建的 session 生效；Listener 接受的 session 返回 `kInvalidOperation`（sess.go:621-642）
- `SetDscp`：Windows 仅部分支持（记录支持矩阵到 README）；Linux `IP_TOS`/`IPV6_TCLASS`；入参 `dscp<<2` 后写入 TOS 字节（sess.go:604-611）
- `SetRateLimit`：自实现令牌桶，burst = `kMaxBatchSize*kMtuLimit`（替代 x/time/rate）

**OOB 前置条件（#26）**：`SetOobHandler` / `SendOob` 在 `fec_encoder_ == nullptr` 时必须返回错误 `kOobRequiresFec`；`oob_max_size()` 返回 0（sess.go:855,873,894）。P6 测试矩阵中 OOB 项只在 FEC(10,3) 配置下执行。

### 3.4 错误码契约（#23）

| 场景                        | Go 语义                     | C++ `ErrorCode`                                |
| ------------------------- | ------------------------- | ---------------------------------------------- |
| deadline 到期               | `errTimeout`              | `kTimeout`                                     |
| session 已关闭 / 二次 Close    | `io.ErrClosedPipe`        | `kClosedPipe`                                  |
| socket 收发错误               | 原始 error                  | `kSocketError`（附 errno/last_error）             |
| KCP conv 不匹配              | `Input` 返回 -1             | `kConvMismatch`                                |
| 输入过短                      | `Input` 返回 -2             | `kTooShort`                                    |
| FEC 恢复失败                  | 计入 `FECErrs`，丢包           | `kFecRecoverFailed`                            |
| AEAD 校验失败 / CRC 不符        | 计入 `InCsumErrors`，丢包      | `kIntegrityFailed`                             |
| 密文不支持                     | —                         | `kUnsupportedCipher`                           |
| OOB 无 FEC / 超长 / 队列满      | 报错 / 报错 / **静默丢弃返回 nil**  | `kOobRequiresFec` / `kOobTooLarge` / `kOk`(静默) |
| output 队列满（`PostProcess`） | **丢包 + recycle，靠 KCP 重传** | `kOk`(静默丢，#38)                                 |
| AEAD Seal 容量不足            | panic                     | `kBufferTooSmall`（crypt.go:83）**[偏离 D1]**      |

错误码实现：`enum class ErrorCode { kOk, kTimeout, kClosedPipe, ... }`（Google: Enumerator Names = `k`+CamelCase）+ 自定义 `error_category`，走 `std::error_code`；核心层返回 `ErrorCode`，不抛异常。**全文只用 `ErrorCode` 这一个名字**（v5.2 曾并列出现 `Errc` 与 `ErrorCode`，已统一）。

### 3.4.1 偏离登记表（#54，总原则 #36 的强制配套）

凡不照抄 Go 行为的点，必须登记在此并注明理由。实现时新增偏离必须先加表项。

| #   | 偏离点              | Go 行为                                                                            | C++ 行为                                                                       | 理由                                                                                                                                                    |
| --- | ---------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | AEAD `Seal` 容量不足 | `panic("please increase MTU size")`                                              | 返回 `kBufferTooSmall`                                                         | 库不 panic；调用方可恢复                                                                                                                                       |
| D2  | `SetMtu` 返回值语义   | `bool` 实为 `ret == 0`（0=成功，反直觉）                                                   | `true` = 成功                                                                  | 语义直觉化，实现等价                                                                                                                                            |
| D3  | TimedSched 并行度   | 1 prepend + N=max(NumCPU,2) worker 并发                                            | 单线程定时堆                                                                       | 实现复杂度；语义等价（§3.2）                                                                                                                                      |
| D4  | 批量收发             | Linux `recvmmsg/sendmmsg`                                                        | v1 不做，逐包 sendto/recvfrom                                                     | 双平台一致性；P8 补（R7）                                                                                                                                       |
| D5  | 外部错误类型           | `error` 接口 + pkg/errors 堆栈                                                       | `std::error_code`                                                            | 语言差异；不保留 Go 式堆栈                                                                                                                                       |
| D6  | 字节切片参数           | `[][]byte` / `[]byte`                                                            | `std::vector<ConstBuffer>` / `void*+len`                                     | 语言差异                                                                                                                                                  |
| D7  | session 生命周期     | GC + goroutine 自然退出                                                              | `shared_ptr` + join                                                          | 资源管理是总原则的明确例外（§3.1）                                                                                                                                   |
| D8  | 行宽               | —（Go 用 gofmt，无 80 列硬限）                                                           | **100 列**（Google C++ Style 要求 80）                                            | 密码学 T 表、hex 黄金向量、wire 布局注释在 80 列内不可读；`.clang-format: BasedOnStyle Google, ColumnLimit 100`                                                            |
| D9  | CFB 工作缓冲         | 实例持有 `encbuf`/`decbuf` + `encMu`/`decMu`（crypt.go:130-158），`Encrypt/Decrypt` 需加锁 | 反馈寄存器用**栈上局部数组**，`BlockCrypt` 无共享可变状态 → `Encrypt/Decrypt` 声明为 `const`，L1 锁取消 | 每连接一个 crypt 实例，缓冲本就无跨线程复用价值；省掉两把锁与一次内存写。并发安全由"无可变状态"保证，强于加锁                                                                                           |
| D10 | RS 编解码器的可见性      | 无对应公开 API（`klauspost/reedsolomon.New` 是依赖，`fecEncoder/fecDecoder` 未导出）           | `include/kcp/internal/rs.h`，**不建** `include/kcp/reedsolomon.h`               | 与 Go 的可见性一致：RS 是 FEC 层的实现细节；对外只暴露 `FEC` 配置与 `SetFEC`                                                                                                  |
| D11 | FEC 分片缓冲的所有权     | #42 设计：池化 buffer，恢复成功移交调用者、失败自回收                                                 | `FecPacket` = owning `std::vector`；恢复出的分片直接 move 给调用者，失败时随栈销毁                | 偏离的是「协议」而非行为：RAII 让移交/回收这组约定不存在，少一类泄漏与二次释放路径。池只用于 P6 的收发缓冲                                                                                            |
| D12 | KCP 段载荷的所有权      | `defaultBufferPool.Get()[:size]` + `recycleSegment` 手工归还（kcp.go:284-297）         | `Segment::data` = owning `std::vector`；段被丢弃时随析构释放                            | 与 D11 同源：KCP 有 4 条段丢弃路径（ACK 覆盖 / una 越过 / recv 弹出 / heap 弹出），逐条手工归还是泄漏与二次归还的温床。实测 1 MiB 传输里 762 段、每次 malloc 约 50ns，相对 1.4KB memcpy 可忽略（P7 实测若超基线再引入池） |
| D13 | 丢包中继的形态          | §6.2：UDP socket 一对 + 双线程转发，实时运行                                                  | 进程内 `Relay`（`std::deque` + 注入式 `Clock`）；丢包模型与 §6.2 一致（均匀 + Gilbert-Elliott）  | KCP 没有 I/O，只有 `output` 回调；socket 只增加实时抖动和端口/线程依赖。虚拟时钟让 30% 丢包场景可复现、毫秒级跑完。**P6 已补真 UDP 中继**（`tests/lossy_relay.{h,cc}`），两种形态并存：P5 的虚拟时钟中继验协议，P6 的 socket 中继验 socket 语义                                          |
| D14 | 读循环的唤醒方式        | 阻塞 `ReadFrom`，靠 `SetReadDeadline` / `Close` 打断（readloop.go:47-70）                   | `SysWaitReadable(fd_, 50)` 有界 `select` + `closed_` 原子标志；无唤醒管道                              | POSIX 上 `shutdown()` 不保证唤醒阻塞在 `recvfrom` 的线程，而在读者阻塞时关 fd 是 UB。有界等待把关闭延迟上界钉死为 50 ms，且不必为"打断读者"引入 signal/self-pipe 两套平台技巧                                                       |
| D15 | 批量读             | 一次唤醒处理一个数据报                                                                | 一次唤醒最多排空 `kMaxBatchSize`(64) 个数据报（每收一个用 `select(0)` 探测是否还有）                      | Windows 跨线程唤醒实测 96 µs/往返（`bench/udp_pingpong`），远大于单包处理成本。这是 D4（`recvmmsg`/`sendmmsg`）的用户态近似版，不改变线上字节                                                                                            |
| D16 | 队列关闭后的可排干语义     | `ch` + goroutine，退出即丢                                                            | `BlockingQueue::Close()` 后 `Pop` 仍返回已入队项，排空后才返回 false                                     | `close()` 要求"关闭前 flush 生效（尾部包不丢）"是 P6 门禁项；若 `Close()` 立即让 `Pop` 返回 false，尾包被吞，门禁不成立                                                                                                       |
| D17 | 发送缓冲的逻辑长/容量分离   | 切片 `buf[:size]`，扩容天然不越界                                                         | `SendRequest{std::vector buffer, std::size_t size}`，`resize()` 只缩不涨                                | AEAD tag 写在明文末尾之外；任何"扩容式 `resize()`"都会把 tag 值初始化成 0。P6 实际踩中（`frame_test` 抓到偏移 1412 全零），根因是逻辑长度与分配容量混用一个字段                                                                              |
| D18 | 判死可见性          | `state` 不可见，只能靠读超时间接观察                                                       | 新增 `UdpSession::IsDead()`                                                                         | dead_link 是 §4.8 的可判定门禁；P6 生命周期测试与 P7 诊断都需要直接断言而不是等超时                                                                                                              |
| D19 | 限速器的来源         | `golang.org/x/time/rate`（外部模块）                                                 | `internal/rate_limiter.h` 令牌桶，burst = `kMaxBatchSize * kMtuLimit`                                | 零第三方依赖（总原则 #36）。语义按 sess.go:648-658 对齐：非正速率 = `rate.Inf`，请求超 burst 时钳到 burst（Go 丢弃 `WaitN` 的 error，实际行为就是放行）                                                            |
| D20 | 线上字节的可观察性      | 无此能力（Go 侧靠包装 `net.PacketConn` 即可，库内不需要）                            | `UdpSession::SetPacketTrace` / `Listener::SetPacketTrace`，回调签名 `(outgoing, data, len)`             | §6.1 要求"两端各自 dump 首包十六进制"。Go 的 `ServeConn`/`NewConn` 接受 `net.PacketConn`，包装即可；C++ 的 listener 自己持有 fd、`Dial` 自己建 socket，没有等价缝隙。回调只在设置后生效（未设时一次原子读），文档明确要求线程安全                                                         |

### 3.5 全局对象与静态生命周期（#32/#33）

Go 的 `SystemTimedSched`、`DefaultSnmp`、`defaultBufferPool` 是包级变量，进程退出时**不析构**。C++ 照此设计：

1. 三者均为**函数内静态**（Meyers singleton），避免跨 TU 静态初始化顺序问题（C++11 起首次调用构造，线程安全）
2. `TimedSched` 提供 `Shutdown()`；**程序正常退出不调用它**（进程结束即止），仅在测试中显式调用以验证线程可回收
3. `Snmp` / `BufferPool` 不提供析构清理，`std::atexit` 不注册任何依赖上述单例的回调
4. 禁止在静态对象里持有 `std::thread` 且依赖析构顺序；定时器线程**故意 detach 或由 `Shutdown()` join**，二者择一并在 §6 测试中验证

### 3.6 read / write 运行时段语义（#37/#38/#39，P6 行为核心）

**read（消息边界语义，三条路径，照抄 sess.go:296-334）**：

1. `buf_ptr_` 有残留（上次 read 的 b 装不下一条消息的尾部）→ 直接 copy 返回，**允许短读**（n < len(b)）
2. `PeekSize() > 0` 且 `len(b) >= size` → `kcp_->Recv(b)` **DMA 直读用户 buffer**，返回 size
3. 否则 `kcp_->Recv(recv_buf_)` 中转 → copy 进 b，**剩余进 `buf_ptr_`**

- 即：**read 返回"一条 KCP 消息（或其残留）"的大小，不保证填满 b**。stream 模式下消息边界由 KCP 内部重组消解，但 buf_ptr_ 机制仍生效
- `recv_buf_` 容量只增不复核（`capacity < size` 才重分配，#49）；初始 1500（kMtuLimit）
- 文档必须写明：调用方按循环 read 使用；断言测试须覆盖"小 b 读大消息"的 buf_ptr_ 路径

**write_buffers（sess.go:366-425）**：

1. 每次循环先查 `socket_write_error_` / `die_`
2. `wait_snd() < snd_wnd_` 才发送；否则阻塞等 `write_event_`（带 deadline）
3. 逐 slice 按 `mss_` 切段 `kcp_->Send(b)`
4. 发完后：`wait_snd() >= snd_wnd_ || !write_delay_` → 立即 `Flush(kFlushFull)`；**`write_delay_` 默认 false → 默认立即 flush**（#39）；`SetWriteDelay(true)` 才等 `Update` tick 聚合
5. 成功后 `snmp::bytes_sent += n`

**KCP output 回调（sess.go:229-245，#38）**：

- `size >= kOverhead`（=24，见 §4.7）才投递
- `BufferPool::Get()` 取 `[:size+header_size_]`，数据 copy 到 `[header_size_:]` 预留头空间
- 投递 `post_processing_` 队列（容量 `kDevBacklog`=2048）**非阻塞**：满则 **drop + recycle**（KCP 重传兜底）；`die_` 已置位则直接退出
- C++ 的 `BlockingQueue` 必须实现"满则丢"而非阻塞（阻塞会持 L2 死锁）

### 3.7 SetMtu 契约（#40，撤回 v3 误判）

```
SetMtu(mtu): mtu = min(kMtuLimit, mtu) - header_size_ - (aead ? aead.Overhead() : 0)
构造路径同样调用 SetMtu(kMtuDef)（sess.go:248）
```

- AEAD 的 `header_size_` 只含 `kNonceSize`(12)，但 `SetMtu` 额外减 `Overhead()`(16) → 最终 UDP 包 ≤ 用户 mtu，**不会 IP 分片**。v3 所述 quirk 不成立，已撤回
- 默认 `kMtuDef=1400`；六种配置的内部 mtu/mss 见 §4.2 表

### 3.8 加密双接口（#44）

```
BlockCrypt (CFB 系): virtual void Encrypt(dst, src) / Decrypt(dst, src)   // 支持 in-place
AeadCrypt  (GCM)   : virtual void Seal(dst, nonce, plaintext) / Open(...)
                     // Go 的 Encrypt/Decrypt 在 AEAD 上是 panic，C++ 里不提供（编译期隔离）
```

- session 持 `std::variant`/抽象基类 + `is_aead()` 分派；写路径按 §4.1 分流
- `Seal` 前检查 `dst.capacity() - dst.size() >= plaintext.size() + Overhead()`，不足返回 `kBufferTooSmall`（Go panic，crypt.go:83）
- AAD 恒为空（sess.go:718,726，#46）
- 每包 nonce：`FillRand` 生成，CFB 16B / GCM 12B（sess.go:717,729）

---

## 4. 线上格式

### 4.1 处理顺序

```
发送：KCP 输出 → 预留 headerSize → ①FEC 编码 → ②加密 → ③发送
接收：网络 → 解密 → CRC 校验 → FEC 解码 → KCP
```

### 4.2 六种配置的 wire 布局

**`S` = KCP 段 = 24B 段头 + payload**。段头 24 字节**已包含 conv**：`conv(4)+cmd(1)+frg(1)+wnd(2)+ts(4)+sn(4)+una(4)+len(4)`（kcp.go:58 注释原文，`IKCP_OVERHEAD = 24`）。**mss = mtu − 24**（kcp.go:198），因此**不得再额外计一次 conv**——早期版本写"conv4 + 24B 段头"是错的，会让段总长算成 28B 头、`len` 字段与 `kcp.json` 全错。  
**`F` = FEC 头 8B**（seqid4 + type2 + size2，即 fecHeaderSizePlus2）。

| 配置           | headerSize | wire                                         |
| ------------ | ---------- | -------------------------------------------- |
| None + 无 FEC | 0          | `S`                                          |
| None + FEC   | 8          | `F ‖ S`                                      |
| CFB + 无 FEC  | 20         | `CFB_enc( nonce16 ‖ crc32_4 ‖ S )`（**整包加密**） |
| CFB + FEC    | 28         | `CFB_enc( nonce16 ‖ crc32_4 ‖ F ‖ S )`       |
| GCM + 无 FEC  | 12         | `nonce12 ‖ AES-GCM(S) ‖ tag16`               |
| GCM + FEC    | 20         | `nonce12 ‖ AES-GCM(F ‖ S) ‖ tag16`           |

- CFB：`nonce` 是 16B 随机填充，**无语义但被加密**；`crc32` 覆盖 `F ‖ S`（不含 nonce/crc 自身）；初始反馈 = `E_K(kInitialVector)`
- GCM：`headerSize = 12` 不含 16B tag，但 `SetMtu` 减 `Overhead()` 兜底（§3.7）

**六种配置的内部 mtu / mss**（用户 mtu=1400 为例，照 §3.7 公式）：

| 配置         | KCP 内部 mtu        | mss  |
| ---------- | ----------------- | ---- |
| None 无 FEC | 1400              | 1376 |
| None + FEC | 1392              | 1368 |
| CFB 无 FEC  | 1380              | 1356 |
| CFB + FEC  | 1372              | 1348 |
| GCM 无 FEC  | 1400−12−16 = 1372 | 1348 |
| GCM + FEC  | 1400−20−16 = 1364 | 1340 |

### 4.3 CFB 变体精确语义（#43，crypt.json 向量的依据）

以 `encrypt16` 为例（`encrypt8` 同构，块大小 8）：

```
tbl = E_K(kInitialVector)                     // 初始反馈，crypt.go:50 常量
n = len(src) >> 4; repeat = n >> 3; left = n & 7
for each 128B group:                          // 8x 展开仅性能，无语义
    for each 16B block:
        dst[block] = src[block] XOR tbl
        tbl = E_K(dst[block])                 // 反馈寄存器取密文（标准 CFB）
for each remaining full 16B block (left 个):  // 同上，逐块
    ...
tail = src[base:]                             // 不足一块的残字节
dst[tail] = src[tail] XOR tbl                 // 纯 XOR：不进 tbl、不再加密
```

- **残字节规则**：`len(src) % blockSize != 0` 时尾部残字节只 XOR。Go 用宽切片 `dst[base:]` 表达（crypt.go:466-501），**C++ 必须按"块推进 + 尾部 XOR"实现，禁止照抄宽切片字面**
- `len(src)==0` 直接返回；支持 in-place（`dst==src`，crypt.go:304）
- decrypt 对称：`dst = src XOR tbl; tbl = E_K(src)`（反馈取**密文**即输入）
- `crypt.json` 向量**必须含非块对齐长度**（如 8B 块的 13B、16B 块的 33B），否则残字节路径无覆盖

### 4.4 接收侧 FEC 分流（按 `LE16(data[4:6])`）

**⚠️ 该表作用于"解密后的明文"**（§4.1：解密 → CRC → 分流）。CFB 配置下密文里的 `data[4:6]` 是随机字节，对着密文找 `0xf1` 永远找不到——分流必须在解密成功后。

| 值        | 含义             | conv 位置          | payload 位置  | 处理                               |
| -------- | -------------- | ---------------- | ----------- | -------------------------------- |
| `0x00f1` | FEC data shard | `LE32(data[8:])` | `data[12:]` | FEC 解码 → 去 FEC 头 → `kcp_->input` |
| `0x00f2` | parity shard   | —                | —           | 仅进解码器，不投上层                       |
| `0x00f3` | OOB            | `LE32(data[8:])` | `data[12:]` | 绕过 KCP，投 OOB handler             |
| 其他       | 裸 KCP 段        | `LE32(data[0:])` | —           | `kcp_->input`                    |

不冲突前提：KCP `cmd∈[81,84]` + `frg∈[0,255]` → `LE16` 落在 0x0051..0x0354，与 0x00f1..0x00f3 不重叠。

**OOB 帧完整规格（sess.go:872-935,1094-1101）**：

- 布局：`FEC头8 ‖ conv4 ‖ payload`，接收端取 `data[kFecHeaderSizePlus2 + 4:]`（sess.go:1100）
- **复用 FEC 头做解复用，但不进 FEC 编码/解码**（sess.go:889 "Reuse the FEC header layout for demultiplexing, but are NOT protected by FEC"）——无冗余保护、无重传、无 ACK
- `oob_max_size() = kcp_->mtu() − 4`（sess.go:878，注意是减 `convSize` 而非整个 FEC 头；FEC 头空间已在 `SetMtu` 扣过）
- 超长判定 `convSize + len(data) > kcp_->mtu` → `kOobTooLarge`（sess.go:904）
- 队列满 → **静默丢弃返回成功**（sess.go:926-930）；session 关闭 → `kClosedPipe`
- handler 在**输入路径同步调用**，文档要求 MUST 快速返回

### 4.5 最小长度检查（照抄，注意是 min）

- session 侧：`len < min(24, 8+4)=12` → 丢弃（sess.go:1009）
- Listener 侧：12B 门槛；FEC data 帧另需 `len ≥ 8+24=32`（sess.go:1213）；裸帧需 `len ≥ 24`（sess.go:1229）
- output 回调：`size >= IKCP_OVERHEAD` 才投递（#38，值见 §4.7）

### 4.6 KCP 默认参数（#24，kcp.json 逐字节比对的前提）

| 参数                                       | 默认值               | 出处                |
| ---------------------------------------- | ----------------- | ----------------- |
| `snd_wnd` / `rcv_wnd` / `rmt_wnd`        | 32 / 32 / 32      | kcp.go:49,263-265 |
| `mtu` / `mss`                            | 1400 / mtu-24     | kcp.go:50,266-267 |
| `rx_rto` / `rx_minrto` / `rx_maxrto`     | 200 / 100 / 60000 | kcp.go:34-37      |
| `interval` / `ts_flush`                  | 100 / 100         | kcp.go:52,271-272 |
| `ssthresh`（init/min）                     | 2 / 2             | kcp.go:53,273     |
| `dead_link`                              | 20                | kcp.go:54,274     |
| `fast_ack`                               | 3                 | kcp.go:51         |
| `probe_init` / `probe_limit`             | 500 / 120000      | kcp.go:55-56      |
| `snd_buf` / `rcv_queue` / `snd_queue` 容量 | wnd×2             | kcp.go:276-278    |
| 段内 `sn` 偏移                               | 12                | kcp.go:64         |

**`rcv_wnd` 会写进段头的 `wnd` 字段** → C++ 默认值必须一致，否则 `kcp.json` 逐字节比对必挂。（表中为协议字段名；对应 C++ 成员为 `snd_wnd_`/`rcv_wnd_`/`rx_rto_` 等，加尾下划线。）

### 4.7 常量与边角（#45/#46/#52）

| Go 名称                                       | 值                                                             | C++ 常量（`k`+CamelCase）                          | 用途                                                          |
| ------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------- |
| `initialVector`                             | `{167,115,79,156,18,172,27,1,164,21,242,193,252,120,230,107}` | `kInitialVector`                               | CFB 初始反馈（crypt.go:50）                                       |
| `saltxor`                                   | `"sH3CIVoF#rWLtJo6"`                                          | `kSaltXor`                                     | simpleXOR 的 PBKDF2 salt（crypt.go:51）                        |
| `nonceSize` / `crcSize` / `cryptHeaderSize` | 16 / 4 / 20                                                   | `kNonceSize` / `kCrcSize` / `kCryptHeaderSize` | sess.go:68,71,74（`cryptHeaderSize = nonceSize + crcSize`）   |
| `convSize`                                  | 4                                                             | `kConvSize`                                    | sess.go:80；`oob_max_size() = mtu − 4`（§4.4）                 |
| `mtuLimit`                                  | 1500                                                          | `kMtuLimit`                                    | sess.go:77；bufferpool 切分粒度、`SetMtu` 上限                      |
| `devBacklog`                                | 2048                                                          | `kDevBacklog`                                  | sess.go:86；post_processing_ 队列容量（#38 满则丢）                   |
| `maxBatchSize`                              | 64                                                            | `kMaxBatchSize`                                | sess.go:94；令牌桶 burst 基数（P6 性能基线用）                           |
| `fecHeaderSize` / `fecHeaderSizePlus2`      | 6 / 8                                                         | `kFecHeaderSize` / `kFecHeaderSizePlus2`       | fec.go:51-52；FEC 头 6B + 2B 对齐（§4.4 分流靠这 2B）                 |
| `typeData` / `typeParity` / `typeOOB`       | 0xf1 / 0xf2 / 0xf3                                            | `kTypeData` / `kTypeParity` / `kTypeOob`       | fec.go:53-55；FEC 分流                                         |
| `maxShardSets`                              | 3                                                             | `kMaxShardSets`                                | fec.go:58；`DiscardShards` 判据（fec.go:340）                    |
| `maxFECEncodeLatency`                       | 500(ms)                                                       | `kMaxFecEncodeLatency`                         | sess.go:91；`encode()` 的连续性入参（sess.go:698），§5 fec.json 确定性依据 |
| `IKCP_MTU_DEF`                              | 1400                                                          | `kMtuDef`                                      | 构造路径 `SetMtu` 入参（kcp.go:53）                                 |
| `IKCP_OVERHEAD`                             | **24**                                                        | `kOverhead`                                    | 段头字节数（**含 conv**，kcp.go:58）；output 最小段检查；mss = mtu − 24     |

### 4.8 dead_link 判死（#25）

`flush` 中 `segment.xmit >= kcp.dead_link` → `kcp.state = 0xFFFFFFFF`（kcp.go:942-944）。高丢包测试（30%）必须注意：单段重传 20 次即判死，测试时长与丢包率的组合不得触发误判导致的"假失败"。

---

## 5. 黄金向量

生成器 `tools/golden/main.go`（`replace github.com/xtaci/kcp-go/v5 => D:/work/kcp-go`），输出含 `meta{go_version, kcp_go_commit, generated_at, schema}`。

| 向量           | 内容                                                                            | 比对方式                                                                                            |
| ------------ | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `crypt.json` | 7 算法 × 固定 key/输入缓冲的密文，**含非块对齐长度**（#43）                                        | 逐字节                                                                                             |
| `rs.json`    | (3,1)(10,3)(20,10)(128,128) 的 parity + 擦除恢复 + 矩阵前 4 行；**每组含一组变长分片**（#41 补齐契约） | 逐字节                                                                                             |
| `fec.json`   | 编码帧、**变长 shard set**（第二轮，缓存里残留上一轮的更长包）、丢 N 片恢复、OOB 帧                          | 逐字节；生成器**断言 parity 帧数 == parityShards**，否则重试（确定性依据是常量 `maxFECEncodeLatency=500`，sess.go:91,698） |
| `kcp.json`   | Send+flush 输出段（消息模式 & 流模式）                                                    | **ts 字段（段内偏移 8..11）掩码置零后逐字节**；另断言 ts 与本机时钟差 <5s；params 按 §4.6 固定                                |
| `frame.json` | 给定 KCP 段 → 加密后字节（6 种配置）                                                       | 逐字节；CFB/GCM 用**固定 nonce**（session 管线里 nonce 随机，故向量只锁"给定 nonce 下的密文"，组装由 C++ 侧自建 buffer 复算）      |

### 5.6 JSON schema（#27，防止实现者猜）

所有文件：`{"meta":{...},"vectors":[...]}`（`kcp.json`/`frame.json` 的元素字段见下）。

```jsonc
// crypt.json
{"vectors":[{"algo":"aes128cfb|aes192cfb|aes256cfb|tea|xtea|salsa20|simplexor|none|aesgcm",
             "block_size":8|16,"key_hex":"..","plain_hex":"..","cipher_hex":"..",
             // 仅 aesgcm：
             "nonce_hex":"..","tag_hex":".."}]}

// rs.json
{"vectors":[{"data_shards":10,"parity_shards":3,"shard_size":1024,
             "data_hex":[".."],"parity_hex":[".."],"erased":[0,3],
             "recovered_hex":[".."],"matrix_head":[[..],[..],[..],[..]],
             // 变长场景（#41）：
             "var_len":true,"max_len":1024,"shard_lens":[1024,700,...]}]}

// fec.json
// kind=encode-varlen 是同一个 encoder 的第二轮，各 shard 载荷长度不同：只有这条能暴露
// "补齐到 maxlen 前没清零"的缺陷（首轮缓存全零，不清零也能过）。
{"vectors":[{"kind":"encode|encode-varlen|decode|oob",
             "data_shards":10,"parity_shards":3,"header_offset":0,"encode_latency_ms":500,
             "packets_hex":[".."],"parity_hex":[".."],"expect_parity_count":3,
             "dropped":[0,5],"recovered_hex":[".."],"packet_hex":".."}]}

// kcp.json
{"vectors":[{"stream":false,
             "params":{"conv":1,"mtu":1400,"snd_wnd":32,"rcv_wnd":32,
                       "nodelay":1,"interval":10,"resend":2,"nc":1,"wait_snd":0},
             "segments":[{"cmd":81,"frg":0,"sn":1,"una":0,"len":1200,
                          "bytes_hex":"..","ts_masked":true}]}]}

// frame.json
{"vectors":[{"crypt":"none|cfb|aesgcm","fec":false,
             "data_shards":0,"parity_shards":0,"header_size":0,
             "nonce_hex":"..",           // cfb 16B / aesgcm 12B
             "kcp_seg_hex":"..",
             "crc32_le":"0x12345678",    // 仅 cfb
             "encrypted_blob_hex":".."}]}
```

C++ 侧：`tests/json_reader.{h,cc}`（<120 行扁平解析器，只支持上述结构），schema 变更必须同时更新生成器与解析器。

---

## 6. 阶段与门禁

### P0 脚手架 + 互通工具 + 向量基建（2d）

`git init`；CMake + Presets（**win/linux 双 preset**，决策⑤）；`build.bat/build.sh`；**`.clang-format`（`BasedOnStyle: Google, ColumnLimit: 100`，D8）**；目录骨架（`.h`/`.cc` + `internal/`）；LICENSE（每个移植文件保留 xtaci MIT 头 + 自实现密码学标注参考规范来源）；`tools/golden` 生成 5 个向量；**`tools/interop/goecho_{server,client}.go` 可编译运行**（#28/#34）；`json_reader` 可解析回写的向量；**核对 §4.7 全部常量（`kOverhead=24` 已填，其余逐条对源码确认）**。  
**门**：

- [x] `build.bat` 通过，`ctest` 跑通 ≥1 个真实断言测试 → 2 个（`smoke_socket_test`、`vector_meta_test`），Debug + Release 均全绿
- [x] 生成器产出 5 个 json（含合法 meta），`vector_meta_test` 对 5 个文件的 schema / 长度不变量全部通过
- [x] Go echo server 可启动、client 可回环连通（802 行内 1 MiB @ aes + FEC 10/3，65 MB/s）
- [x] `git log` 有首个提交（`1150c03`）
- [x] §4.7 常量表逐条对源码复核（含 `kOverhead=24` 含 conv、`convSize=4` 补齐、fec 常量行号）
- [x] **命名合规**：`clang-format --dry-run --Werror` 全绿（6 文件）、`check_guard.py` 通过、无 `#pragma once`
- [ ] **双平台**：Linux 侧 `build.sh` 冒烟 **未验证**——本机 WSL 被安全策略禁用、无独立 g++；`build.sh` 与 linux preset 已就位，待有 Linux 环境时补跑（记为 E1）

#### P0 实施记录（v5.5，与计划的偏差）

| 项             | 计划                                           | 实际                                                                          | 原因                                                                           |
| ------------- | -------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| 向量生成器入口       | `tools/golden/main.go` 直接调用参考实现              | `gen.go`（驱动）+ `ref/golden_ref.go.txt`（`go test -overlay` 注入 kcp-go 包内执行）    | `fecEncoder`/`fecDecoder`/`initialVector` 均未导出；overlay 是唯一既访问私有符号又不改动参考仓库的方式 |
| 向量来源          | §5 表格                                        | 5 个文件全部由参考实现产出，逐个自检（crypt 往返、RS 擦除恢复、FEC parity 计数与类型、KCP 段长度一致性、frame 六配置） | —                                                                            |
| interop 布局    | `tools/interop/goecho_{server,client}.go` 平铺 | `goserver/`、`goclient/`、`kcpcrypt/`（共享工厂）                                   | 同目录两个 `main` 会让 `go build ./...` 失败；目录分离是 Go 惯例                              |
| `matrix_head` | 取 RS 内部矩阵前 4 行                               | 通过编码单位向量 `e_c` 反解（公开 API）                                                   | `genMatrix` 未导出；由线性性保证与内部矩阵逐位相同                                              |
| 构建环境          | —                                            | `build.bat` 增加 Windows SDK 回退（vcvars 依赖 `reg.exe`，受限 shell 下会失败）            | 沙箱与部分 CI 环境屏蔽 reg.exe，否则报 `LNK1104: kernel32.lib`                            |
| 门禁脚本          | `check_guard.py`（5 行）                        | `check_guard.py` + `check_format.py` 并入 `build.bat`                         | 计划要求两条门禁，统一由构建脚本执行                                                           |

### P1 基础原语（1d）—— ✅ 已完成

crc32/sha1/pbkdf2/`FillRand`/snmp/bufferpool（全局单例按 §3.5；pool 按 `kMtuLimit`=1500 定长切分，#49；`FillRand` 双后端 BCryptGenRandom/getrandom）。  
**门**：CRC32("123456789")=0xCBF43926；SHA-1/PBKDF2 标准向量；与 `crypt.json` CRC 字段一致；两平台熵源均产出非全零缓冲。

- [x] CRC-32 IEEE 用例 + `frame.json` 的 CRC 字段对拍；FIPS 180-1 SHA-1、RFC 2202 HMAC、RFC 6070 PBKDF2（`primitives_test`）
- [x] `FillRand` 长度遵守（canary）、非全零、256 次取值互异（`entropy_test`）
- [x] bufferpool 定长/拒收异容量/取回互异，snmp 计数与表头顺序（`foundation_test`）
- [ ] Linux `getrandom(2)` 分支未实测（E1 环境阻塞同前）

### P2 加密层（2.5d）—— ✅ 已完成

AES（**AES-NI intrinsics + cpuid 检测 + T 表回退**，决策⑥）→ GCM(GHASH) → Salsa20 → TEA/XTEA → CFB 变体（**§4.3 残字节规则**）→ 双接口工厂（§3.8）。  
**注意**：Salsa20 语义须为 `XORKeyStream(dst+8, src+8, nonce=src[0:8], key)`，即**前 8 字节明文透传**，其余以首 8 字节作 64 位 nonce 做 Salsa20 流加密（crypt.go:175-181）。  
**门**：

- [x] FIPS-197 附录 C.1/C.2/C.3（128/192/256）逐字节 —— `tests/aes_test.cc`，T 表与 AES-NI 两条路径各自跑一遍
- [x] NIST GCM SP 800-38D test case 2（全零）+ test case 3 输入（60B 明文、无 AAD）—— `tests/gcm_test.cc`；后者期望值由 Go `crypto/aes`+`cipher.NewGCM` 产出
- [x] Salsa20 ECRYPT set 6（8B nonce）keystream —— `tests/salsa20_test.cc`
- [x] **`crypt.json` 全算法逐字节**：9 算法 × {64B, 37B} = 18 条，`tests/crypt_test.cc` 逐字节 + 往返 + in-place；非对齐 37B 覆盖 §4.3 残字节规则
- [x] **AES-NI 与 T 表交叉互验**：512 个随机块 × 3 种 key 长度逐字节相同（`aes_test`），且 AES-CFB 的 wire 密文由两条路径各自复现（`crypt_test`）
- [x] AEAD 容量不足返回 `kBufferTooSmall` 而非 panic（D1）；tag 被篡改/长度 < tag 返回 `kIntegrityFailed`
- [x] `check_guard` 14 headers / `check_format` 37 files / `ctest` 9/9 全绿

#### P2 实施记录（v5.6，两条**会静默产出错密文**的坑，均已定位）

| # | 坑              | 症状                                      | 正解                                                                                                                                                                                                                              | 取证                                                                                         |
| - | -------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| 1 | **GHASH 位序约定** | AES-GCM 密文全对、**只有 tag 错**（说明 CTR 对、乘法错） | GCM 的块内位序是 **首字节的 MSB = 系数 x^0**（即"1"的块表示为 `0x80 00 …`）。乘 x 时整串**右移**、进位从 byte15 的 LSB 溢出，归约常量加在 **byte 0** 且掩码为 **`0xE1`**（x^128=x^7+x^2+x+1 → 位下标 7,2,1,0 → 掩码 0x01|0x20|0x40|0x80）。按"MSB=x^127 + 0x87 入 byte15"写会得到完全不同的 tag | 用 Go `crypto/aes`+`cipher.NewGCM` 反解 `S = tag ⊕ E(J0)`，再以 big.Int 多项式乘法（正/反两种位序）比对，反序版唯一命中 |
| 2 | **XTEA 表推进节奏** | XTEA 密文全错，其余算法全对                        | `xtea/cipher.go:85-93` 每对轮**只 `sum += delta` 一次**：偶数项用当前 sum 构造并推进，奇数项复用推进后的 sum 且键下标取 `(sum>>11)&3`；循环每轮末尾**不再推进**。多推一次会让 `table[2]` 之后全部错位                                                                                    | 与 `crypt.json` 的 `xtea` 向量逐字节对拍                                                            |

附带确认（此前未钉死的参数）：`NewTEABlockCrypt` 走 `tea.NewCipherWithRounds(key, 16)` —— **TEA 是 16 轮，不是 x/crypto 默认的 64 轮**（crypt.go:246）；Salsa20 的计数器**每次调用从 0 重启**（`salsa20.XORKeyStream` 每次重建 16B 输入块），因此 kcp-go 每包依赖随机 nonce 头去重，跨包不复用 keystream。

### P3 Reed-Solomon（2d）—— ✅ 已完成

GF(2⁸) 表 → 系统性 Vandermonde（Vandermonde → 顶部子阵求逆 → 左乘）→ Encode/ReconstructData。  
**接口契约（#41）**：`ReconstructData(shards)` **要求调用方传入等长分片**（缺失分片传空 buffer 占位）；补齐到 maxlen + 尾部清零由 **FEC 层（P4）**&#x8D1F;责，不在 RS 内。  
**门**：

- [x] 前 `data` 行 = 单位阵：(1,1)/(2,1)/(3,1)/(10,3)/(20,10)/(64,32)/(128,128) 七组逐一校验（`rs_test`）
- [x] **`rs.json` parity 逐字节**：5 组（(3,1,128B)、(10,3,1KB)、(20,10,512B)、(128,128,64B)、(10,3,变长)），含 `matrix_head` 逐项对拍
- [x] 1000 轮随机擦除恢复：等长 500 轮（`data ⊆ {3,10,20,33}` × `parity ⊆ {1,3,10}`，丢失 `1..parity` 片，`Reconstruct`/`ReconstructData` 各半）+ 变长 500 轮（先把 `1..maxlen` 的数据补零到 maxlen 再编解码）
- [x] 契约负例：丢失 `parity+1` 片返回 `kFecRecoverFailed` 且**不分配**任何分片；片数/长度不齐返回 `kInvalidArgument`；`New` 拒绝 `d<1`/`p<0`/`d+p>256`
- [x] `check_guard` 16 headers / `check_format` 42 files / `ctest` 10/10 全绿（Debug + Release）

#### P3 实施记录（v5.7）

| 项    | 计划                          | 实际                                                                                      | 原因                                                                                                                           |
| ---- | --------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 乘法实现 | 未指定                         | 64 KiB 稠密 `mul[a][b]` 表（`MulTable()` 返回整表引用，数据路径每 shard 取一次指针），setup 路径走 `GaloisMul` 包装 | 与 `galois.go:851` 的 mulTable 同构；log/exp 每次乘要两次查表 + 条件减，在 128 片配置下差别可观                                                        |
| 矩阵求逆 | "顶部子阵求逆"                    | Gauss-Jordan on `[M \| I]`，内层用 `mul[factor][pivot[c]]` 单引用，128×128 约 4.2M 次查表           | 计划未限定算法；选带行主元交换的实现以覆盖奇异判定                                                                                                    |
| 矩阵类型 | 未指定                         | `.cc` 内匿名命名空间的 `Matrix`（稠密、行主序），不对外暴露                                                   | 对外只需要 `MatrixAt(row,col)` 与三个编解码入口；暴露矩阵类会诱导调用方绕过 MDS 约束                                                                      |
| 分片容器 | `shards`                    | `internal::ShardSet = std::vector<std::vector<std::uint8_t>>`，**空 vector = 缺失**         | 与 Go 的 `nil` 语义同构，且不需要额外的 present 位图                                                                                         |
| 公开头  | `include/kcp/reedsolomon.h` | **不建**，改为 `include/kcp/internal/rs.h`（目录树已同步）                                           | kcp-go 自身不导出 RS 编解码器（那是 `klauspost/reedsolomon` 的 `New`，属实现依赖）；`fecEncoder`/`fecDecoder` 同样未导出，公开的只有 `FEC` 配置结构与 `SetFEC` 路径 |

### P4 FEC 层（1.5d）—— ✅ 已完成

fecEncoder/fecDecoder/shardHeap；autotune 仅挂点。  
**补齐落地（#41/#42）**：decode 中把已收 shard `[:maxlen]` + 尾部清零；仅 `k < dataShards` 的缺失位分配空 buffer；恢复成功 → recovered 缓冲所有权移交调用者，失败 → 自回收（§3.4 计 FECErrs）。  
**约束**：`shouldTune` 缺省恒 false，包正常入 shardHeap，**严禁实现为 return nil 丢包**（Go 那个分支是真丢包）。  
**门**：

- [x] **`fec.json` 全项逐字节**：`encode`（10 数据帧 + 3 parity，含 FEC 头与 2B 长度字段）、`encode-varlen`（同一 encoder 第二轮，各 shard 长度 206→89 不等）、`decode`（丢 shard 0/4 后恢复 2 片）、`oob`（74B 帧，seqid 0xffffffff + typeOob）
- [x] 移植 fec_test：**全部可恢复丢失组合**（13 包丢 1~3 片的 286 种组合全跑，逐片比对被丢包的 payload）+ OOB + 重复包/超 paws/短包三条负例
- [x] **FEC 关闭 = 解码器为 nullptr**：`FecDecoder::New(0,0)`、`New(0,3)`、`New(10,-1)`、`New(200,100)` 均返回 nullptr；`128+128` 可建
- [x] **snmp 断言**：丢 2 片场景 → `fec_recovered=2`、`fec_parity_shards=3`、`fec_full_shard_set=0`、`fec_errs=0`、`fec_shard_set=1`（gauge）、`fec_shard_min=0`；无丢包场景 → `fec_full_shard_set=1` 且 `fec_recovered=0`
- [x] **连续性窗口**：`rto=0` 时 10 个数据包不产出 parity，但 seqid 仍推进到 13（下一个数据包落在 parity 槽位，接收端靠这个空档判丢）；`rto=500` 时正常产出
- [x] **陈旧 shard set 回收**：喂 6 个 set 各 1 包后只剩 4 个（set 0/1 被 `maxShardSets=3` 规则丢弃）
- [x] `check_guard` 18 headers / `check_format` 46 files / `ctest` 11/11 全绿（Debug + Release）

#### P4 实施记录（v5.8）

| 项                | 计划                | 实际                                                                                           | 原因                                                                                                                                         |
| ---------------- | ----------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| autotune         | “仅挂点”             | **完全不实现**：无 `shouldTune` 分支、无 sampler                                                        | Go 那段在检测到类型不匹配时 `return nil`（fec.go:279-320），是真丢包；P4 只保证“包一定进 shardHeap”。参数变更场景要连同 sampler 一起在 P8 做，届时才验证得了重调后的恢复链                         |
| 长度字段语义           | —                 | `size = len(buf) − payloadOffset`，**含自身 2 字节**（fec.go:406）                                   | 注释写的是 `PAYLOAD(SIZE-2)`，容易误读成“不含自身”；按“不含自身”写会让每包少 2B，FEC 头之后的整条偏移链全错                                                                       |
| 解码器缓冲            | 池 + 所有权移交         | `FecPacket` = `std::vector<std::uint8_t>`，恢复出的分片**本身即 owning vector**，直接 move 给调用者；失败时随栈对象销毁 | 偏离 **D11**：RAII 让“成功移交 / 失败自回收”这组协议不存在，少一类泄漏路径；池只留给 P6 的收发缓冲                                                                               |
| RS 调用            | —                 | 编码侧把 `[payloadOffset, maxSize)` 拷进成员 `ShardSet`（复用，不反复分配）；解码侧把每片 `pkt[6:]` 拷进 `shards_`      | 见 R20：RS 是 owning `ShardSet` 接口，视图化要等 P6/P7 实测（Go 用 alias 省掉这一跳）。当前每包多一跳 ~1.4KB memcpy                                                     |
| 时间基准             | —                 | `steady_clock` 毫秒，而非 `time.Now().UnixMilli()`                                                | 唯一用途是两次数据包的间隔比较；墙钟跳变会把“突发”误判为“非连续”（少发 parity）或反之                                                                                           |
| **黄金向量缺口（本轮补上）** | `fec.json` 只有等长场景 | 新增 `encode-varlen`：同一 encoder 的**第二轮**，10 个 shard 载荷 200/187/…/83 字节                         | 等长向量里 `maxSize − len == 0`，**尾部补零规则一次都没被走到**：变异测试（删掉 memset）不是断言失败而是直接越界崩溃，说明该路径无数据对拍。补向量后同一变异由 `varlen parity packet 0/1/2 mismatch` 精确捕获 |

### P5 KCP 核心（3.5d）—— ✅ 已完成

kcp.go 逐函数移植（含 §4.6 全部默认值、§4.8 dead_link）。  
**时限（#69）**：30% 丢包场景单次传输**上限 120s**；超时即判失败并记录重传计数，**不得无限等待**。若 `dead_link` 被触发（state=0xFFFFFFFF），属测试参数不当而非实现缺陷。  
**门**：

- [x] **`kcp.json` 逐字节**：消息模式（frg 2/1/0，载荷 1376/1376/248）与流模式（3 段全 frg=0）两组；ts（偏移 8..11）掩码后比对，且**掩码前先断言这 4 字节 == 注入的时钟值**（4321），堵住"忘了写 ts 也能过"的口子
- [x] 移植 kcp_test：`TestSegmentHeap`（含 32 位绕回序 0xFFFFFFFE < 0xFFFFFFFF < 0 < 1）、`TestSetMtuBoundary`（−1 / 0 / 23 / 24 / 25 / 1400，并验证 mss=1 时每段恰好 25 字节）
- [x] **§6.2 丢包中继** 0% / 10% / 30%：1 MiB 载荷逐字节一致，虚拟耗时 **4.7s / 9.1s / 17.6s**，重传 **0 / 88 / 572**，全程未触发 dead_link（30% 场景离 120s 预算有一个数量级余量）
- [x] **MTU 边界**：payload = 1 / mss−1 / mss / mss+1 / 2·mss / mtu−1 / mtu / mtu+1 共八档；段数 = ⌈len/mss⌉，对端 `PeekSize` 返回整条消息长度、`Recv` 内容逐字节相等
- [x] **流模式合并**：两次 Send（100B + 50B）合并为一个 150B 段，字节顺序不变
- [x] **接收侧语义**：后到分片不可读（`PeekSize` = −1）→ 前片到达后可读；缓冲差 1 字节返回 −2 **且不消费**；读空返回 −1
- [x] **Input 错误码**：短包 −1、conv 不匹配 −1、长度字段越界 −2、未知命令 −3
- [x] **重复包**：同一段投递两次只累加 `repeat_segs`，不重复入队，且 ACK 照常重发
- [x] **拥塞控制开启**（nc=0）：1 MiB @ 10% 丢包 **56.3s** 完成，覆盖慢启动 + AIMD + RTO 回退路径
- [x] **dead_link**：100% 丢包下 20 次重传后 `IsDead()` 为真且传输不完成
- [x] `check_guard` 22 headers / `check_format` 54 files / `ctest` 13/13 全绿（Debug + Release）

#### P5 实施记录（v5.9）

| 项              | 计划                                             | 实际                                                               | 原因                                                                                                                                                         |
| -------------- | ---------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 段载荷            | 沿用 bufferpool（`newSegment` / `recycleSegment`） | `std::vector<std::uint8_t>` 独占                                   | 偏离 **D12**：池化的真实代价是"每条丢弃路径都要记得归还"（acked / una 越过 / recv 弹出 / heap 弹出），RAII 把这组生命周期约定整组消掉；每段约 1 次 malloc，相对一次 memcpy 可忽略                                    |
| 丢包中继形态         | §6.2 的 UDP socket 一对 + 双线程                     | 进程内 `Relay` + 注入式虚拟时钟（`Clock`）                                   | 偏离 **D13**：KCP 是纯状态机，`output` 回调就是传输边界，套 socket 只会引入实时抖动。虚拟时钟让"30% 丢包 × 1 MiB"从"可能 20s+"变成 17.6s 虚拟时间 / 实跑 60ms，且完全可复现。**真 UDP 中继留到 P6**（那时才有 session 需要验） |
| `flush` 返回值    | `uint32` nextUpdate                            | `void`                                                           | Go 的三处调用（`Input` / `Update` / close）全部忽略返回值；留一个没人读的返回值只会诱导误用                                                                                               |
| `ParseData` 签名 | `parse_data(segment)` 传值                       | `ParseData(header, payload, len)`，载荷只在非重复时拷贝                     | Go 的 `segment.data` 是输入缓冲的切片，传值只拷切片头、随后才深拷贝；C++ 里若先拷进 Segment 再判重，重复包要多付一次 memcpy                                                                          |
| 日志             | 编译期开关（`debug` build tag）                       | 运行期掩码 + 惰性 lambda 组串                                             | Go 默认构建里 `debugLog` 是空函数；这里保留"默认零成本"（一个分支）但不必重编库就能开 trace                                                                                                  |
| `state` 可见性    | —                                              | 新增 `IsDead()`                                                    | Go 的 `state` 全仓只写不读；dead_link 门禁要断言、P6 判活也要用                                                                                                               |
| **flush 首帧空转** | —                                              | 照抄：`cwnd` 初值 0 → 首次 flush 一段都不发，Phase 6 把 cwnd 抬到 1，下一 tick 才发首段 | KCP 原始实现就是这个行为（`ikcp_flush` 末尾 `if (cwnd < 1) cwnd = 1`）。移植时"顺手修好"会让首帧与 Go 不一致；`TestCwndBootstrap` 钉住，其余用例显式 `NoDelay(..., nc=1)` 绕开                       |
| 段缓冲扩容          | —                                              | `SetMtu` 缩小后仍可能发出旧的大段：`ensure_capacity` 按需扩 buffer               | Go 在同样场景下会 `ptr = ptr[len(data):]` 越界 panic（缓冲按新 mtu 分配）；C++ 不能 UB，选择扩容把旧段完整发出去而不是截断                                                                       |

### P6 会话层（5d）—— ✅ 已完成

socket RAII（**platform/socket 双实现**，决策⑤）→ ringbuffer/`BlockingQueue`(**满则丢**，#38)/`TimedSched`（单线程 + §3.5 生命周期）→ `UdpSession` 管线（**§3.6 read/write 语义、§3.7 SetMtu、§3.8 双接口**）→ `Listener` → OOB/keepalive/deadline/限速/DSCP。  
**门**：

- [x] **`frame.json` 6 种配置逐字节**（组装层唯一硬证据）
- [x] 回环：10 并发 × 1MB，**FEC(0,0)**、FEC(10,3)+GCM、FEC(10,3)+Salsa20 三组（#70：裸路径并发行为同样要验）
- [x] **生命周期（#20/#21）**：阻塞 read 中 close 能返回；二次 close 返回 `kClosedPipe`；close 前 flush 生效（尾部包不丢）；进程退出不 terminate；线程/句柄数回落
- [x] **read 语义（#37）**：小 b 读大消息触发 buf_ptr_ 路径；DMA 路径；短读语义；消息边界不跨 read 合并（消息模式）
- [x] **FEC 分流四路**：裸段/data/parity/OOB 正确路由；OOB 仅在 FEC 开启下测试（#26）
- [x] **错误码行为**：超时/关闭/socket 错误/CRC 失败/output 队列满（静默丢 + KCP 重传兜底）五类与 Go 一致
- [x] **行为差异（#47/#48）**：`SetReadBuffer` 对 listener session 报 invalid；`SetDscp` 支持矩阵记录（Windows 部分 / Linux 全）
- [x] **性能基线（§6.3）**：与 `goecho` 的 Go↔Go 基线对比，差距写入 `README.md`（R7）+ `bench.md`；AES-NI 路径与 T 表路径的吞吐差也记录
- [ ] **双平台**：上述回环与生命周期测试在 Windows + Linux 各跑一遍全绿 —— **Windows 全绿（Release + Debug，16/16）；Linux 待环境（E1）**

#### P6 实施记录（v5.10）

| 项                  | 计划                                        | 实际                                                                                  | 原因                                                                                                                                       |
| ------------------ | ----------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 读循环唤醒方式            | Go 式阻塞 `ReadFrom` + deadline             | `SysWaitReadable(fd_, 50)` 有界 `select` + `closed_` 原子标志                              | 偏离 **D14**：POSIX 上 `shutdown()` 不保证唤醒阻塞在 `recvfrom` 的线程，读者阻塞时关 fd 是 UB；有界等待把关闭延迟上界定死为 50 ms                                           |
| 一次唤醒收多少            | 1 个数据报                                    | 最多 `kMaxBatchSize`(64) 个                                                             | 偏离 **D15**：Windows 跨线程唤醒实测 96 µs/往返（`bench/udp_pingpong`），远大于单包处理成本。D4 的 `recvmmsg` 用户态近似版，不改线上字节                                         |
| 关闭路径的队列语义          | `Close()` 后 `Pop` 立即返回 false             | 先排干再返回 false                                                                        | 偏离 **D16**：否则 `close()` 的尾部 flush 会被 `PostProcess` 吞掉，门禁"close 前 flush 生效"不成立                                                              |
| 发送缓冲               | 切片 `buf[:size]`                            | `SendRequest{vector, size}`，`resize()` 只缩不涨                                          | 偏离 **D17**：AEAD tag 写在明文末尾之外，扩容式 `resize()` 会把它值初始化成 0（`frame_test` 抓到偏移 1412 全零）                                                          |
| 限速器                | `golang.org/x/time/rate`                  | `internal/rate_limiter.h` 令牌桶                                                       | 偏离 **D19**：零第三方依赖；burst = `kMaxBatchSize * kMtuLimit`，超 burst 钳到 burst（Go 丢弃 `WaitN` 的 error，实际就是放行）                                        |
| 判死可见性              | `state` 只写不读                              | `UdpSession::IsDead()`                                                              | 偏离 **D18**：P6 生命周期与 P7 诊断要直接断言，而不是等读超时                                                                                                    |
| 丢包中继               | §6.2 真 UDP 一对 + 双线程                      | **两套并存**：`tests/relay_test.cc`（真 socket）+ P5 的进程内 `Relay`（虚拟时钟）                    | P5 的虚拟时钟验协议（30% 丢包 × 1 MiB 从 20s+ 变成 60ms 且可复现），P6 的 socket 中继验 socket 语义；二者互不替代                                                        |
| 中继干净链路断言           | `retrans == 0`                            | `retrans <= 64`（1 MiB 762 段的 5%）                                                     | 中继自身每个数据报一次唤醒就是瓶颈，socket 缓冲会溢出造成额外丢包。把两侧 socket 缓冲提到 4 MB、测试窗口收到 64/64 后实测 `retrans=6`；`== 0` 是不可判定断言                            |
| 并发压测形态            | —                                         | **必须是一个 listener + N 会话**                                                            | 一个客户端对一个独立服务端进程的形态**复现不出**任何并发缺陷（实测 160 次全绿），因为竞争全在共享资源（listener 的 socket 与 monitor 线程）上；这条写进 `tools/bench/run_bench.py` 的并发格 |

#### P6 缺陷记录（两处都是"照抄 Go 没能照抄到底"）

| # | 表现 | 根因 | 判定证据 | 修复 |
| - | --- | --- | --- | --- |
| 1 | 单 listener + 10 并发 + FEC(10,3) 时，9/10 客户端在 ~950 KB 处停滞：`in_pkts` 卡住、`retrans` 涨到 1500+、`srtt` 还是 19 µs、`kcp_in_errors`/`csum_errors`/`in_errs` 全 0；服务端只有 1 行 STATS 后再无输出 | `Listener::Monitor` 对 `recvfrom` 错误 `NotifyReadError` + `return`。Windows 把对端关闭引发的 ICMP 端口不可达报成下一次 `recvfrom` 的 `WSAECONNRESET`(10054) → monitor 线程永久退出 → 该 listener 上**所有**会话同时失去入站通路。kcp-go 的 `monitor()` 只在 `err == nil` 时处理，否则 `InErrs++` 后继续 | 临时打印确认错误码 10054；改为不可忽略后，同样场景 120 次并发客户端全绿（此前 15/40 失败）；变异回退后 `TestListenerSurvivesPeerDisappearing` 立刻 `FAIL … socket error` | `platform::IsIgnorableRecvError` + monitor/readLoop 计数后继续读 |
| 2 | `session_test` 约 1/10 概率 `STATUS_HEAP_CORRUPTION`（0xc0000374），且失败那次耗时比正常多约 1 s（走了超时早退路径） | `Listener::close()` 只关 fd、不清 `sessions_`。会话的 `shared_ptr` 就活在 map 里，于是 `~Listener` 先析构成员 `sessions_`，再析构剩余会话，会话析构 `close()` → `listener_->CloseSession()` → 擦除**已释放**的 map。kcp-go 的 `Listener.Close` 会先 `Close()` 每个子会话（listener.go:1158-1176） | 12/12 复跑全绿（此前约 1/10 崩）；变异回退"关闭子会话"后 `TestListenerCloseClosesSessions` 两行断言同时 `FAIL` | `Listener::close()` 快照 → 清 map → 逐个 `close()`（在 fd 关闭之前，且不持 L3 锁，避免 L2→L3 递归自锁） |

**教训（写进风险表 R22）**：Go 的读循环与 `Close` 都是"永不因错误返回 / 递归关闭子节点"的形态。移植时任何一处加了 `return`，在 Go 里被 GC 和 goroutine 掩盖的后果（线程永久退出、析构顺序反转）都会变成"整机停摆"或"堆损坏"。判定这类问题的唯一办法是**共享资源的并发形态压测**（一个 listener + N 会话），单连形态永远测不出来。

### P7 验收（1.5~2d）—— ✅ 已完成

`run_matrix.py` 跑 2 方向 × {None, AES-CFB, AES-GCM, Salsa20} × {FEC(0,0), FEC(10,3)} = 16 格，逐格记录握手/1MB 双向校验和/关闭干净度。

**实际判定方式（比计划更强）**：每格 1 MiB echo，三条断言同时成立才算过——

1. **校验和**：客户端回读的 SHA-256 必须等于 `918f58c0…`，而这个值由 `run_matrix.py` 用 Python 独立按载荷规则（`payload[i] = i*7+11`）算出来，不是抄实现里的常量。两端实现同时错到"彼此一致"是抓不到的，这样能抓到。
2. **双向流量**：echo 一次即覆盖两个方向。
3. **首包逐字节（`--dump-dir`）**：发送侧 `-dump-packet` 抓的首个数据报，与接收侧抓到的首个数据报必须**完全相同**；不同则报首个差异偏移。16 格 × 3 轮 = 48 次全部一致。这把"线上字节一致"从"校验和一致"升级成了逐字节证据。

**结果**：`matrix.md`，16/16 格 × 3 轮全绿。

**矩阵覆盖度说明（#67）**：这 4 种加密覆盖了三条实现分支——`None`（无加密）、`AES-CFB`（**16B 块** CFB）、`AES-GCM`（AEAD）、`Salsa20`（流密码）；**但 8B 块 CFB 分支（TEA/XTEA）不在矩阵内**，其组装级字节正确性仅由 `crypt.json`（组件级）+ `frame.json`（组装级、C++ 自算）保证，无跨语言端到端验证。这是**已知且接受的覆盖缺口**（理由：8B 块与 16B 块共用同一 CFB 实现，差异仅在块长参数；且 TEA/XTEA 非主流选型）。若后续要补，加 2 格变 20 格。

**止损线**：单格定位 >2d 则降级为"FEC 关闭先互通"，FEC 互通转 P8 并记录未决原因。—— 未触发。

#### P7 实施记录（v5.10）

| 项                  | 计划                                                    | 实际                                                                                          | 原因                                                                                                                                                          |
| ------------------ | ----------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 首次运行                  | —                                                     | **16/16 一次通过**                                                                               | P6 的两处并发缺陷修完后没有新的线上问题；这也侧面说明 §5 的五个黄金向量把字节层钉得够紧                                                                                                          |
| 抓包接口                  | `--dump-packet` 参数，两端同格式                              | C++ 侧加了 `UdpSession::SetPacketTrace` + `Listener::SetPacketTrace`（偏离 **D20**）；Go 侧不动库，用 `net.PacketConn` 包装（`kcptap.Conn`） | Go 的 `ServeConn`/`NewConn` 本来就接受 `net.PacketConn`，天然可插桩；C++ 的 `Listener` 自己持 fd、`Dial` 自己建 socket，没有等价缝隙                                                                       |
| 抓包位置                  | "首包十六进制"                                              | listener 在**解密前**抓（`OpenInPlace` 是原地解密，晚一步原始字节就没了）；客户端在 `ReadLoop`/`Tx` 抓                      | 抓密文才是 §6.1 需要的（按偏移查 §4 布局表）；同时发现一处易误读：**`crypt=none` 仍是 20 字节头**（`NoneBlockCrypt` 只是 Encrypt 空转，nonce+CRC32 照写），真正 0 字节头只在"根本不装 crypt 对象"时（`kcp::Listen`/`Dial`），与 Go 的 `Dial` 一致 |
| 关闭干净度                | 逐格记录                                                  | 断言客户端 exit 0 + `ok=1` + 字节数；服务端在客户端完成后被 terminate                                                      | "服务端收到 FIN"在 UDP 上不存在；能判定的只有客户端侧完整性与服务端不中途报错                                                                                                              |

### 6.1 互通失败定位流程（#29）

1. 两端各自 dump 首包十六进制（`--dump-packet <file>` 参数，C++/Go 同格式）
2. `dump_packet.py` 做逐字节 diff，首个差异偏移 + 上下文 ±32B
3. 按偏移查 §4 布局表定位字段 → 对应源码行号 → 检查该字段的实现
4. 若 diff 落在密文区 → 优先查 CFB 残字节规则（§4.3）/ GCM nonce 与 tag；若落在 FEC 头 → 查 seqid/type/size 与 RS 补齐；若落在 KCP 段 → 查 §4.6 默认值

### 6.2 丢包中继规格（#49，P5 门禁的可判定前提）

- **形态**：测试内独立线程（不占外部进程），`tests/lossy_relay.{h,cc}`；UDP socket 一对（client_relay / relay_server），双线程转发
- **丢包模型**：默认均匀随机 `p ∈ {0, 0.1, 0.3}`；额外提供 **Gilbert-Elliott 突发模型**（good/bad 两态，p_g=0.01/p_b=0.5，平均突发长 10）测 KCP 抗突发——两模型结果分别记录
- **延迟注入**：可选固定延迟 ±10ms 抖动（模拟 RTT）；中继**不得重排、不得损坏字节**（只整包丢弃）
- **判定**：1MB 载荷 SHA-256 比对 + **snmp 重传计数合理性**（丢包率↑ → `retrans_segs` ↑，30% 下不得触发 dead_link 假失败，§4.8）
- **对照**：同一中继参数跑 Go↔Go 基线（P6 复用），C++↔C++ 与其对比

**P6 落地情况**：两种形态**并存**，各管一件事——`tests/relay_test.cc` 用真 socket 双线程验证 socket 语义（四场景：clean 0% / 均匀 10% ×1 MiB / 均匀 30% ×256 KiB / Gilbert-Elliott ×256 KiB），P5 的进程内 `Relay` + 虚拟时钟继续验证协议本身。有两处实测校准值必须记着，否则断言不可判定：

1. **干净链路的 `retrans` 不是 0 才是 bug**。中继自己每个数据报一次唤醒就是瓶颈，socket 缓冲会溢出造成额外丢包。把中继两侧收发缓冲提到 4 MB、被测会话窗口收到 64/64 之后，实测 `dropped=0 retrans=6`；断言因此定为 `retrans <= 64`（1 MiB 的 762 段 × 5%）。
2. **echo 线程要靠读 deadline 解阻**。KCP 没有 FIN，`server->read()` 的阻塞读不会因为对端 `close()` 返回，`echo.join()` 会永久挂起（实测 16 项全挂 300+ s）。`stop_echo()` 用 `SetReadDeadline(now)` 解阻再 join，这条对所有"读到对端消失"的用例都适用。

### 6.3 性能基线测量方法（#50/#68，P6 门禁的可判定前提）

- **指标**：吞吐（MB/s，1MB×N 累计）、平均 RTT（KCP `srtt()`）、CPU（进程 user+sys 时间 / 墙钟）、常驻内存
- **场景**：单流 1MB×100（主指标）；10 并发流 × 1MB（次要）；**FEC(0,0)**、FEC(10,3)+GCM、FEC(10,3)+Salsa20 三组
- **参数一致性（#68，否则基线不可比）**：Go 基线必须使用与 C++ **完全相同的参数**——`conv=1, mtu=1400, nodelay=1, interval=10, resend=2, nc=1`，snd/rcv wnd 32/32，加密与 FEC 组合相同。`goecho_server`/`client` 通过命令行参数显式传入，**不得依赖 kcp-go 默认值**（默认值与 §4.6 不同会导致误判）
- **统计**：每场景跑 5 轮，去首轮预热，报**中位数 + min/max**；写 `bench.md` 落 README
- **机器状态控制（v5.13 新增，来自 P8.0 的实测教训）**：同一工作负载在**同一次会话内**多次干净全量基线，run 间可差 45%（实测 109.5 / 111.7 / 160.5 MB/s，而 run 内 min/max 仅 ±1%）。**跨会话引用基线数字、或用单次测量支撑优化排序，一律无效**；每次要下性能结论，必须当场重跑多轮，并在记录里带上当次的 `bench/syscall_cost` 校准行（`sendto`/`recvfrom`/探测价）作为该次机器状态的指纹。旧基线（§6.3.1）未遵守本条，其数值只在那时的机器状态下成立
- **对照与阈值**：同机 Go↔Go 为基线；C++↔C++ 与之对比。**判定线：吞吐低于基线 30% 或 CPU 高于基线 50% 即视为需要解释**——属经验阈值而非硬标准；超出即必须归因，且**顺序固定：先给每个系统调用定价（`bench/syscall_cost`），再查拷贝次数，最后才怀疑协议/加密**。v5.12 实测证明这条顺序的价值：P6 当时把差距归给"无批量收发（R7）"，主因其实是 `sendto` 这个 API 的单位成本（§6.3.1），而"无批量收发"只解释读侧那 1.75 µs/包
- **双平台**：Windows 与 Linux 各测一遍（`sendto` 路径与调度器差异会影响结果），分别记录

#### 6.3.1 P6 实测结果与归因（Windows x64，本机回环）

> **v5.13 状态标注**：本节数值测于 2026-10-18 22:20~23:29 的"机器忙"窗口（同窗口 relay_test 出现 111 次重传风暴），**当前不可复现**：同机同代码重测为 109~160 MB/s（P8.0，§6.3.2）。保留原文供追溯，但**任何排序决策必须以 §6.3.2 的当前状态表为准**。Go 侧数字跨状态稳定（119.5 → 119 MB/s），C++ 侧塌了 10 倍——线程多的实现（本移植客户端 4 线程）在机器忙时先塌，这是两侧比值从 9.7 倍变成 1.1 倍的原因。

驱动：`python tools/bench/run_bench.py --rounds 5`（每格独立端口 + READY 门禁，5 轮去首轮取中位数，明细见 `bench.md`）。

| 配置 / 场景                    | C++      | Go       | 比值   |
| -------------------------- | -------- | -------- | ---- |
| none fec=0/0，单流          | 12.2 MB/s | 119.5 MB/s | 0.10 |
| none fec=0/0，10 并发        | 10.9     | 52.4     | 0.21 |
| aes-gcm fec=10/3，单流       | 8.4      | 112.1    | 0.07 |
| aes-gcm fec=10/3，10 并发    | 8.5      | 48.6     | 0.17 |
| salsa20 fec=10/3，单流       | 9.0      | 86.3     | 0.10 |
| salsa20 fec=10/3，10 并发    | 8.7      | 47.3     | 0.18 |

归因（每一项都是独立测出来的，不是推断）：

| 观测                                       | 数值                     | 结论                                                                            |
| ---------------------------------------- | ---------------------- | ----------------------------------------------------------------------------- |
| KCP 纯状态机（`bench/kcp_pump`，mss 1376）     | 0.8~2.2 GB/s（随 CPU 频率浮动） | 协议引擎不是瓶颈（比会话层高两个数量级）                                                       |
| AES-CFB 两条后端（`bench/aes_bench`）          | 1262 / 331 MB/s（3.81x） | 加密不是瓶颈                                                                        |
| 跨线程 UDP 往返（`bench/udp_pingpong`，20k 次）   | **86 µs**              | 一次 OS 唤醒 ≈43 µs；成批排空的意义在这                                                    |
| 单流吞吐，窗口 32 / 128 / 512                  | **13.1 / 13.5 / 12.2 MB/s** | **不是窗口×RTT**。窗口放大 16 倍吞吐不动 ⇒ 限制在"每数据报成本"，不在在途字节数                                 |
| 单流吞吐折算（窗口 32）                           | **8.9k 数据报/秒/方向 ≈ 112 µs/包** | 客户端每发一个数据报要付 `sendto` + `recvfrom` + 就绪探测。**v5.12 勘误**：旧写的"4.07 万包/秒 ≈ 24.6 µs"与 12.2 MB/s ÷ 1376 自相矛盾，是算错的 |
| Go 侧同参数单流                                | 119.5 MB/s ≈ **11.5 µs/包**（同上勘误） | 差 9.7 倍，比旧的 4.5 倍更大                                                                        |
| 单个数据报的发送（`bench/syscall_cost`）              | `sendto` **41~46 µs**；`WSASendTo`（null OVERLAPPED）**2.6 µs**；已 connect 的 `send()` **2.5 µs** | **这才是真正的瓶颈**。同一台机器、同一个数据报、同一个目标地址，只换 API 就差 **15~17 倍**。三组对照排除了两个现成解释：不是"异步 vs 同步"（null OVERLAPPED 是同步语义，一样 2.6 µs），不是"地址参数查找"（`WSASendTo` 带地址照样 2.6 µs）。CPU 与墙钟分离后可见：`sendto` 的 44 µs 里只有 21 µs 是 CPU，其余是线程未运行 ⇒ 调用内部在等 |
| 读路径（同一工具）                              | `recvfrom` **1.0 µs**、就绪探测 `select(0)` **0.75 µs**、非阻塞空读 **0.28 µs** | 读路径比发送路径低两个数量级。**P8 的第一个杠杆在发送侧，不在接收侧** |
| 旁证：同机 Go 的未连接 `WriteTo`（`tools/interop/syscallprobe`） | **2.9 µs** | 同一台机器、同样是未连接 socket、同样带地址 ⇒ 与语言运行时无关，是 `sendto` 这个 API 在 Windows 上的行为。Python 的 `sendto` 同为 45 µs，三方一致 |
| CPU（客户端，占单核百分比 / 每字节 CPU 时间）           | C++ 79% · Go 270%       | 绝对 CPU 时间 C++ 更多：100 MiB 用 6.5 s 对 Go 2.2 s。同源同因——每数据报两次系统调用加一次调度，Go 的完成端口把这一层摊掉了 |
| 单向（`-discard`）                           | **2.48 MB/s**          | **不是回归**：接收侧没有数据可捎带 ACK，只能走 `interval`=10 ms 的 flush tick，再被 Windows 定时器粒度放大到 ≈17 ms。KCP 协议本身的性质，Go 侧同样如此（其工具未提供该开关，故未做交叉对照） |
| AES-GCM 加速（`bench/aes_bench`）              | **168 MB/s**（T 表 123 MB/s） | GHASH 目前是 4-bit 查表（`internal/gcm.cc:81-113`），没有走 PCLMULQDQ，所以 AES-NI 只体现 1.37 倍而非 CFB 的 3.81 倍。**不是 P6 门禁项**（P2 门禁只要求 `crypt.json` 逐字节），已列入 P8：单流 8.4 MB/s 离 168 MB/s 很远，当前不影响，但一旦 D4/IOCP 把每包成本压下去，GCM 会先成为瓶颈 |

> **勘误（v5.10）**：v5.9 及更早的讨论里曾用"会话层 12 MB/s ≈ 8.6k 包/秒 = 平台往返上限的 83%"来归因。**这个算法是错的**：它把成批流水的段按"每段一次往返"折算，而实际是每批 24 段共享一次往返。窗口扫描实验（吞吐随窗口放大不变）直接证伪了"窗口×RTT 受限"，正确的归因是每数据报的固定 I/O 成本。


### P8 性能收敛（P8.0 已完成于 v5.13；P8.1 触发条件失效，P8.2~P8.6 触发条件均未满足）

**为什么必须独立成阶段**：P6 的门禁只要求"差距写入 README 并归因"，P7 只要求互通全绿。结果是归因做到了"每数据报固定成本"，但**没有分解到可执行项**——而 v5.12 把这句话变成了具体数字：客户端的每一个数据报都要付一次 `sendto`，而 `sendto` 在那时的本机是 **41~46 µs**，占 112 µs/包的近一半，且这个成本**换一个 API 就消失 15~17 倍**（§6.3.1）。P8 的任务就是把剩下的成本逐段压掉，每一步都可判定。

> **v5.13 勘误（P8.0 实测）**：上面这段立论的前提（112 µs/包、`sendto` 41~46 µs、15~17 倍 API 差）**是当时机器状态的测量，当前不复现**（同机同代码 109~160 MB/s、`sendto` 3.4 µs、API 差 1.3 倍；判定实验见 §134）。P8.0 的分解表（§6.3.2）显示当前状态已超额达成 25 MB/s 目标线，且没有任何一项的触发条件成立。**P8 保留为框架，但在触发条件重新成立之前不实施任何一项**——这正是"每项带触发条件"这条规则的设计目的。

**P8 的目标线（不是"追平 Go"）**：

- 单流 `none fec=0/0` ≥ **25 MB/s**（当前 12.2，即 2 倍），10 并发同比例改善
- 每数据报 CPU 时间 ≤ 当前的 **60%**
- 16 格互通矩阵与 `relay_test` 必须逐项保持全绿；任何一项退化即回滚该项
- **不承诺**追平 Go 的 119 MB/s：那是 IOCP + goroutine 调度 + 无 per-session 线程的形态差异，追平意味着重写 I/O 模型（P8.3 才讨论），不在本阶段承诺范围内

#### P8.0 仪器化：先把 112 µs/包 拆开（唯一的前置项）

没有这一步，后面每一项都只能靠猜，而 P6 已经证明"猜"在这类问题上会错得离谱（R22）。

- **内容**：给 `UdpSession` 加按线程的时间账——`read` 线程、`post` 线程（FEC + 加密 + `Tx`）、调用者线程（`write` → `Kcp::Send`）各自的 CPU 与墙钟；以及 `SysSendTo`/`SysRecvFrom`/`SysWaitReadable` 的**调用次数与累计耗时**。Windows 用 `GetThreadTimes`，POSIX 用 `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`。
- **输出**：`echo_client -profile` 在 `RESULT` 行后追加一行 `PROFILE read_cpu_us=… post_cpu_us=… caller_cpu_us=… tx_n=… tx_us=… rx_n=… rx_us=… probe_n=… probe_us=…`
- **门禁（账必须自洽）**：三段 CPU 之和与进程总 CPU 相差 ≤ 10%；`tx_us`/`rx_us` 与各自调用次数相符（±5%，与 `bench/syscall_cost` 的单次价对照）。**账不自洽就先修账，不许往下走。**
- **产出**：一张"112 µs/包分解表"写进本文档 §6.3.2，作为 P8.1~P8.6 的排序依据。**这张表出来之前，P8.1 之后任何一项都不许动手。**

#### P8.1 发送路径：`sendto` → `WSASendTo`（Windows）

- **依据**：§6.3.1 的四行实测。同一数据报、同一目标地址：`sendto` 41~46 µs，`WSASendTo`（含 null OVERLAPPED 的同步语义）2.6 µs，已 `connect` 的 `send()` 2.5 µs；Go 的未连接 `WriteTo` 2.9 µs，Python 的 `sendto` 45 µs。**API 决定成本，不是语义、不是地址、不是语言。**
- **内容**：`platform::SysSendTo` 在 Windows 上改走 `WSASendTo`（`lpOverlapped = nullptr`，保持"返回即代表数据报已交给内核"的同步契约，从而**不需要**改动 `Tx` 的缓冲区生命周期）。POSIX 侧不动（那边 `sendmmsg` 是另一个杠杆，见 P8.4）。
- **门禁**：
  1. `frame.json` 六种配置逐字节不变（组装层没动，但这是唯一能挡住"顺手改了缓冲区"的检查）
  2. 16 格互通矩阵 × 3 轮全绿（含每格首包逐字节对拍）
  3. `relay_test` 四场景全绿（丢包/重传语义不受影响）
  4. `build.bat Release` + `Debug` 全部 16 项通过
  5. `bench/syscall_cost` 与 `run_bench.py` 的前后对照：**吞吐与每包 CPU 至少一项显著改善**；若两者都不动，记录"当前不是瓶颈"并保留改动（它是 P8.3 的前置），不许硬凑结论
- **风险**：低。`WSASendTo` 与 `sendto` 共用同一条 `AsSockAddr` 路径与同样的长度/族校验；POSIX 侧零改动。

#### P8.2 读路径：去掉每包的 `select(0)` 探测

- **依据**：每包付 `probe_ready` 0.75 µs + `recv_ok` 1.0 µs；改成"先非阻塞 `recvfrom`，遇 `EWOULDBLOCK` 再回到阻塞等待"后是 0.28 µs + 1.0 µs。
- **量级**：只值 ~0.5 µs/包，**比 P8.1 小两个数量级**。写在这里是为了明确"读路径不是瓶颈"，而不是为了现在做。**触发条件**：P8.0 的表显示读路径占比 > 10%，否则不做。
- **门禁**：同 P8.1 的 1~5。

#### P8.3 IOCP / 事件驱动（仅在 P8.0 的数据支持下启动）

- **前置**：P8.1 落地后，P8.0 的表显示"I/O 等待仍占单包成本 > 30%"。若 `sendto` 换成 `WSASendTo` 之后单包成本已降到 20 µs 以下，IOCP 的收益上限只是"省掉每包一次线程唤醒"，而读侧已经在批量排空（D16）——**这种情形下不做**。
- **范围**：只替换 socket I/O 的驱动方式（完成端口 + 每会话不再独占 3 个线程），**不改协议、不改线上字节**。
- **门禁**：P8.1 的 1~5，外加：线程数不增加、`TestListenerCloseClosesSessions` 与 `TestCloseUnblocksRead` 仍绿（关闭路径是 IOCP 最容易回归的地方）。
- **止损**：2 个工作日内不能把 16 格矩阵跑绿，回滚并记录未决原因。

#### P8.4 Linux 侧批量收发（D4）

- `recvmmsg`/`sendmmsg`：Linux 上一次系统调用可带多个数据报。**这是 Linux 的主要杠杆，Windows 没有等价 API**（`WSASendMsg` 一次仍只有一个数据报）。
- **前置**：E1（Linux 实机）先跑通。**没有 Linux 环境就不许写**——无法判定的改动一律不做。

#### P8.5 GHASH 走 PCLMULQDQ

- **依据**：`src/internal/gcm.cc` 目前是 4-bit 查表，AES-GCM 168 MB/s 对 AES-CFB 1262 MB/s，AES-NI 只体现 1.38 倍而非 3.8 倍。
- **时机**：当前不影响（单流 8.4 MB/s 离 168 MB/s 很远），但 P8.1/P8.3 把每包成本压下去之后它会**先**成为瓶颈。**触发条件**：单流 `aes-gcm fec=10/3` 达到 40 MB/s 以上再动。
- **门禁**：`TestBackendsAgree` 的六种长度逐字节不变 + NIST 向量 + 实测 ≥ 1.5 倍。

#### P8.6 RS 视图化（R20）

- 省掉 FEC 路径上的一次 memcpy（owning 接口 → 视图接口）。**触发条件**：P8.0 的表显示 FEC 段落占单包成本 > 10%。

#### P8 的通用规则（每条都来自已经踩过的坑）

1. **一项一提交**，每项独立可回滚。禁止"顺手一起改"——R22 的教训就是"看起来同源的两个缺陷其实一个是 recv 错误分类、一个是析构顺序"。
2. **每项前后对照**：同一 `run_bench.py` 参数，5 轮去首轮取中位数，写进 §6.3.2。禁止只报"改后"的数字。
3. **回归门不可让步**：`build.bat` 全绿（16 项）+ 16 格互通矩阵 + `relay_test`。任何"吞吐上升但正确性证据减弱"的改动一律回滚。
4. **测了没用也要记**：写清"试了什么、数字多少、为什么没用、已回退"。P6 已经这样处理过三项自旋优化，避免下一轮重复劳动。
5. **不许用编译期开关**掩盖未胜出的方案；未胜出的直接删掉。

#### §6.3.2 P8 测量台账（P8.0 已填，2026-10-18，Windows x64 回环）

**仪器化（P8.0 交付物）**：`kcp::UdpSession::EnableProfiling()` / `profile()`（`include/kcp/platform/profile.h` + `src/platform/profile.cc`）给会话装五本 CPU 账——read 线程、post 线程、update 回调（共享 `TimedSched`，按回调计费）、writer、reader；`SysSendTo`/`SysRecvFrom`/`SysWaitReadable` 另记调用次数与墙钟。默认关闭（每数据报一次 relaxed atomic load）；开启后每个数据报多两次墙钟读（~0.04 µs）、每个 worker 循环多两次线程时钟读（~0.18 µs）——`bench/syscall_cost` 的 `CLOCK` 行给出这两个价格，仪表本身比被测对象便宜一个数量级。`examples/echo_client -profile` 在 `RESULT` 后打印 `PROFILE` 行；`tools/bench/profile_split.py` 负责折叠成下表并执行门禁（`--fold` 可重折存档）。

**门禁口径（相对计划原文修正过两处，都写明了理由）**：

1. **CPU 闭合 ±10%**：五桶之和 vs 进程 CPU。Windows `GetThreadTimes` 粒度 15.6 ms，短跑必然量化失败（4 MiB/120 ms 时 +33%）——运行必须 ≥1 s（100 MiB 满足）。
2. **定价对照两级**（计划原文的 ±5% 相等不可能达成）：会话内价格超出 `bench/syscall_cost` 同调用价格 50% 记警告、150% 记失败。理由是两种测量对象不同——微基准发给**同进程** socket，会话发给**另一进程的存活对端**，跨进程唤醒 ~1 µs（空闲）到 2x（对端被并发挤掉）；而说谎的计数器（累计了错误的数量）落在 10x，不与 2x 混淆。

**当前状态分解表**（`profile_split.py --config X --mb 1 --iters 100`，即 §6.3 工作负载；仪器化开启）：

| 配置               | MB/s   | 墙钟 µs/包 | CPU µs/包 | read 线程 | post 线程 | reader | writer | CPU 闭合  |
| ---------------- | ------ | ------- | ------- | ------- | ------- | ------ | ------ | ------- |
| none fec=0/0     | 148.6  | 5.1     | 13.3    | 33%     | 33%     | 30%    | 2%     | **-2.5%** |
| aes-gcm fec=10/3 | 41.8   | 12.9    | 27.2    | 36%     | 41%     | 20%    | 2%     | **-0.9%** |
| salsa20 fec=10/3 | 59.1   | 9.3     | 20.2    | 32%     | 43%     | 21%    | 2%     | **-0.8%** |

`none` 配置的系统调用明细（另两组同构，仅价格随加密/FEC 上浮）：

| 系统调用            | 次数      | µs/次 | µs/包 | 微基准价 | 判定         |
| --------------- | ------- | --- | --- | ---- | ---------- |
| `sendto`        | 143459  | 2.88 | 2.88 | 3.33 | ok (-13%)  |
| `recvfrom`      | 151263  | 0.63 | 0.67 | 0.95 | ok (-33%)  |
| `select(0)` 探测 | 151263  | 1.08 | 1.14 | 0.74 | ok (+46%)  |
| `select(50ms)` 等待 | 6746 | 16.89 | 0.79 | - | 空闲非工作 |

**这张表推翻的与确认的**：

- **推翻**：§6.3.1 的"112 µs/包、`sendto` 占近一半、换 API 省 15~17 倍"。当前每包墙钟 5.1 µs、CPU 13.3 µs，系统调用合计 ~4.7 µs 墙钟且只占 CPU 账的一小片——其余在 `Kcp::Input`、FEC、加解密与逐字节校验，均匀分布在三个线程（各 1/3）。**没有任何单一段落值得先动手**，这正是 P8 每一项都设触发条件的原因。
- **确认**：P6 的两条归因仍然成立——协议引擎不是瓶颈（`kcp_pump` 0.8~2.1 GB/s）、读路径不是瓶颈（recvfrom + 探测 = 1.7 µs/包）。
- **机器状态漂移（新方法论记录，见 §140）**：绝对 MB/s 在 run 间漂移 ±30%（同工作负载三次干净全量基线：109.5 / 111.7 / 160.5），run 内 min/max 却只有 ±1%。**上表的百分比（各段占比）是时钟状态无关的，绝对吞吐不是**——跨会话比较必须同机会话内多轮中位数。

**P8.1~P8.6 按本表重算触发条件**：

| 项 | 触发条件（原文）                                   | 当前状态                                      | 结论            |
| --- | ---------------------------------------- | ----------------------------------------- | ------------- |
| P8.1 `WSASendTo` | （无条件项，立论是 API 差 15~17 倍）                  | `sendto` 3.4 µs vs `WSASendTo` 2.7 µs = **1.3 倍**，每包只值 ~1 µs | **不实施**（记录：当前不是主要瓶颈，P8 规则 4） |
| P8.2 去 `select(0)` 探测 | 读路径占比 >10%                           | recvfrom+探测 = 1.7 µs/包墙钟，占 CPU 账 <15%        | 未满足           |
| P8.3 IOCP        | P8.1 后 I/O 等待仍占单包成本 >30%                 | 无 >30% I/O 等待可省（系统调用合计 ~4.7 µs 墙钟）        | 未满足           |
| P8.4 Linux `sendmmsg` | E1 先跑通                                | E1 仍阻塞                                    | 同前            |
| P8.5 GHASH PCLMULQDQ | 单流 aes-gcm 达 40 MB/s（**且** P8.1/P8.3 先压下每包成本） | 41.8~45.7 MB/s 过线，但前置链未发生；且 GHASH 168 MB/s 对 45 MB/s 利用率 27%，未成为瓶颈 | 未满足（前置链断裂）    |
| P8.6 RS 视图化      | FEC 段落占单包成本 >10%                        | post 线程整体 33~43%，但其中 `sendto` 只占 1/3，FEC 段无法从系统调用价单独拆出；按 none 配置（FEC 关闭）33% 反推，FEC 特有工作 <10% | 未满足           |

**台账**：

| 项 | 状态 | 单流 MB/s（前 → 后） | 每包 CPU（前 → 后） | 结论 |
| --- | --- | --- | --- | --- |
| 基线（P6，未改动） | 已测 | 12.2 | 待 P8.0 | §6.3.1（**状态特定，当前不复现**，见 §134） |
| P8.0 仪器化 | **已完成** | 148.6（当前状态，run 间 ±30%） | 13.3 µs | 门禁全过；推翻 P8 立论前提 |
| P8.1 `WSASendTo` | **触发条件失效** | — | — | 15~17 倍 → 1.3 倍；记录不实施 |
| P8.2 去 `select(0)` 探测 | 未开工（触发条件未满足） | — | — | 读路径系统调用 <15% CPU |
| P8.3 IOCP | 未开工（前置未满足） | — | — | 无 >30% I/O 等待可省 |
| P8.4 Linux `sendmmsg` | 未开工（依赖 E1） | — | — | 同前 |
| P8.5 GHASH PCLMULQDQ | 未开工（前置链断裂） | — | — | 见上表 |
| P8.6 RS 视图化 | 未开工（触发条件未满足） | — | — | FEC 特有工作 <10% |

**新增工具（v5.12）**：`bench/syscall_cost`（C++ 侧逐调用定价，含墙钟与 CPU 两个时钟）、`tools/interop/syscallprobe`（Go 侧同构对照）。这两个工具不是一次性脚本：`run_bench.py` 的 Calibration 段直接调用它们，所以每次基线都会重测，数字不会过期。

---

## 7. 工期

**20~22.5 个工作日当量**（P0 2 / P1 1 / P2 2.5 / P3 2 / P4 1.5 / P5 3.5 / P6 5 / P7 1.5~~2），C++ 约 7500~~8500 行含测试。

**P8 未计入上述数字**（v5.12 补）：它不在原计划的交付范围内，按 §P8 的分解，最坏情形是 P8.0 1d + P8.1 0.5d + P8.2 0.5d + P8.3 2d + P8.4 1d + P8.5 1d ≈ **6d 上限**；其中 P8.2/P8.3/P8.5/P8.6 都带触发条件，实际大概率只做 P8.0 + P8.1（1.5d）。

较 v5 的增量：双平台 socket/熵源/构建/测试 +1.5d（决策⑤）；AES-NI + 回退 + 交叉互验 +1d（决策⑥）。

**P0~P6 实际**：代码量约 1.05 万行（含测试/示例/微基准），P6 超出预算的部分全部花在两处并发缺陷的定位上（§6 缺陷记录）——症状是"随机超时"与"随机堆损坏"，都不是靠读代码能看出来，最终靠**一个 listener + N 会话**的压测形态 + 变异测试才钉死。这一段投入是划算的：两处都是会在生产上表现为"跑几小时后整机不响应"的类型。

---

## 8. 风险

| #   | 风险                                                                   | 缓解                                                                                                      |
| --- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| R1  | RS 矩阵与 klauspost 不一致                                                 | `rs.json` 在 P3 仲裁                                                                                       |
| R2  | CFB 整包加密/CRC 覆盖范围/8x 展开偏差                                            | `crypt.json`（P2）+ `frame.json`（P6）双仲裁                                                                   |
| R3  | Windows socket 选项不可用（DSCP 等）                                         | 返回明确"不支持"                                                                                               |
| R4  | 手写 condvar 与 Go 调度不等价                                                | §3.2 规则 + 生命周期测试                                                                                        |
| R5  | AES 安全性与性能                                                           | AES-NI 路径恒定时间（决策⑥）；仅无 AES-NI 的老 CPU 回退 T 表，README 记录该路径 cache-timing 差距；加固走 P8                          |
| R6  | KCP 后续 tick 无脱机向量                                                    | 行为单测 + 丢包中继 + 端到端互通                                                                                     |
| R7  | 无批量收发导致吞吐低于 Go 版                                                     | **已实测并定位到具体调用**（`bench.md` / §6.3.1）：单流 12.2 MB/s 对 Go 119.5 MB/s。归因不是协议/加密/RS（`kcp_pump` 0.8~2.2 GB/s），不是窗口×RTT（32/128/512 吞吐不变），**而是 `sendto` 自己：41~46 µs/包，占 112 µs/包的近一半**；同机 `WSASendTo` 2.6 µs，`WSASendTo`+null OVERLAPPED（同步语义）同样 2.6 µs，已 connect 的 `send()` 2.5 µs，Go 的未连接 `WriteTo` 2.9 µs，Python 的 `sendto` 45 µs ⇒ **API 决定成本**。消解入口是 P8.1                                       |
| R8  | 互通 16 格调试时间不可控                                                       | P7 止损线                                                                                                  |
| R9  | 全局单例析构顺序 / 静态初始化顺序（#32/#33）                                          | §3.5 函数内静态 + 不析构；P6 测"进程退出不 terminate"                                                                  |
| R10 | JSON schema 漂移（#27）                                                  | §5.6 字段级定义 + `schema` 版本号                                                                               |
| R11 | TimedSched 单线程 vs Go 多 worker                                        | §3.2 记录；不影响协议正确性                                                                                        |
| R12 | **CFB 残字节语义误译**（宽切片字面直译，#43）                                         | §4.3 规则 + 非对齐长度向量双保险                                                                                    |
| R13 | **Read 消息边界语义误实现**（按"填满 b"写，#37）                                     | §3.6 + P6 bufptr 专项测试                                                                                   |
| R14 | **output 队列"满则丢"被实现成阻塞**（持锁死锁，#38）                                   | §3.6 + P6 队列满场景测试                                                                                       |
| R15 | RS 等长契约被下压到 RS 层（补齐逻辑重复实现，#41）                                       | §3/P3 接口契约：补齐归 P4                                                                                       |
| R16 | **平台行为分叉**（双平台下 socket 选项/调度差异，决策⑤）                                  | platform 抽象层收敛差异；P6 门禁双平台全量回归；§6.3 基线双平台各测                                                              |
| R17 | **GHASH 位序/归约常量搞反**（密文对、tag 错，P2 已实际踩中）                              | §6 P2 实施记录 #1 的判定方法（`S = tag ⊕ E(J0)` 反解 + big.Int 反序比对）；`gcm_test` 双向量 + `crypt.json` 两个 aesgcm 长度     |
| R18 | **XTEA 表推进节奏错位**（每对轮多推进一次 sum，P2 已实际踩中）                              | §6 P2 实施记录 #2；`crypt.json` xtea 向量逐字节                                                                   |
| R19 | **RS 层擅自吸收补齐职责**（对不等长分片做 padding/truncate，掩盖 P4 的 padding bug）       | RS 对不等长一律 `kInvalidArgument`（`rs_test::TestEncodeRejectsBadShapes`）；补齐只在 P4 做，且 P4 门禁有 `fec.json` 逐字节对拍 |
| R20 | RS 的 owning `ShardSet` 接口让 FEC 每包多一跳 ~1.4KB memcpy（Go 用 alias 免掉这一跳） | 先实测：P6/P7 吞吐若低于 Go 基线 30%，再给 RS 加 `EncodeView` / `ReconstructView`（视图 + 调用方预分配）；现在动手属未测先改               |
| R21 | **flush 首帧空转被"顺手修好"**（`cwnd` 初值 0 时首帧不发段，看起来像 bug）                   | `TestCwndBootstrap` 钉住；`kcp.json` 首帧向量在 nc=1 下不受 cwnd 影响，两条路径都要保留                                       |
| R22 | **"永不返回"的循环被加上了 return**（读循环 / `Close` 递归关闭子节点这两类 Go 形态，加了 `return` 就变成整机停摆或堆损坏） | P6 两处实际踩中：`Monitor` 遇 `WSAECONNRESET` 退出 → 同 listener 全部会话饿死；`Listener::close` 不关子会话 → 会话析构回调已释放的 map（`STATUS_HEAP_CORRUPTION`）。缓解：①照抄 Go 的错误策略（recv 错误只计数）②`Listener.Close` 必须先关全部子会话再关 fd ③判定只能用**共享资源并发形态**（1 listener + N 会话）压测，单连形态永远测不出（实测 160 次单连全绿而并发 15/40 失败）④`TestListenerSurvivesPeerDisappearing` + `TestListenerCloseClosesSessions` 钉住，两处均做过变异回退验证 |
| R23 | **per-call 系统调用成本随 API 变化一个数量级**（`sendto` 44 µs vs `WSASendTo` 2.6 µs，仅 Windows；Linux 上 `sendto` 本就是 1~2 µs 量级） | `bench/syscall_cost` 把每个调用单独定价（墙钟 + CPU 双时钟），`run_bench.py` 每次基线都重跑它，数字不会过期；P8 每一项都以它做前后对照。**教训**：先给每个系统调用定价，再讨论算法/协议/加密，否则会把 I/O 成本误记到协议头上 |

---

## 9. 验收标准

- [x] P1~P6 全部门禁通过（含 5 个向量逐字节、生命周期、错误码、MTU 边界）—— P6 的"双平台"一项待 Linux 环境（E1），Windows 已全绿
- [x] §3.3 API 覆盖 100%（映射表逐条兑现：CamelCase 签名 + 仅 `read`/`write`/`write_buffers`/`close` 与 11 个取值存取器为 snake_case 例外 + `k`+CamelCase 常量 + 尾下划线成员）
- [x] **命名合规（Google C++ Style）**：`clang-format --dry-run --Werror` 全绿（77 文件）；无 `#pragma once`、guard 全为 `KCP_*_H_`（28 个头）；无 `kIcp*`/`I*` 接口前缀/`Errc` 残留
- [x] §3.4 错误码行为与 Go 逐条对齐（含 output 队列满静默丢、recv 错误只计数不致命）
- [x] **§3.4.1 偏离登记表 D1~D19 逐条可验证**（每个偏离点有对应测试或文档说明）
- [x] MSVC `/W4` + GCC/Clang `-Wall -Wextra` 通过（定点 pragma 抑制需注明原因）
- [x] 互通矩阵 16 格全绿（3 轮，且每格首包逐字节对拍）—— 见 `matrix.md`
- [x] 零第三方依赖（Windows: ws2_32 + bcrypt；Linux: 仅 glibc/Threads）
- [x] §4 全部表格有自动化测试覆盖（含 CFB 非对齐、RS 变长、§4.7 常量表）
- [x] 性能基线落 README（§6.3 方法），与 Go 版差距明确并已归因（§6.3.1）
- [x] 并发/生命周期测试后线程与句柄无泄漏，进程退出不 terminate
- [ ] **双平台**：Windows + Linux 构建、测试、互通冒烟全部通过（决策⑤）—— Windows 已通过（Release + Debug，16/16），Linux 待环境
