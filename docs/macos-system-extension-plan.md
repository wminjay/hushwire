# macOS System Extension 迁移计划

状态：已确认，分阶段实施
日期：2026-08-09

## 目标

把当前通过 AppleScript 临时提权并启动 root CLI 的 macOS 客户端，迁移为系统原生托管的 Packet Tunnel：

```text
HushWire.app
  ├─ 配置、状态、日志与连接控制
  ├─ NETunnelProviderManager
  └─ OSSystemExtensionManager（仅负责安装/升级扩展）
                 │
                 ▼
com.jamie.HushWire.PacketTunnel.systemextension
  ├─ NEPacketTunnelProvider
  ├─ HushWire Rust Core
  ├─ UDP / TCP / Noise 会话
  └─ packetFlow + NEPacketTunnelNetworkSettings
```

目标结果：

- 首次安装时批准 System Extension 和 VPN 配置；正常连接、断开不再要求管理员密码。
- GUI、授权辅助进程和隧道数据面生命周期完全分离。
- 由 macOS 创建和回收虚拟接口，并管理路由、DNS、MTU 与 VPN 状态。
- GUI 退出后隧道可以继续运行；重新打开 GUI 后读取真实系统状态。
- 支持定向路由、全隧道、UDP、TCP、重连、重协商和多 peer。
- 保留当前 Linux 服务端和 v3 wire protocol，不因 macOS 迁移修改线上服务。

## 已确认的部署选择

HushWire 使用 Network Extension 框架中的 `NEPacketTunnelProvider`，并在 macOS 上打包为 System Extension。

选择 System Extension 而非 Packet Tunnel App Extension 的原因：

- 客户端计划直接安装，不以 Mac App Store 为唯一分发渠道。
- System Extension 可使用 Developer ID 签名并直接分发。
- 数据面运行在全局系统上下文，不依赖当前 GUI 或登录会话的临时子进程。
- 与 Tailscale Standalone 的部署模型一致，更符合长期运行的 macOS VPN。

这不是放弃 Network Extension；System Extension 是 `NEPacketTunnelProvider` 的承载方式。

## 当前基线

- Rust crate 版本：`0.6.1`。
- macOS GUI：SwiftPM executable，手工组装 `.app`。
- 当前签名：ad-hoc。
- 当前启动链：`HushWire.app -> osascript -> authtrampoline -> hushwire-control -> hushwire`。
- 已复现缺陷：`authtrampoline` 被 macOS idle-exit 清理时，同一进程组内的 HushWire 收到 `SIGTERM`。
- 当前 Rust `tunnel::run` 同时负责 TUN、路由、信号、transport 和协议循环，尚不能直接嵌入 Packet Tunnel。
- `src/lib.rs` 目前只公开 crypto/replay 模块，需要建立独立的数据面 API。

## 开发者账号与标识

可用公司开发团队：`95Q852BXKJ`。

暂定标识：

- 容器 App：`com.jamie.HushWire`
- System Extension：`com.jamie.HushWire.PacketTunnel`
- App Group：`group.com.jamie.HushWire`

开发阶段使用 Apple Development 签名和开发 provisioning profiles。直接分发阶段需要为同一团队准备：

- Developer ID Application certificate
- App 与 System Extension 对应的 Developer ID provisioning profiles
- Hardened Runtime
- notarization 与 stapling

密钥、API key 和公证凭据不得写入仓库。

## 实施阶段与验收门槛

### 阶段 0：稳定现有测试客户端

工作：

- 让 CLI 在 GUI 特权启动后建立独立 session/process group。
- 保留 PID 校验和优雅 `SIGTERM` 清理。
- 修复 root 进程被普通用户 `kill -0` 误报为 stopped 的辅助脚本状态判断。

验收：

- HushWire PID 的 PGID 不再等于 `authtrampoline` 的 PGID。
- 授权启动器退出或被系统清理后，HushWire 仍运行。
- GUI 正常断开仍能清理 TUN 和路由。
- 不改变 Linux 服务、配置格式或 wire protocol。

回退：恢复现有 `hushwire-control` 与 CLI 参数即可。

### 阶段 1：拆分 Rust Core

把现有 `tunnel::run` 拆为三层：

```text
协议核心 Engine
  ├─ session / handshake / crypto / replay / rekey
  ├─ route lookup / peer state / stats
  └─ transport abstraction

Packet I/O adapter
  ├─ CLI TUN adapter
  └─ Network Extension packetFlow adapter

平台配置 adapter
  ├─ CLI route/firewall adapter
  └─ NEPacketTunnelNetworkSettings adapter
```

要求：

- `Engine` 不直接打开 `/dev/tun`，不执行 `/sbin/route`，不安装 signal handler。
- transport 继续复用现有 UDP/TCP 实现。
- CLI 行为保持兼容，由 CLI adapter 组合原有能力。
- 建立线程安全的 start/stop、packet ingress/egress、stats 和 event API。

当前进度（2026-08-10）：

- `config`、`router`、`packet`、`state`、UDP/TCP transport 已从 CLI 私有模块提升为 library 模块。
- 会话、握手、rekey、防重放和单边重启恢复状态已迁入 `engine`。
- `Engine` 已提供 IP ingress、transport ingress、transport/IP action、握手事件和 peer stats API。
- 现有 CLI 数据面已经改为调用 `Engine`；TUN、socket、系统路由、防火墙和 signal handler 仍留在平台 adapter。
- 已增加两个 Engine 纯内存实例的完整握手及双向 IP packet 测试，全程不创建 TUN 或 socket。
- 已在隔离的 `10.77.60.1/32` 实机配置中验证连接、服务端单边重启后 19 秒自动恢复，以及正常停止清理；默认路由和生产实例全程未变。
- 握手重试、keepalive、会话失效和 UDP rebind 决策已抽为 Rust `EngineScheduler`，CLI 与 Network Extension 通过同一套调度策略驱动 Engine。

验收：

- 现有 Rust 单元、集成、netns 测试全部继续通过。
- 新增内存 Packet I/O 测试，覆盖双向数据、重连、重协商和停止。
- CLI 与抽取前的配置和 wire 行为一致。

### 阶段 2：建立稳定 C ABI

产物：

- `libhushwire_core.a`
- `HushWireCore.h`
- arm64 与 x86_64 macOS 构建
- 可供 Xcode 引用的 XCFramework 或等价构建产物

API 最小集合：

- runtime create/destroy
- start/stop
- submit outbound IP packet
- receive inbound IP packet callback
- state/event callback
- peer stats snapshot
- error ownership与字符串释放

当前进度（2026-08-11）：

- ABI v1 已完成，导出 opaque runtime、幂等 start/stop、IP/transport ingress、同步 action/event 回调、peer stats 与公开路由元数据。
- 配置可直接从内存 TOML 解析，不需要把私钥和 PSK 写入临时文件。
- 所有入口使用固定容量错误结构，Rust panic 被截留在 ABI 内；Swift 不负责释放 Rust 字符串或 packet buffer。
- stop 会拒绝新 packet、等待正在执行的回调结束，然后丢弃 Engine 与全部会话状态。
- `libhushwire.a` 已生成 arm64/x86_64 universal XCFramework：`dist/HushWireCore.xcframework`。
- Swift smoke test 已实际链接 XCFramework，并通过 create/start/metadata/重复 stop/destroy。
- 构建与验证入口分别为 `macos/scripts/build-core-xcframework.sh` 和 `macos/scripts/test-core-xcframework.sh`。

验收：

- Swift 测试 target 可创建和销毁 runtime。
- 重复 start/stop 不泄漏线程、socket 或回调。
- ABI panic 不跨越 FFI；所有异常转为结构化错误。

### 阶段 3：创建 Xcode App 与 System Extension

工作：

- 建立正式 Xcode project；保留现有 SwiftUI 代码并逐步迁移。
- 增加 Packet Tunnel System Extension target。
- 配置 App Group、Network Extension 和 System Extension install entitlements。
- 用 `OSSystemExtensionManager` 管理安装/升级。
- 用 `NETunnelProviderManager` 保存 VPN 配置和控制连接。

当前进度（2026-08-09）：

- 已建立由 `macos/project.yml` 生成的正式 Xcode project，包含 SwiftUI 容器 App 与 Packet Tunnel System Extension 两个 target。
- `.systemextension` 已正确嵌入 `Contents/Library/SystemExtensions`，并静态链接 HushWireCore ABI v1。
- 已实现 `OSSystemExtensionManager` 激活控制与 `NETunnelProviderManager` 配置/状态骨架。
- 生命周期预览在任何 `setTunnelNetworkSettings` 调用前返回明确错误，不创建接口、路由或 DNS 设置。
- 无签名编译、Xcode embedded-binary validation、Apple Development 签名及严格 deep signature verification 均已通过。
- 团队 `95Q852BXKJ` 已生成 `com.jamie.HushWire` 与 `com.jamie.HushWire.PacketTunnel` 的 Mac Development profiles；当前开发 Mac 已登记。
- 已完成 Apple Development 签名、人工批准、激活、VPN profile 保存、失败生命周期与正常停止验证；macOS 会复用驻留的 provider 进程，但每次连接的 Core/session/network settings 均独立启停。

验收：

- 开发签名严格验证通过。
- System Extension 能安装、启用、替换版本和卸载。
- 无真实 peer 时也能安全启动并返回明确错误，不遗留网络设置。
- App 关闭和重新打开后状态一致。

### 阶段 4：接入真实 Packet Tunnel

工作：

- 把 `packetFlow` 与 Rust Core 双向桥接。
- 使用 `NEPacketTunnelNetworkSettings` 设置地址、included/excluded routes、DNS 和 MTU。
- 对全隧道正确处理 peer endpoint 旁路，避免 transport 套入自身隧道。
- 将配置拆为公开元数据与 Keychain/App Group 中的敏感材料。
- 把 peer/session/stats/events 暴露给 GUI。

当前进度（2026-08-09）：

- App 将 TOML 验证后原子写入权限为 `0600` 的当前用户 App Group 文件；VPN provider configuration 只保存固定存储类型与路由策略，不保存 private key、PSK 或 TOML。System Extension 以 root 身份解析到不同的 App Group 容器，且 macOS 会把 `startTunnel(options:)` 留在可诊断的 session state 中，因此 start options 也不承载密钥：provider 先以“等待配置、无路由”状态启动，再由 App 通过私有 `sendProviderMessage` 通道传递配置，成功后才安装 `/32` network settings。
- App 已显示接口地址、UDP/TCP、MTU、Peer、Endpoint 和 allowed routes，连接后轮询显示握手、收发字节、last-seen 与真实 endpoint。
- Packet Tunnel 已接入 `NEPacketTunnelFlow`、Rust Core、Network.framework UDP/TCP transport；TCP 使用与 CLI 相同的 2 字节大端长度帧。
- provider 现在支持默认的 `host-routes-only`、`split-routes-v1` 与显式选择的 `full-tunnel-v1`。分流 v1 接受单 Peer、最多 256 条非默认 IPv4 CIDR，DNS 必须被路由覆盖，并与全隧道一样在认证预握手完成后才安装路由和 DNS；全隧道仍只接受单条 `0.0.0.0/0` 且要求每次由 App 明确确认，同时可用少量 `excluded_ips` 表达“默认走隧道、例外直连”，无需维护 WireGuard 式补集列表。
- Peer endpoint 已支持 DNS 名称；Core 在每个 runtime 创建时解析一次、优先 IPv4，并向 UI 同时公开配置名称与本次解析地址。macOS 会按本次解析结果生成 endpoint 排除路由，CLI 对任何会捕获 endpoint 的分流/全隧道路由也会先安装物理路径例外。
- 已加入共享 runtime smoke test，覆盖配置解析、公开元数据、start、初始握手、scheduler tick 与 stop；System Extension 无签名构建通过。
- Apple Development 签名的 build 5 已完成原位升级，并通过隔离的 `10.77.60.1/32` 实例验证真实握手、双向 packet flow、正常连接/断开及接口与路由完整清理；默认路由、DNS、Tailscale 和生产 `27777`/`27779` 实例全程未变。
- UDP 与 TCP 均完成 64 MiB 双向传输并校验 SHA-256；TCP 在持续下载下发现的非阻塞短写问题已改为有界的完整帧待写队列，修复后未再出现 `EAGAIN` 导致的帧流损坏。
- 已跨越 120 秒自动 rekey 连续 Ping：换钥边界前后数据包连续，服务端只完成一次 responder 握手，没有重复会话、解密或认证错误。此前旧会话在 initiator 立即替换时丢弃在途包的问题，已通过 receive-only previous-session grace 修复。
- App build 7 会在启动时通过 System Extensions properties API 恢复扩展真实状态；已验证连接中退出、重开和仅替换容器 App 均不重启 provider、不打断数据面，UI 能恢复 VPN、配置和实时会话。
- `/32` 安全策略已提取为共享校验层并由 Swift smoke test 覆盖，明确拒绝子网/默认路由、固定本地监听端口及无 Peer 路由配置，拒绝发生在安装 VPN settings 之前。
- 已验证服务端先不可达时 UI 显示 endpoint 未确认和从未收到认证流量；服务恢复后立即自动握手。已连接状态下停止服务约 36 秒后，恢复服务约 4.2 秒完成新握手、约 5–6 秒恢复数据。
- Linux systemd 停止时发现 `KillMode=control-group` 可能波及临时 `ip route del` 子进程；v0.6.1 加入短时有界重试并保持最终精确路由检查，隔离实例连续三轮 start/stop 均无清理警告和残留路由，两个生产实例保持 active。
- 在独立 UTM macOS 26.6.1 虚拟机中完成 build 11 / extension build 9 验收：`/32` 模式只安装 `10.77.61.1/32`，默认路由、DNS 与公网出口保持不变；全隧道模式将默认流量导入 utun、把 `154.40.60.58` endpoint 保留在 `en0`、安装 `1.1.1.1`/`1.0.0.1` DNS，并从隔离服务端出口访问公网。断开后路由、DNS 和公网出口均恢复，宿主机网络全程未变。
- 全隧道服务端不可达时，连续观测到 15 秒预握手窗口内默认路由和 DNS 从未改变，随后自动失败并回到 Disconnected；绕过 App 直接启动的请求在约 1 秒内因缺少本次明确确认而被拒绝。
- 完成 System Extension build 6 → 7 → 8 原位升级。测试发现快速停止再启动时 `NWParameters.allowLocalEndpointReuse` 会复用刚取消的 UDP 流，使服务端暂时保留旧会话直到 90 秒恢复计时器触发；禁用本地 endpoint 复用后，连续重连使用不同 NAT 端口并约 1 秒完成握手。停止路径也改为由 macOS 在 `stopTunnel` 完成后统一拆除 utun，避免应用重复清理 network settings 的竞态和误报。
- 完成 extension build 8 → 9 原位升级和 UTM 整机重启验收：重启后扩展仍为 activated/enabled，VPN 保持断开，默认路由与公网出口安全恢复，App 配置继续可用。被动服务端保留旧 endpoint 并持续重试超过 13 分钟时，重启后的客户端仍可在不重启服务端的情况下切换到新 NAT endpoint 并完成握手；UDP/TCP 网络命名空间测试也覆盖了任一端单独重启后的双向恢复。
- Developer ID 直接分发 entitlement 与本地打包器已经落地；打包器会验证两个 direct profile，按 extension → app 顺序签名，要求 Hardened Runtime/secure timestamp，随后执行 notarize、staple、Gatekeeper 验证并生成校验和。v0.7 及以后 tag 只先产生草稿 Release，避免旧的 ad-hoc GUI 被误当成 System Extension 正式包。
- 待完成：实体 Mac 的 sleep/wake、Wi-Fi/有线切换、扩展崩溃、24 小时运行、Developer ID 证书/profile 实签、公证和干净环境直接分发验收。

验收顺序：

1. 无路由配置，只验证扩展生命周期。
2. 单个 `/32` 测试地址，不影响默认路由。
3. UDP 定向隧道。
4. TCP 定向隧道。
5. peer/server 单边重启恢复。
6. sleep/wake、Wi-Fi 切换和 GUI 退出/重开。
7. 最后才验证 `0.0.0.0/0` 全隧道和 DNS。

### 阶段 5：稳定性与安全验收

必须覆盖：

- 24 小时持续运行与周期 rekey。
- 扩展 crash、App crash、系统重启、用户注销与重新登录。
- 配置损坏、密钥错误、服务端不可达、TCP 半开与 UDP NAT 变化。
- System Extension 更新、降级拒绝、App 删除与卸载。
- DNS 泄漏、endpoint 路由循环、IPv4/IPv6 行为和多网络服务。
- 日志不得输出私钥、PSK、完整敏感配置或认证材料。
- App、extension、XCFramework 和最终 dmg/pkg 全链路签名验证。

### 阶段 6：直接分发

- Developer ID archive/export。
- 公证、staple、Gatekeeper 离线验证。
- 在干净 macOS 用户环境安装和首次授权。
- 升级已有版本且不丢失配置。
- 形成 release notes、安装说明、恢复/卸载说明。

## 网络安全边界

- 开发和前四轮测试禁止修改默认路由。
- 所有定向测试使用独立测试地址和服务器隔离实例。
- 全隧道测试前记录默认 gateway、DNS 和 endpoint exception。
- 每次停止后验证 System VPN 状态、路由、DNS 和接口均已恢复。
- 不在协议迁移期间改动生产 `27777`/`27779` 实例。
- 任何需要重启当前 Mac 隧道或远端测试实例的步骤，先明确记录目标与回退路径。

## 发布策略

- `0.6.x`：v3 协议、安全修复和现有 GUI 启动器稳定化。
- `0.7.0-dev`：System Extension 开发预览，仅用于隔离配置。
- `0.7.0`：通过完整 UDP/TCP、恢复、升级和全隧道验收后发布。

System Extension 迁移不改变 v3 wire protocol，因此 Linux 端只要运行兼容版本，不需要因 GUI 架构变化再次改配置或密钥。
