# Tern TURN Relay

为 Windows / macOS / Linux Tern 提供 **Rust 原生 Cloudflare TURN 专用连接入口**。复用 Linux 服务器已有的 session daemon，不修改 Tern 二进制、原服务、系统路由或远端工作区；连接失败不自动退回直连。采用 [MPL-2.0](LICENSE)，依赖许可见 [第三方声明](THIRD_PARTY_NOTICES.txt)。不是 Tern 或 Cloudflare 官方产品。

## 支持范围

| 角色 | 系统与架构 | 发行程序 |
|---|---|---|
| 本机客户端 | Windows 10/11 x64，Tern 0.9.8 | `tern-turn-relay-windows-x86_64.exe` |
| 本机客户端 | macOS Apple Silicon / Intel，Tern 0.9.8 | `tern-turn-relay-darwin-arm64` / `tern-turn-relay-darwin-x86_64` |
| 本机客户端 | Linux x86_64 / arm64 桌面，Tern 0.9.12 | `tern-turn-relay-linux-x86_64` / `tern-turn-relay-linux-arm64` |
| 远端 helper | Linux arm64 / x86_64，已有 Tern 用户服务与 session daemon | `tern-turn-relay-linux-arm64` / `tern-turn-relay-linux-x86_64` |

- 不声明支持 Windows ARM64、x86 或 ARM64 上的 x64 仿真。Linux 本机客户端与远端 helper 使用同一份静态 Linux 程序。
- Linux 本机需要 `/usr/bin` 下的 GNU coreutils（包括 `stat`、`sha256sum`、`dd`）、`awk`、`curl`、`cmp`、`mktemp` 与 `/usr/bin/ssh`（OpenSSH Client），以及 `/usr/bin/zenity` 或 `/usr/bin/kdialog` 提供桌面隐藏输入；没有桌面对话框时只能在终端中输入。Tern 的路径来自 XDG：配置在 `$XDG_CONFIG_HOME/tern`（默认 `~/.config/tern`），默认 profile 的插件数据在 `$XDG_STATE_HOME/tern/plugin-data`（默认 `~/.local/state/tern/plugin-data`）。
- Linux 的用户私有组（umask 002）下 Tern 会创建组可写目录。仅在 `/etc/nsswitch.conf` 中 `passwd`、`group` 各唯一且来源仅为 `files`，并核验当前用户独占主组、没有其他补充成员时，才允许该组的组写权限。每次权限判断重新读取，不永久缓存成员关系；NSS 文件上限 64 KiB，账户文件各 4 MiB，缺失、重复、不完整或超限记录均拒绝。LDAP/SSSD 等混合来源按严格规则处理，需移除相关目录的组写权限；其他组可写或任何人可写始终拒绝。
- Windows 需要系统自带的 Windows PowerShell 5.1 和 **原生 OpenSSH Client**（Windows 可选功能）；不需要 WSL、Git Bash、Python、Cargo 或本机编译。PowerShell 仅短暂校验/准备运行时，持续转发由 Rust 完成。构建工具中的 Python 仅用于维护者打包和 CI。
- Windows 私有数据和受管理文件必须位于启用文件事务（TxF）的本地 NTFS 卷；ReFS、FAT、网络卷、EFS 加密文件或 TxF 不可用时拒绝写入。微软已弃用 TxF，未来系统可能移除；升级系统前需重新确认兼容性，不能把该依赖视为长期平台保证。
- 需要已核验 SSH 主机密钥的 OpenSSH 别名，可非交互公钥登录；HostName 为公网 IPv4。先使用系统 OpenSSH 成功登录并核验主机指纹。ProxyJump、ProxyCommand、IPv6 和域名目标不在支持范围内。
- 用户自己的 Cloudflare Realtime TURN Key；流量费用由该账户承担。插件不提供共享凭据，不读取浏览器登录状态，也不提供 OAuth 登录。

## 安装与首次配置

在 **Tern → Preferences → Plugins → Install…** 填写：

```text
github.com/jiwangyihao/tern-turn-relay
```

或运行：

```sh
tern plugin install github.com/jiwangyihao/tern-turn-relay
```

未配置的新安装只注册插件，不下载程序、不访问 Cloudflare、不部署网关、不选择服务器。已有安装保留原来的持久恢复语义：仅当用户此前显式连接并保存了恢复意图、配置精确匹配、同一 loopback Host 仍存在时，才可恢复已授权的后台；不会自动添加或切换原生 Host。显式 Stop 会撤销该恢复意图。

没有 Git 时，从 [Releases](https://github.com/jiwangyihao/tern-turn-relay/releases) 下载源码归档，核验 SHA-256，解压后在 Install… 选择含 `plugin.toml` 的目录。

1. 打开 **TURN → Settings: server, Cloudflare Key and private runtime**。首次显式打开设置时，下载与插件版本一致的 Rust 程序，验证固定 SHA-256 和大小，存入私有目录；需要至少 256 MiB 空闲空间。
2. 选择 **配置 Cloudflare TURN Key**。先在 [Cloudflare Realtime 控制台](https://dash.cloudflare.com/?to=/:account/calls) 创建自己的 TURN Key，再通过系统隐藏输入窗口填写 Key ID 和 **TURN-key API token**，不要填写账户级 API Token。验证成功后保存；取消或验证失败保留原凭据。
3. 选择已有 SSH 别名。插件按远端架构下载并验证 Linux Rust helper，通过严格 SSH 放入远端私有缓存，再只读检查原服务、daemon 和实际 UDP 监听端口。不会启动第二个 session daemon；多个工作区可供选择。
4. 阅读 **TURN 配置确认** 页，核对目标、工作区、网关目录、本机端口及 SSH 规则文件，再点击状态栏 **TURN · 确认配置**，选择 **确认应用**。
5. 选择 **连接 TURN TLS**。允许从本机 Host 或对应服务器 Host 发起；拒绝切换无关远端 Host，不自动回退直连。

默认本机 UDP/TCP 端口为 `18377`。确有冲突时在 **高级：自定义本机端口** 修改，新端口会显示在确认页。更改运行中的配置前必须显式 Stop，向导不会擅自中断连接。

Windows 请确认系统 OpenSSH 可读取当前用户的 SSH 配置、密钥与 known_hosts，不要把 Git Bash/WSL 的 SSH 配置误当原生配置。路径含空格或中文可用；向导按 argv 元素传参，不拼接 shell 命令。默认本机入口只绑定 `127.0.0.1`，不要开放到公网。下载不使用系统 HTTP 代理；企业网络需要能直接访问 GitHub HTTPS 发行资产、Cloudflare TURN TLS/UDP 与原 SSH 服务。不要通过关闭证书或身份验证绕过网络限制。

## 从 0.4.x / 0.5.0–0.5.9 升级到 0.5.10

先显式 Stop，再通过 Settings → 插件管理更新。新版本使用独立的 `native-runtime/0.5.10/`，准备失败不覆盖旧运行时、凭据或配置；配置和原网关/daemon 身份仍需通过检查，不会静默重新绑定。Windows 首次安装后必须先显式 Settings；普通 Status 查询不触发下载。显式 Stop 为保持旧版迁移兼容，可以先准备缺失的控制程序，失败时不会断开 Host 或假报已停止。所有实际原生命令都经 `--exec` 再次验证程序完整性；不能把文件存在或一次 Settings 成功当作后续执行授权。

## 从 0.3.x 升级

先使用旧版 **Stop TURN for ALL windows and SSH TCP sessions** 停止共享入口，再执行原生插件更新。远端程序及原 daemon 不会被 Stop 关闭。

如果已经通过 Tern 原生安装器替换了插件、旧后台仍在运行，直接选择新版 Stop：它会先下载并校验缺少的 Rust 控制程序，再执行停止。准备失败会明确提示“Stop 未执行”，不会假报已停止或断开 Host。

打开新版 Settings，准备经过校验的 Rust 程序，然后选择 **迁移到 Rust 后端** 并明确确认。迁移核对安装归属、现有配置、SSH 规则、网关指纹及原 daemon 绑定；保存 schema 4 配置并移除不再使用的 `dependency_dir` 字段，不更换凭据或服务器身份。迁移不自动连接；完成后显式连接。

旧版私有 Python、依赖及回退源码包保留，但新版不会执行它们。不要按目录名直接递归删除；确认无运行进程、其他安装或回退需求后再清理。旧 `.path` 链接安装需通过有归属校验的迁移，Tern `--force` 本身不能覆盖链接。

## 操作与状态

| 命令 | 行为 |
|---|---|
| Connect configured Host via TURN TLS / UDP | 经专用网关连接；不自动直连回退。 |
| Settings | 配置、明确确认的旧版迁移、更新、卸载。 |
| Restore configured Host to direct | 显式恢复原地址及身份，不停止其他窗口或 SSH 使用的共享后台。 |
| Stop TURN for ALL windows and SSH TCP sessions | 撤销自动恢复意图并停止共享后台，会中断经本机 TCP 入口的 SSH，不终止远端程序。 |
| Status | 查询模式、原生 Host、SSH TCP、流量、队列、恢复状态及脱敏错误。 |

状态栏流量按 1024 换算，是本次后台累计字节而非速率。历史丢包不等于当前拥塞。详情页可滚动、重复查询复用同一页。`ready` 表示后台就绪，不能替代原生 Host 已连接的验证；旧 `status.json` 也不是进程存活证明。

已成功建立的网关遇到明确的可恢复网络故障时，会按 2、5、15、30 秒退避，之后每 30 秒继续尝试，不因旧重试次数耗尽而永久停机。每次重连仍重新核验原 daemon 和网关身份；Stop 会取消等待及正在进行的连接。首次启动尚未建立连接时仍有启动期限。认证、指纹、权限、哈希、未知协议或无法可靠分类的错误仍停止，不自动放行。详情中的“最近网关故障阶段”保留脱敏诊断；它是历史原因，不代表当前仍未恢复。

TURN 临时凭据续发与 allocation 续期分别处理。现有连接和预热连接在凭据到期前准备替代分配，旧连接仍有效时继续传输，替代分配验证成功后再切换；凭据已经失效时停止使用旧连接，等待有效凭据恢复，不延长旧凭据的本地到期时间。明确的网络超时、限流和服务暂时不可用按有界频率重试；授权、证书、响应格式和本地凭据安全错误继续失败关闭。详情分别显示现有连接与缓存凭据的到期时间，缓存已更新不代表全部连接已完成切换。

### 远端 daemon 已明确重启后的恢复

先执行 **Stop**，更新插件并准备新版运行时，再打开 Settings → **恢复：审核重启后的 daemon**。阅读新旧 PID、启动时间、socket、网关指纹和备份位置；再次打开 Settings，明确选择「确认重绑」。成功后手动选择原来的 TURN TLS 或 UDP 连接。

审核与应用之间身份发生变化会拒绝提交，必须重新审核。该操作不重启 daemon、不修改凭据或证书、不自动启动连接；普通 Start 仍拒绝未知 daemon 身份变化。不要删除 `daemon-identity.json` 绕过检查。Tern 自身冷启动可能重建终端并自动恢复任务，重绑不保证原进程存活，也不修复其多客户端布局同步。


## 路径与安全约束

本机 Tern → loopback UDP → Cloudflare TURN → 认证封装网关 → 远端 loopback Tern frontend → **原 session daemon**。

- 专用 frontend 使用独立身份，仅绑定回环地址并关闭中继。启动前有界查询已核验 Tern 的版本；0.9.12 及以上使用 `--relay none`，旧版同时显式关闭 Iroh 和 pkarr。原服务身份保留，只有明确 Restore 才走原地址。
- 公网网关验证每次 SSH 控制会话的密钥、方向、flow 和重放窗口；拒绝裸 QUIC。控制通道失效后销毁旧代流量与密钥，旧数据不会跨代转发。
- Linux 远端始终核验 UNIX socket、SO_PEERCRED、daemon PID、进程启动时间、系统启动标识、可执行文件路径、参数、所有权与权限。同一进程/socket 上的 Tern 就地升级允许可执行文件 inode 改变，或新增一个规范绝对路径的 `--handoff` 参数对；其他参数与身份变化拒绝自动改绑。Windows 本机控制使用私有 ACL 与实时进程身份，不把旧状态文件或陈旧 PID 当作停止授权。
- TLS 验证证书和主机名。证书、授权、未知协议及身份错误失败关闭，不作为网络抖动无限重试。
- 已建立的 TURN 分配按有效期续期，以单调时钟约束真实到期时间；过期分配不继续转发。可恢复故障只重建受影响 flow；网关恢复单独处理，并重新核验原工作区。
- 单 flow 上行队列最多 64 包 / 256 KiB，最多 16 条 flow；记录丢弃并保留健康连接。单次连接、flow 重试、冷却、闲置回收和 Stop 取消均有界；已建立网关的可恢复重连采用有上限的退避间隔，不设永久失败次数上限。
- 同一本机端口上的 TCP 独立转发到原 SSH 服务，**SSH 不经过 TURN**。通过 HostKeyAlias 验证原主机身份，不改远端 authorized_keys。忽略 OpenSSH 配置的第三方 SSH 实现不在保证范围内。

TURN 不是普通 HTTP CDN。Rust 的原型测量显示进程内存和分发体积更小，但没有证明 RTT 更低或吞吐始终更高；不要把本版当作跨境延迟保证。

## 私有数据

以 Settings 检查和 Status 详情实际显示的插件数据路径为准；默认 profile 常见位置如下（自定义 profile 不共用数据）：

| 系统 | 路径 |
|---|---|
| macOS | `~/Library/Application Support/Tern/plugin-data/tern-turn-relay/` |
| Linux | 默认数据目录为 `~/.local/state/tern/plugin-data/tern-turn-relay/`（遵循 `XDG_STATE_HOME`）；插件代码位于 `~/.config/tern/plugins/tern-turn-relay/`。`TERN_CONFIG_DIR` 自定义 profile 的数据位于该 profile 的 `plugin-data/` |
| Windows | 默认数据目录为 `%LOCALAPPDATA%\Tern\plugin-data\tern-turn-relay\`；插件代码位于 `%APPDATA%\Tern\plugins\tern-turn-relay\`，两者不是同一个目录。自定义 profile 以 Tern 实际传入并经核验的路径为准 |

- `credentials/cloudflare.json`：Unix 使用目录 0700、文件 0600 的私有明文文件；Windows 保存用户级 DPAPI 密文，同时保留私有文件 DACL。Windows 密文不能直接复制给另一用户使用；旧明文文件不会静默加载，需在 Settings 显式重新配置，取消时保留原文件。输入文件仍须满足私有文件要求。
- `native-runtime/0.5.10/`：经版本、大小和 SHA-256 校验的本机程序（Windows 为 `tern-turn-relay.exe`）与发行清单，以及按需下载的 Linux helper。
- `config.json`、`installation.json`：非秘密配置及安装归属。
- `runtime/`：生命周期锁、原生控制入口、状态和恢复意图。不要自行删除锁或按 PID/进程名杀进程来绕过检查。
- Windows 私有资源在创建时使用当前用户、SYSTEM 与 Administrators 的受保护 DACL；本机仅接受规范的盘符绝对路径，远端路径仍为 POSIX。原子比较并替换使用 TxF 内核事务写锁、事务内私有暂存文件、`MoveFileTransacted` 与提交，避免检查后同名替换造成丢失更新；不采用「检查后 rename」或「先删除再重写」降级。
- Windows 采用局部保护：信任当前用户的 Tern 与插件安装环境，宿主、普通数据目录及祖先目录不因额外写权限而硬失败，也不自动修改这些目录的 ACL。专用运行时、凭据目录和控制通道仍使用局部访问控制；路径类型、对象身份、内容校验及审核后更改检测继续保留。**DPAPI 不能抵御当前用户权限被攻陷，或能修改 Tern 插件代码的本机进程。** Settings 会明确提示这一信任边界。
- Windows 系统组件存在严格限定的硬链接例外：仅限 `GetSystemDirectoryW` 返回的 System32 子树内 `.exe` / `.com`，所有者必须为 SYSTEM、Administrators 或 TrustedInstaller，DACL 禁止包括当前用户在内的非系统主体写入，祖先仍固定并拒绝 reparse point。所有私有文件及用户目录中的程序仍拒绝硬链接。
- TxF 及其支持的文件系统是上述写入保证的必要前提；不支持时失败关闭。普通读取、锁和程序校验仍保留各自的句柄保护。兼容限制与弃用状态参见微软的 [TxF 编程注意事项](https://learn.microsoft.com/en-us/windows/win32/fileio/programming-considerations-for-transacted-fileio-) 和 [TxF 弃用说明](https://learn.microsoft.com/en-us/windows/win32/fileio/deprecation-of-txf)。

凭据不进入 Luau、命令参数、环境变量、日志或公开 JSON。临时 TURN 凭据和网关会话密钥只存在于可信进程内存及匿名管道。自定义 Tern profile 默认使用自己的 SSH 规则文件；已有安装保留记录中的规则归属。

## 更新、卸载与自动化

在 Settings → 插件管理明确确认更新或卸载；两者都要求后台已停止。更新仅使用固定项目仓库。卸载先核验文件与 SSH 标记规则的所有权，用户修改过的资源不会被静默删除；保留配置、凭据、旧运行环境、远端网关身份和原 daemon。

Windows 更新/卸载以文件身份校验后的注册目录移动完成。卸载解除注册并撤销自有 SSH 标记块，但将完整安装包保留到插件数据目录的 `retained-packages/`；返回 `installed_package_preserved`，不递归删除未知内容。保留包不是仍启用的插件；确认没有回退或归属需求前不要手工清除。

Tern 自带删除插件仅移除插件目录，不执行本项目的 SSH 规则清理。删除本地凭据与在 Cloudflare 撤销 Key 是独立操作，不包含在卸载中。

自动化使用同一原生二进制的 `onboarding`、`credentials` 和 `relay` 子命令；秘密仅通过 stdin/私有文件传递。完整顺序见 [Agent 配置指南](docs/agent-setup.md)。不再提供 Python CLI 兼容入口。

## 构建与发布

优先使用已有远端构建环境或 GitHub Actions，避免在高内存压力机器上编译：

```sh
cargo test --locked --manifest-path native/Cargo.toml
cargo build --release --locked --manifest-path native/Cargo.toml
```

CI 在各自原生 runner 执行 macOS arm64/x86_64、静态 Linux arm64/x86_64、Windows x86_64 MSVC 的 Rust 行为测试和发行程序 `--version`、`--help`、smoke。每个平台的 `collect` 会执行实际程序核验版本与架构，并生成绑定目标、版本、大小和 SHA-256 的 `.receipt.json`。汇总清单和源码打包都重新核对五份记录及最终资产，拒绝旧版本、缺失记录或收集后被修改的文件。

将五个平台产物与对应收集记录汇总到同一目录后执行：

```sh
python tools/release.py manifest .artifacts/release release.json
python tools/release.py package dist --assets .artifacts/release
```

打包工具不自行上传或发布。源码归档包含 Rust 源码、Cargo.lock、Luau UI、两种 bootstrap、测试、许可和打包工具，不包含私有配置、凭据、运行目录、依赖缓存或验收截图。

### 验收边界

自动化测试不等于真实 Cloudflare/Tern 连接验收。本版本的发布记录应分别列出五平台 CI、Windows 原生安装/Settings/隐藏输入/ACL、TLS 与 UDP 真实 Host 连接、Stop/Restore/升级卸载、原远端 daemon 与会话保留证据。没有对应记录的场景不能视为已通过；Windows ARM64 不在本次覆盖范围。维护者不能仅凭后台 `ready` 宣称原生 Host 已连接，也不能用 macOS 或 Linux 编译代替 Windows 真机验收。

Windows 真机验收已验证：隐藏输入后向 Cloudflare 签发短期凭据、DPAPI 加密保存、TURN TLS 精确 Host 连接与双向流量、原远端 daemon 和会话保留、停止入口后恢复 TLS。当前测试网络的 TURN UDP 分配超时并失败关闭，未回退直连；不能据此声明 UDP 真实连接通过。Windows 后台启动同时验证了启动器及时返回与后台继续存活，而非仅检查一次 `ready`。
