# Tern TURN Relay

为 macOS Tern 提供 **Rust 原生 Cloudflare TURN 专用连接入口**。复用 Linux 服务器已有的 session daemon，不修改 Tern 二进制、原服务、系统路由或远端工作区；连接失败不自动退回直连。采用 [MPL-2.0](LICENSE)，依赖许可见 [第三方声明](THIRD_PARTY_NOTICES.txt)。不是 Tern 或 Cloudflare 官方产品。

## 支持范围

- 本机：macOS Apple Silicon / Intel，Tern 0.9.8。
- 远端：Linux x86_64 / arm64，已有 Tern 用户服务与 session daemon。
- 本机和远端均不需要 Python、Cargo、系统级安装或本机编译。构建工具中的 Python 仅用于维护者打包和 CI，不属于运行时。
- 已核验 SSH 主机密钥的 OpenSSH 别名，可非交互公钥登录；HostName 为公网 IPv4。ProxyJump、ProxyCommand、IPv6 和域名目标不在支持范围内。
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

安装只注册插件。插件加载不下载程序、不访问 Cloudflare、不部署网关、不自动选择服务器。没有 Git 时，从 [Releases](https://github.com/jiwangyihao/tern-turn-relay/releases) 下载源码归档，核验 SHA-256，解压后在 Install… 选择含 `plugin.toml` 的目录。

1. 打开 **TURN → Settings: server, Cloudflare Key and private runtime**。首次显式打开设置时，下载与插件版本一致的 Rust 程序，验证固定 SHA-256 和大小，存入私有目录；需要至少 256 MiB 空闲空间。
2. 选择 **配置 Cloudflare TURN Key**。先在 [Cloudflare Realtime 控制台](https://dash.cloudflare.com/?to=/:account/calls) 创建自己的 TURN Key，再通过系统隐藏输入窗口填写 Key ID 和 **TURN-key API token**，不要填写账户级 API Token。验证成功后保存；取消或验证失败保留原凭据。
3. 选择已有 SSH 别名。插件按远端架构下载并验证 Linux Rust helper，通过严格 SSH 放入远端私有缓存，再只读检查原服务、daemon 和实际 UDP 监听端口。不会启动第二个 session daemon；多个工作区可供选择。
4. 阅读 **TURN 配置确认** 页，核对目标、工作区、网关目录、本机端口及 SSH 规则文件，再点击状态栏 **TURN · 确认配置**，选择 **确认应用**。
5. 选择 **连接 TURN TLS**。允许从本机 Host 或对应服务器 Host 发起；拒绝切换无关远端 Host，不自动回退直连。

默认本机 UDP/TCP 端口为 `18377`。确有冲突时在 **高级：自定义本机端口** 修改，新端口会显示在确认页。更改运行中的配置前必须显式 Stop，向导不会擅自中断连接。

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

## 路径与安全约束

本机 Tern → loopback UDP → Cloudflare TURN → 认证封装网关 → 远端 loopback Tern frontend → **原 session daemon**。

- 专用 frontend 使用独立身份，关闭 Iroh、relay 和 pkarr。原服务身份保留，只有明确 Restore 才走原地址。
- 公网网关验证每次 SSH 控制会话的密钥、方向、flow 和重放窗口；拒绝裸 QUIC。控制通道失效后销毁旧代流量与密钥，旧数据不会跨代转发。
- 始终核验 UNIX socket、SO_PEERCRED、daemon PID、进程启动时间、系统启动标识、可执行文件路径、参数、所有权与权限。同一进程/socket 上的 Tern 就地升级允许可执行文件 inode 改变；其他身份变化拒绝自动改绑。
- TLS 验证证书和主机名。证书、授权、未知协议及身份错误失败关闭，不作为网络抖动无限重试。
- 已建立的 TURN 分配按有效期续期，以单调时钟约束真实到期时间；过期分配不继续转发。可恢复故障只重建受影响 flow；网关恢复单独处理，并重新核验原工作区。
- 单 flow 上行队列最多 64 包 / 256 KiB，最多 16 条 flow；记录丢弃并保留健康连接。重试、冷却、闲置回收和 Stop 取消均有界。
- 同一本机端口上的 TCP 独立转发到原 SSH 服务，**SSH 不经过 TURN**。通过 HostKeyAlias 验证原主机身份，不改远端 authorized_keys。忽略 OpenSSH 配置的第三方 SSH 实现不在保证范围内。

TURN 不是普通 HTTP CDN。Rust 的原型测量显示进程内存和分发体积更小，但没有证明 RTT 更低或吞吐始终更高；不要把本版当作跨境延迟保证。

## 私有数据

默认插件数据目录：

```text
~/Library/Application Support/Tern/plugin-data/tern-turn-relay/
```

- `credentials/cloudflare.json`：Cloudflare Key，目录 0700、文件 0600，原子更新，拒绝符号链接与硬链接。**这是权限保护文件，不是 Keychain 加密存储。**
- `native-runtime/0.4.0/`：经校验的本机 Rust 程序、发行清单，以及按需下载的 Linux helper。
- `config.json`、`installation.json`：非秘密配置及安装归属。
- `runtime/`：生命周期锁、控制 socket、状态和恢复意图。

凭据不进入 Luau、命令参数、环境变量、日志或公开 JSON。临时 TURN 凭据和网关会话密钥只存在于可信进程内存及匿名管道。自定义 Tern profile 默认使用自己的 SSH 规则文件；已有安装保留记录中的规则归属。

## 更新、卸载与自动化

在 Settings → 插件管理明确确认更新或卸载；两者都要求后台已停止。更新仅使用固定项目仓库。卸载先核验文件与 SSH 标记规则的所有权，用户修改过的资源不会被静默删除；保留配置、凭据、旧运行环境、远端网关身份和原 daemon。

Tern 自带删除插件仅移除插件目录，不执行本项目的 SSH 规则清理。删除本地凭据与在 Cloudflare 撤销 Key 是独立操作，不包含在卸载中。

自动化使用同一原生二进制的 `onboarding`、`credentials` 和 `relay` 子命令；秘密仅通过 stdin/私有文件传递。完整顺序见 [Agent 配置指南](docs/agent-setup.md)。不再提供 Python CLI 兼容入口。

## 构建与发布

优先使用已有远端构建环境或 GitHub Actions，避免在高内存压力机器上编译：

```sh
cargo test --locked --manifest-path native/Cargo.toml
cargo build --release --locked --manifest-path native/Cargo.toml
```

CI 构建 macOS arm64/x86_64 和静态 Linux arm64/x86_64。`tools/release.py` 生成依赖许可、固定资产清单和可复现源码归档；构建工具不会自行上传或发布。源码归档包含 Rust 源码、Cargo.lock、Luau UI、许可和打包工具，不包含私有配置、凭据、运行目录、依赖缓存或验收截图。
