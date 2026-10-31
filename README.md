# Tern TURN Relay

为 macOS Tern 提供 Cloudflare TURN 专用连接入口。复用远端已有 session daemon，不修改 Tern 二进制、原服务或系统路由；连接失败不会自动退回直连。采用 [MPL-2.0](LICENSE)。

## 支持范围与前提

- 本机 macOS arm64 或 x86_64、Tern 0.9.8。无需自行安装或操作 Python；首次打开设置会准备插件私有的 CPython 3.13.9。
- 远端 Linux、Python 3.9+、已运行的 Tern 用户服务与 session daemon（已验证 Tern 0.9.6、0.9.8）。远端 Python 仍是前提，但用户不需要手动执行部署脚本。
- 已配置并核验主机密钥的 OpenSSH 别名，能够非交互公钥登录。当前要求 HostName 为公网 IPv4，不支持 ProxyJump/ProxyCommand、IPv6 或直接填域名。
- 用户自己的 Cloudflare Realtime TURN Key。插件不附带共享凭据，不读取浏览器登录状态；流量费用由所用 Cloudflare 账户承担，请先查看官方计费规则。
- 原生窗口插件仅支持 macOS；没有宣称跨平台 GUI 支持。此项目不是 Tern 或 Cloudflare 官方产品。

## 安装

在 **Tern → Preferences → Plugins → Install…** 中填写：

```text
github.com/jiwangyihao/tern-turn-relay
```

也可以只运行一次 Tern 原生命令：

```sh
tern plugin install github.com/jiwangyihao/tern-turn-relay
```

安装只注册插件，不要求预先生成配置，不访问 Cloudflare，不部署远端网关，也不自动切换服务器。GitHub 安装需要系统有 Git；没有 Git 时，从 [Releases](https://github.com/jiwangyihao/tern-turn-relay/releases) 下载并校验源码归档，解压后在 Install… 中选择包含 `plugin.toml` 的目录。

### 首次配置

1. 在命令面板选择 **TURN → Settings: server, Cloudflare Key and private runtime**；如果显示状态栏，也可以点击 **TURN · 待配置**。
2. 向导自动下载、校验并准备插件私有 Python。使用固定发行版及 SHA-256，不安装系统级软件、不需要管理员权限；仅显式打开设置时准备，插件加载本身不会下载。首次准备需要联网，并要求至少 1 GiB 可用空间。
3. 选择 **配置 Cloudflare TURN Key**。先在 [Cloudflare Realtime 控制台](https://dash.cloudflare.com/?to=/:account/calls) 创建自己的 TURN Key，再在系统隐藏输入窗口填写 **Key ID** 和 **TURN-key API token**。不要填写账户级 API Token。验证成功后才保存；取消或验证失败不会覆盖已有凭据。
4. 选择已有 SSH 别名。向导通过严格 SSH 检查已有服务、daemon 和实际 UDP 监听端口；发现多个可验证工作区时列出供选择，不要求抄写路径或指纹。
5. 阅读无遮挡的 **TURN 配置确认** 页，核对目标、原工作区、网关目录、本机端口及 SSH 规则文件。然后点击状态栏的 **TURN · 确认配置**（或再次打开 Settings），选择 **确认应用**。这一步安装依赖、部署专用网关并保存配置，不启动第二套 session daemon。
6. 选择 **连接 TURN TLS**。可以从本机 Host 或对应服务器 Host 发起；拒绝切换无关远端 Host，失败不自动回退直连。

已配置的凭据和目标会被识别并复用。运行中不自动停止连接来修改配置；需要更改时先显式 Stop（会中断共享入口上的连接）。默认本机端口为 `18377`；确有冲突时使用 **高级：自定义本机端口**，新端口会显示在确认页。

### 凭据与配置保存位置

默认凭据文件：

```text
~/Library/Application Support/Tern/plugin-data/tern-turn-relay/credentials/cloudflare.json
```

目录权限 0700、文件权限 0600；原子写入，不跟随符号链接或接受硬链接。**这是权限保护的本地文件，不是 Keychain 加密存储。** 输入只经过系统隐藏输入进程、匿名管道和可信 helper 内存，不进入 Luau 状态、命令参数、环境变量、日志或公开结果。

运行环境位于同一插件数据目录的 `managed-python/`，与连接后台的 `runtime/` 分离。自定义 Tern profile 默认把 SSH 兼容规则写入该 profile 的插件数据目录 `ssh-config`，不改用户全局 SSH 配置；服务器认证仍使用原有 OpenSSH 别名。该独立规则文件不会自动作用于普通 `ssh` 调用，需要显式使用它。已有安装保留其记录的 SSH 规则归属。

自动化仍可使用统一的 `onboarding.py` JSON 接口和底层 CLI；这是 agent／开发者接口，不是普通用户安装步骤。参见 [Agent 配置指南](docs/agent-setup.md)。本版不提供 OAuth 登录、不创建共享 Cloudflare 账户或 Key。

## 操作与状态

| 命令 | 行为 |
| --- | --- |
| Connect configured Host via TURN TLS / UDP | 连接独立身份的专用入口，验证后切换；不自动直连回退。 |
| Settings: server, Cloudflare Key and private runtime | 原生配置向导：准备运行环境、配置 Key、选择服务器、审核变更、更新或卸载。 |
| Restore configured Host to direct | 显式恢复原地址及身份，不停止其他窗口使用的后台或 SSH。 |
| Stop TURN for ALL windows and SSH TCP sessions | 停止共享后台、撤销自动恢复意图；会中断经本地 TCP 入口的 SSH，但不结束远端程序。 |
| Status: TURN mode, native Host, SSH TCP, bytes and errors | 查询状态并打开可滚动详情；重复点击复用同一页。 |

状态栏示例：`TURN TLS · 已连接 · ↑3.5 MiB ↓241.8 MiB`。单位按 1024 换算，表示本次后台实例的累计流量，不是速率。后台停止时隐藏流量；异常与当前拥塞仅显示短提示。队列、flows、SSH、累计丢包、身份与完整错误在详情页。详情是查询快照，再次点击刷新；toast 不承载完整诊断。

连接使用原生 Host API，不打开连接对话框或自动信任未知身份。远端程序与历史会话仍属于原 daemon；Host 显示名可能变成本机入口地址。

## 专用路径与安全边界

路径：本机 Tern → loopback UDP → Cloudflare TURN → 认证封装网关 → 远端 loopback Tern frontend → 原 session daemon。

专用 frontend 使用独立身份并关闭 Iroh、relay 和 pkarr。公网网关拒绝裸 QUIC，验证每次 SSH 会话的密钥、方向、flow 与重放窗口。密钥只通过 SSH stdin 传递，不进入参数、日志或公开状态。原服务及其身份保留，只有显式 Restore 才回直连。

启动及运行中检查 socket、SO_PEERCRED、daemon 进程身份。控制通道失效时立即停止旧网关转发并销毁旧流密钥；可恢复的连接或心跳故障会有界重建控制链，重新核验指纹和原 daemon 身份，再创建新密钥及 TURN 分配。原 daemon 身份改变、未知协议错误或安全检查失败仍停止，不自动改绑、不删除身份记录、不重启原服务。

daemon 的工作区绑定使用 PID、进程启动时间、系统启动标识和 UNIX socket 身份，并核验可执行文件路径、角色参数、所有权及权限。同一进程／socket 上的 Tern 就地升级可以更换可执行文件 inode；inode 不再作为不可变工作区标识。旧记录仅在所有稳定绑定一致且当前可执行文件验证通过后迁移，其他身份变化仍拒绝。

长期 TURN Key 仅供本地可信 helper 使用，临时 TURN 凭据留在运行进程内存中。不要把本项目的私有配置、凭据、安装目录、运行状态或个人验收截图上传到仓库。

同一 loopback 端口的 TCP 独立转发到原 SSH 服务，**SSH 不经过 TURN**。安装器仅维护匹配配置用户、127.0.0.1 与精确端口的标记规则，继承原公钥配置并用 HostKeyAlias 校验原主机身份；不修改远端 authorized_keys。自行实现 SSH 且忽略 OpenSSH 配置的库不在兼容保证内。

## 故障处理

先点击详情，或使用安装输出给出的包／配置／runtime 路径执行 `relay.py status`。`ready` 只证明后台就绪，原生 Host 状态单独核验；旧 status.json 不是进程存活证明。

- 新 flow 的网络类 allocation 失败：等待 2 秒、5 秒后最多追加两次新分配尝试，仍只使用同一已验证网关。初次启动保留原有单次有界分配和总超时。
- TLS、授权或身份错误：不会作为瞬时网络错误自动重试，不会退回直连。检查证书、Key、账户权限或网关身份。
- 已建立分配的续期提前到有效期的一半，使用单调时钟约束真实到期时间；瞬时网络错误在剩余有效期内有限重试，过期后不继续收发。续期或传输确实失效时，只重建受影响的 flow，并保留认证流标识与重放窗口。
- 同一 flow 的分配尝试耗尽后，后续客户端流量可在共享 30 秒冷却后触发恢复；不会无限高速重试，也不会因恢复期间仍有流量而误判为闲置退出。健康 flow 不受影响。状态栏显示“恢复中”，详情列出恢复原因和成功续期次数。
- 网关控制链与 TURN 分配分别恢复。已验证连接的可恢复控制故障最多尝试 5 次重连，等待 2／5／15／30／30 秒；恢复前丢弃旧代的数据，不复用旧会话密钥或 codec。状态栏显示“网关恢复中”，详情保留脱敏故障分类与重连尝试次数。未知或安全类错误不自动重试，Stop 会取消重连。
- 授权、证书、网关身份等非瞬时错误仍停止并保留明确错误；修正原因后显式 Stop，再 Connect。不要凭陈旧 PID 文件杀进程。
- 更新／重启：仅在已附加精确入口、保存模式匹配时有界恢复后台。Stop 会撤销意图；没有无限自动重启。
- 历史丢包不代表当前拥塞。单 flow 队列限制为 64 包／256 KiB；最多 16 条 flow。超过容量时丢弃新流量并记录上行丢弃，不锁死整个后台；现有连接继续工作，空闲 flow 回收后可再次接入。TLS 有背压。

TURN 不是普通 HTTP CDN，也不保证优于直连的延迟、吞吐或可用性。

## 升级与卸载

在 **TURN Settings → 插件管理** 中选择更新或卸载，随后明确确认。两项操作都要求连接已停止，不会代替用户执行 Stop。

- **更新**：仅从固定仓库 `github.com/jiwangyihao/tern-turn-relay` 通过 Tern 原生安装器重新安装默认分支，随后重载插件。保留配置、凭据和运行环境，不自动重新连接；Tern 本身不比较版本，也没有自动更新服务。
- **卸载**：验证本机安装所有权，移除原生插件及未被用户修改的自有 SSH 标记规则；保留私有配置、凭据、运行环境、远端网关身份和原 daemon。未配置的原生插件也可从同一入口卸载。
- **旧版链接安装**：Tern 的 `--force` 不能覆盖 `.path` 链接。更新到带向导的包后，在服务器配置确认页显式迁移；或由 agent 使用新版本 `install.py --migrate-native` 完成一次性迁移。迁移保留原配置、凭据及旧源码包，失败时分别恢复注册、配置和 SSH 规则。不要直接删除旧目录。

普通原生安装也可使用 `tern plugin install github.com/jiwangyihao/tern-turn-relay --force` 更新。直接用 Tern 删除插件只删除插件本体，不执行本项目的 SSH 规则清理；完整卸载应走设置入口。

删除本地凭据与撤销 Cloudflare Key 是独立操作，均不包含在卸载中。Agent 可在用户明确授权后使用 `credentials.py remove-local`；云端撤销需要用户在 Cloudflare 中操作。彻底清理保留数据前应核查其他窗口和安装引用，不能递归盲删。

## 验证与打包

```sh
python3 -m unittest discover -s tests -v
python3 package_release.py --output-dir dist
```

包由显式文件清单生成，包含 MPL 许可、代码、说明及离线测试，不包含 `.artifacts`、`.sdk`、私有配置、凭据、依赖或运行目录。归档可复现，附 SHA-256。打包不会自动上传或发布。

本项目源码受 Mozilla Public License, v. 2.0 约束。依赖仍遵循各自许可；安装时从其发布源获取，未把本机依赖副本打包。
