# Tern TURN Relay

为 macOS Tern 提供 Cloudflare TURN 专用连接入口。复用远端已有 session daemon，不修改 Tern 二进制、原服务或系统路由；连接失败不会自动退回直连。采用 [MPL-2.0](LICENSE)。

## 支持范围与前提

- 本机 macOS、Tern 0.9.8、`/usr/bin/python3`（已验证 Python 3.9）。
- 远端 Linux、Python 3.9+、已运行的 Tern 用户服务与 session daemon（已验证 Tern 0.9.6）。
- 已配置并核验主机密钥的 OpenSSH 别名，能够非交互公钥登录。当前要求 HostName 为公网 IPv4，不支持 ProxyJump/ProxyCommand、IPv6 或直接填域名。
- 用户自己的 Cloudflare Realtime TURN Key。插件不附带共享凭据，不读取浏览器登录状态；流量费用由所用 Cloudflare 账户承担，请先查看官方计费规则。
- 原生窗口插件仅支持 macOS；没有宣称跨平台 GUI 支持。此项目不是 Tern 或 Cloudflare 官方产品。

## 安装

从 [Releases](https://github.com/jiwangyihao/tern-turn-relay/releases) 下载源码归档及 `.sha256` 文件，在同一目录执行 `shasum -a 256 -c <校验和文件>`，解压后进入源码目录。也可以克隆本仓库。

### 1. 创建并配置自己的 TURN Key

在 [Cloudflare Realtime 控制台](https://dash.cloudflare.com/?to=/:account/calls) 选择自己的账户并创建 TURN Key，取得 **Key ID** 与对应的 **TURN-key API token**。

运行：

```sh
python3 credentials.py configure
python3 credentials.py status
python3 credentials.py check
```

`configure` 在终端隐藏输入，验证一次真实的短期凭据签发后才保存；不要把秘密放进命令参数、聊天或截图。`check` 会请求一份短期凭据并丢弃，只输出脱敏结果；`status` 只检查本地配置。

默认保存在：

```text
~/Library/Application Support/Tern/plugin-data/tern-turn-relay/credentials/cloudflare.json
```

目录权限 0700、文件权限 0600，原子写入，不跟随符号链接或接受硬链接。**这是权限保护的本地文件，不是 Keychain 加密存储。** 验证失败不会覆盖已有凭据。已有文件需交互确认，非交互覆盖必须显式 `--replace`。

账户级 API Token 与 TURN-key API token 不同：前者用于创建 Key，后者用于签发连接凭据，不能混用。有关让 agent 帮助创建和配置 Key，参见 [Agent 配置指南](docs/agent-setup.md)。本版没有 OAuth 登录入口。

### 2. 发现已有服务器并生成配置

将 `my-server` 换成已经可用的 SSH 别名：

```sh
python3 setup.py --ssh-destination my-server --discover
python3 setup.py --ssh-destination my-server \
  --output "$HOME/Library/Application Support/Tern/plugin-data/tern-turn-relay/setup-config.json"
```

发现通过严格 SSH 执行只读检查，验证原服务身份、已有 daemon socket、用户及路径，不启动第二套 session daemon，不自动接受未知 SSH 主机密钥。`--discover` / `--dry-run` 输出脱敏 JSON，不写配置。

如果服务器运行多个服务／daemon，或原监听端口未明确出现在进程参数中，必须根据服务器实际情况补充 `--original-state-dir`、`--daemon-socket`、`--target-port`。不要复制其他人的路径或指纹。可用 `--credential-file` 指定自己的私有凭据文件；`--listen-port` 默认 18377。

`config.example.json` 是说明文件，故意不能直接运行；真实指纹必须由发现流程取得。

### 3. 安装并连接

```sh
python3 install.py --config "$HOME/Library/Application Support/Tern/plugin-data/tern-turn-relay/setup-config.json"
```

安装器会：

1. 复用版本匹配的依赖，否则在插件私有目录安装精确固定版本；不覆盖不兼容依赖目录。
2. 将源码复制到插件数据目录中的内容寻址安装包，原解压目录删除后仍可运行。
3. 经已有 SSH 自动部署远端小型 helper，创建独立服务身份，确认它仍连接原 daemon。
4. 保存私有运行配置、安装所有权记录和精确作用域的 SSH 兼容规则，再链接 Tern 插件。

安装不会自动切换 Host。选中原服务器 Host，在命令面板的 `TURN` 分组执行 **Connect configured Host via TURN TLS**。

## 操作与状态

| 命令 | 行为 |
| --- | --- |
| Connect configured Host via TURN TLS / UDP | 连接独立身份的专用入口，验证后切换；不自动直连回退。 |
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

从新版本源码目录运行以下命令。先恢复直连并 Stop，避免安装时中断仍在使用的共享后台：

```sh
python3 install.py
```

升级默认保留已有配置和凭据，拒绝替换正在运行的后台。需要换配置时使用 `--config ... --replace-config`。安装包按内容保留旧版本；激活失败会尝试恢复插件链接、配置和 SSH 规则。

```sh
python3 uninstall.py
```

卸载验证安装所有权，停止自有后台、解除插件链接，并且仅删除未被用户修改的标记 SSH 规则。配置、凭据、安装包及远端私有身份保留；原 daemon 不动。删除本地凭据是独立操作：

```sh
python3 credentials.py remove-local
```

这不会撤销 Cloudflare Key；云端撤销需用户在 Cloudflare 中明确操作。保留数据用于恢复，彻底清理前应核查其他窗口和安装引用，不能递归盲删。

## 验证与打包

```sh
python3 -m unittest discover -s tests -v
python3 package_release.py --output-dir dist
```

包由显式文件清单生成，包含 MPL 许可、代码、说明及离线测试，不包含 `.artifacts`、`.sdk`、私有配置、凭据、依赖或运行目录。归档可复现，附 SHA-256。打包不会自动上传或发布。

本项目源码受 Mozilla Public License, v. 2.0 约束。依赖仍遵循各自许可；安装时从其发布源获取，未把本机依赖副本打包。
