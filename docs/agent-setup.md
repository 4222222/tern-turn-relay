# Agent 原生配置与迁移指南

普通用户走 README 的 Tern 原生安装与设置向导。本指南用于获授权的自动化；不读取浏览器凭据，不创建或共享 Cloudflare Key。执行前检查磁盘、内存与现有连接，复用现有安装。

## 入口与秘密边界

新版唯一运行入口是经固定 SHA-256 校验的 Rust 原生程序，没有 Python 兼容脚本。默认程序位于插件数据目录 `native-runtime/0.5.10/tern-turn-relay`；Windows 为 `native-runtime/0.5.10/tern-turn-relay.exe`。不要执行 PATH 中的同名 helper，也不要将 Linux 资产用于 Windows 本机。Linux 本机与远端 helper 使用同一份静态 Linux 资产。

Linux 本机：默认 profile 为 `$XDG_CONFIG_HOME/tern`（默认 `~/.config/tern`），插件数据为 `$XDG_STATE_HOME/tern/plugin-data/tern-turn-relay`（默认 `~/.local/state/tern/plugin-data/tern-turn-relay`）；`TERN_CONFIG_DIR` profile 的数据位于该 profile 的 `plugin-data/`。需要调用 Tern CLI 的步骤（apply、update、uninstall）从 `/proc` 读取启动本程序的 Tern 进程路径，不搜索 PATH；不是由 Tern 插件启动时（例如在 shell 中运行自动化），必须显式传 `--tern` 绝对路径，否则失败关闭。

只在用户明确准备运行环境时，从已安装插件执行：

```sh
/bin/sh "$PACKAGE/bootstrap-runtime.sh" "$DATA" --prepare
```

Windows 10/11 x64 使用系统可信执行器与明确脚本路径；下例中的路径变量不含秘密，调用运算符逐个传递参数，支持空格与中文：

```powershell
& "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PACKAGE\bootstrap-runtime.ps1" "$DATA" --prepare
```

Windows `report`（或省略模式）只验证已安装的运行时；`--exec COMMAND ...` 只执行通过大小/散列/权限校验的程序，不下载。`--prepare` 下载固定仓库的固定版本 HTTPS 资产，受时限、大小、私有 stage 和原子目录发布约束。显式 Stop 可为旧版迁移准备缺失的控制程序；普通状态查询和加载不能触发准备。不要把 PowerShell 作为持续转发器。

核对返回的 `binary` 位于预期私有版本目录。普通查询不得触发下载；插件加载本身也不准备运行环境。

插件中的所有实际命令通过平台 `--exec` 包装器重新验证后执行。下文 `BINARY ...` 表示原生命令及参数形态；自动化实际执行也应通过对应 bootstrap 的 `--exec ...`，不能仅凭路径存在或先前校验结果直启可能已改变的程序。`report`/`--exec` 不下载；只有明确准备操作和兼容旧后台的显式 Stop 可进入 `--prepare`。

未配置加载不访问 Cloudflare。已配置安装只有在既有持久恢复授权、相同配置和精确 loopback Host 均存在时才能恢复后台，不自动添加或切换 Host；Stop 必须撤销恢复意图。实时查询失败时状态应为未知或不可用，不回读陈旧 `status.json` 冒充存活。

长期 Key 和临时凭据均不得放入 argv、环境变量、聊天、日志、报告或公开 JSON。自动化配置凭据使用匿名 stdin 管道或已有私有明文输入文件（Unix 0600；Windows 当前用户及必要可信系统身份的受保护 DACL）；原生向导使用系统隐藏输入。新凭据先远程验证，再原子替换。Windows 持久化使用用户级 DPAPI，返回 `storage: windows-dpapi-user`；Unix 仍为 `private-file`。替换和删除需要明确授权；取消保留原文件。Windows 旧明文或其他用户无法解密的凭据需显式重新配置，不自动覆盖。

Windows 信任现有 Tern 插件环境：不要求收紧宿主或普通数据目录的额外 ACL，不修改整个 Tern 目录权限。只有专用运行时、私有资源及 IPC 保留局部保护。用户级加密不防御已控制当前用户或能修改插件代码的本机进程；不得将这一模型描述为对宿主篡改的隔离。

## 已有配置优先

调用 `BINARY onboarding inspect --data-dir DATA --package-dir PACKAGE`，stdin 为 `{}`。读取 configured、credential_configured、running、migration_required、registration、readiness 和路径信息，不根据旧状态文件猜测后台存活。自定义 profile 或尚未注册的验证目录必须显式传 `--config-dir PROFILE`；不跨 profile 推断全局归属。

若 migration_required：

1. 告知 Stop 会中断共享 TURN 和入口 TCP SSH，但保留远端程序。
2. 经用户授权执行 `BINARY relay stop --config CONFIG --state-dir RUNTIME`。核对 stopped 且恢复意图已撤销；不要依据陈旧 PID 杀进程。
3. 调用 `BINARY onboarding migrate ...`，stdin `{"confirm":true}`。核验 schema3→4、原目标/网关指纹/daemon socket/凭据路径及 SSH 规则归属保留。
4. 迁移不自动连接。只有获授权后显式 start；旧 Python 运行环境保留且不再被调用。

迁移拒绝身份或所有权变化时，查明差异，不删除持久绑定、网关身份或锁来绕过校验。

## 新配置顺序

1. 安装原生插件并显式准备本机运行程序。
2. 用户通过 Cloudflare 控制台创建自己的 TURN Key。只接受 TURN-key API token，不接受账户管理 Token，不代过 MFA 或服务条款。
3. 导入并验证凭据；已配置时优先复用。
4. 调用 `BINARY onboarding discover ...`，stdin `{"ssh_destination":"my-server"}`。必要时带整数 listen_port；返回 choose 时用返回的 candidate_id 再次 discover。远端是 `tern remote serve --user` 且 daemon 独立启动（不是服务子进程）时无法按进程关系关联，choose 的候选为空；经用户确认后带 `"daemon_socket":"/run/user/<uid>/tern/daemon.sock"` 这类绝对路径再次 discover。远端 helper 仍核验 socket 属主、SO_PEERCRED、进程启动时间与参数，review 会保留该字段供 apply 重新发现。
5. discovery 将经过校验的架构匹配 Rust helper 放入远端私有缓存，用它只读核验服务。它不部署/启动另一个 session daemon；不要声称完全不写远端磁盘。
6. 完整展示 review：目标、工作区、独立网关目录、入口端口、配置与 SSH 文件、旧配置摘要及更改清单。
7. 获批后调用 apply，stdin `{"review":完整原样对象,"authorize_replace":已获替换授权}`。保留 JSON null；不自行拼改审核对象。后端重新发现并比较，变化时重新审核，不能重复提交旧 review。
8. 配置成功不等于连接成功。经授权调用 `BINARY relay start --config CONFIG --state-dir RUNTIME --mode tls`；用户明确选择时才用 udp。
9. 验证后台 ready、原生精确 Host 已连接、真实回流；检查原 daemon 与会话仍在。日志、抓包与截图须先避免或脱敏秘密。

## 故障与管理

- `relay status` 为实时控制查询；保存的状态文件不能证明进程存活。
- 证书、授权、身份、本地凭据安全和未知协议错误失败关闭。临时 TURN 凭据到期由连接轮换处理；明确的续发网络错误、HTTP 429/5xx 按有界频率重试，不因此终止仍有效的连接。不得延长旧凭据有效期、加直连兜底或关闭校验。
- 共享 Stop 撤销恢复意图；Restore 仅恢复明确选择的原 Host，不等同于停止后台。
- update/uninstall 走 onboarding，stdin `{"confirm":true}`，要求后台已停止。固定源更新；保留用户改动的文件和 SSH 规则。
- 卸载不删除 Key、不撤销云端 Key、不关闭原 daemon。清理遗留运行环境前验证进程、安装、链接与回退引用。

### 显式 daemon 重绑

仅在用户明确授权接受已重启的 daemon 时使用。先 `relay stop` 撤销恢复意图，再调用 `onboarding rebind-review --data-dir DATA --package-dir PACKAGE`，stdin 为 `{}`。完整展示返回的 `review`：原服务与网关指纹、旧新进程身份、socket、文件身份和旧绑定备份路径。

获授权后调用 `onboarding rebind-apply`，stdin 为 `{"review":完整原样对象,"confirm":true}`。不得自行拼改审核对象。后端重新验证配置摘要、原服务、当前 daemon 和身份文件，并要求旧 daemon 已退出；审核变化、活动网关、不安全权限或未知身份均拒绝。旧绑定安全备份后才原子替换；成功不会自动连接，需显式 start 并验证实际 Host。保留原证书、凭据与 SSH 配置，不删除旧 pin 绕过失败。

- 交付记录版本、CI/真实场景证据、安装路径、仍在运行的进程及保留资源，不公开私有配置或会话密钥。

## Windows 发布验收

- 原生 OpenSSH Client 必须来自系统目录，公钥登录与 known_hosts 已核验；禁止通过 PATH、WSL 或 Git Bash 替代可信执行器。
- 测试空格/中文 profile、普通宿主目录含额外 ACL 时仍可运行且权限不变、专用运行时的局部保护、junction/reparse point、硬链接、路径穿越/ADS/UNC、下载失败、并发准备和损坏资产；失败应保留已有配置与凭据。
- 系统 PowerShell 等 Windows 组件可以具有系统维护的硬链接；例外仅限原生 `GetSystemDirectoryW` 所指 System32 子树内 `.exe` / `.com`，必须核验 SYSTEM/Administrators/TrustedInstaller 所有权及禁止所有非系统主体写入的 DACL。祖先固定与 reparse 拒绝不放宽，私有文件和用户目录程序仍拒绝硬链接。
- Windows 原子 CAS 依赖启用 TxF 的本地 NTFS：在内核事务写锁保护下创建私有暂存文件、调用 `MoveFileTransacted` 并提交，拒绝同名替换交错造成的丢失更新。验收须包含确定性交错测试；不得以最终文件 ID 重查加普通 rename 代替事务保证，不得先删旧值或删除重写降级。
- ReFS、FAT、网络卷、EFS 加密文件或 TxF 不可用时必须失败关闭。微软已弃用 TxF，未来可能移除，发布与系统升级时均需确认实际兼容性；参见 [编程限制](https://learn.microsoft.com/en-us/windows/win32/fileio/programming-considerations-for-transacted-fileio-) 与 [弃用说明](https://learn.microsoft.com/en-us/windows/win32/fileio/deprecation-of-txf)。
- 五个平台分别运行实际二进制测试。使用 `python tools/release.py manifest ASSET_DIR release.json` 生成真实五资产清单；合并所有目标的依赖许可，不遗漏 Windows crates。归档不能带占位散列。
- 发布前记录 Windows 真机 Tern 0.9.8 Settings、隐藏凭据输入、真实 TLS/UDP 精确 Host、共享 Stop、Restore 不停止其他窗口、更新/卸载归属检查及原远端 daemon/会话不变证据。若未执行或无凭据，应明确写「未验证」，不能写成通过。
