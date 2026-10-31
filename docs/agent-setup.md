# Agent 原生配置与迁移指南

普通用户走 README 的 Tern 原生安装与设置向导。本指南用于获授权的自动化；不读取浏览器凭据，不创建或共享 Cloudflare Key。执行前检查磁盘、内存与现有连接，复用现有安装。

## 入口与秘密边界

新版唯一运行入口是经固定 SHA-256 校验的 `tern-turn-relay` 原生程序，没有 Python 兼容脚本。默认程序位于插件数据目录 `native-runtime/0.4.0/tern-turn-relay`。

只在用户明确准备运行环境时，从已安装插件执行：

```sh
/bin/sh "$PACKAGE/bootstrap-runtime.sh" "$DATA" --prepare
```

核对返回的 `binary` 位于预期私有版本目录。普通查询不得触发下载；插件加载本身也不准备运行环境。

长期 Key 和临时凭据均不得放入 argv、环境变量、聊天、日志、报告或公开 JSON。自动化配置凭据使用匿名 stdin 管道或已有的 0600 私有输入文件；原生向导使用系统隐藏输入。新凭据先远程验证，再原子替换。替换和删除需要明确授权；取消保留原文件。

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
4. 调用 `BINARY onboarding discover ...`，stdin `{"ssh_destination":"my-server"}`。必要时带整数 listen_port；返回 choose 时用返回的 candidate_id 再次 discover。
5. discovery 将经过校验的架构匹配 Rust helper 放入远端私有缓存，用它只读核验服务。它不部署/启动另一个 session daemon；不要声称完全不写远端磁盘。
6. 完整展示 review：目标、工作区、独立网关目录、入口端口、配置与 SSH 文件、旧配置摘要及更改清单。
7. 获批后调用 apply，stdin `{"review":完整原样对象,"authorize_replace":已获替换授权}`。保留 JSON null；不自行拼改审核对象。后端重新发现并比较，变化时重新审核，不能重复提交旧 review。
8. 配置成功不等于连接成功。经授权调用 `BINARY relay start --config CONFIG --state-dir RUNTIME --mode tls`；用户明确选择时才用 udp。
9. 验证后台 ready、原生精确 Host 已连接、真实回流；检查原 daemon 与会话仍在。日志、抓包与截图须先避免或脱敏秘密。

## 故障与管理

- `relay status` 为实时控制查询；保存的状态文件不能证明进程存活。
- 证书、凭据、身份和未知协议错误失败关闭。不得加直连兜底或关闭校验。
- 共享 Stop 撤销恢复意图；Restore 仅恢复明确选择的原 Host，不等同于停止后台。
- update/uninstall 走 onboarding，stdin `{"confirm":true}`，要求后台已停止。固定源更新；保留用户改动的文件和 SSH 规则。
- 卸载不删除 Key、不撤销云端 Key、不关闭原 daemon。清理遗留运行环境前验证进程、安装、链接与回退引用。
- 交付记录版本、CI/真实场景证据、安装路径、仍在运行的进程及保留资源，不公开私有配置或会话密钥。
