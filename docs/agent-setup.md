# 让 Agent 帮助创建和配置 Cloudflare TURN Key

适用场景：首次安装、已有 Key 导入、凭据失效检查、凭据替换。先阅读仓库 README 的支持范围，再按下列步骤执行。本版采用用户自有 Key，不提供 OAuth 登录，也不共享发布方的长期令牌。

## 用户可以直接发送给 Agent

> 请按这个仓库的 docs/agent-setup.md 帮我配置 Tern TURN Relay。先检查本机和已有 SSH 别名；如果我还没有 Cloudflare TURN Key，指导我在自己的账户创建，或在我明确授权后通过官方 API 创建。秘密只通过隐藏输入或私有文件进入程序，不进入聊天、命令参数和日志。使用已有 daemon，不另建工作区。验证完整连接后告诉我保存了什么、如何撤销和卸载。

## 1. 只读预检

运行各入口的 `--help`，然后 `credentials.py status`。该命令输出是否配置、私有存储路径和退出码，不显示 Key ID 或 token，也不调用 Cloudflare。

运行 `setup.py --ssh-destination <用户已有别名> --discover`。SSH 主机密钥必须已核验，禁止自动接受未知主机、复制他人的指纹或取消严格校验。存在多个原服务或 daemon 时，先读服务器进程及 socket 证据，再提供 `--original-state-dir`、`--daemon-socket`、`--target-port`，不能猜一个可能正确的工作区。

完成标准：确认支持的平台、目标账户／服务器和已有 daemon；缺少 Key 时进入第 2 步，有 Key 时进入第 3 步。配置错误时不启动服务、不修改账户。

## 2. 创建 Key：两条受控路径

### 控制台路径（默认）

1. 打开 [Cloudflare Realtime 控制台](https://dash.cloudflare.com/?to=/:account/calls)。用户自行完成登录和 MFA。
2. 确认所选账户、Key 名称、用途以及账户可能承担的 TURN 流量费用。**创建前取得用户对该账户和操作的明确确认。** 不代替用户接受条款、开通付费功能或修改账单。
3. 在该账户的 TURN 管理页面创建专用 Key。界面名称可能变化；以当前官方界面和 [官方创建说明](https://developers.cloudflare.com/realtime/turn/generate-credentials/) 为准。
4. 用户直接把 Key ID 和 TURN-key API token 输入 `python3 credentials.py configure` 的隐藏提示。不要复制到聊天或保存含秘密的屏幕截图。

### 官方 API 路径（用户明确授权时）

创建接口为 `POST https://api.cloudflare.com/client/v4/accounts/{account_id}/calls/turn_keys`，JSON 请求体可为 `{"name":"tern-turn-relay"}`。需要该账户范围的 **Calls Write** API Token。权限名和返回结构以 [官方 API](https://developers.cloudflare.com/api/resources/calls/subresources/turn/methods/create/) 为准。

账户 API Token 只用于创建；成功响应中的 `result.uid` 是 TURN Key ID，`result.key` 是之后签发临时凭据所需的 TURN-key token。两者不能混淆。

由 agent 编排 API 请求时，必须满足：

- 创建前向用户展示账户标识、Key 名称、操作和费用归属，获得确认；只使用用户授权的账户级 token。
- 账户 token 用进程内隐藏输入或用户指定的私有文件读取。禁止把秘密插值进 shell 命令、环境转储、工具调用参数、HTTP 调试日志或模型上下文。
- 固定官方 HTTPS 主机并验证 TLS，禁用重定向；响应有大小和时间上限。捕获响应后直接在进程内映射为下述 legacy JSON，通过子进程 stdin 交给 `credentials.py configure --stdin`；禁止先输出整个创建响应。
- 创建请求超时或连接丢失时，结果未知，先核查账户中的 Key，不盲目重试创建。
- 如果云端已创建、但本地验证／保存失败，报告这个事实及非秘密的 Key 标识。不要继续创建更多 Key，也不要未经确认自动撤销。
- 本版没有 `create-key` CLI。agent 可以用有凭据保护能力的官方集成执行上述 API，或指导用户使用控制台；不能声称仓库中存在该命令。

完成标准：成功创建用户账户中的专用 Key，或明确确认使用其已有 Key。没有权限时说明缺少哪项授权，不尝试读取浏览器 Cookie 或其他应用的 token。

## 3. 安全导入与验证

人类终端流程：

```sh
python3 credentials.py configure
python3 credentials.py check
```

已有私有 JSON 文件可直接导入，agent 只需传路径，不读取或显示正文：

```sh
python3 credentials.py configure --input-file /absolute/private/source.json
```

文件结构是 `provider`（值为 `cloudflare`）、`turn_key_id` 和 `api_token` 三个字段。`api_token` 必须是该 TURN Key 的令牌，而非账户 API Token。源文件必须属于用户、0600、非符号链接、非硬链接，目录祖先不得由其他用户写入。

密码管理器或可信创建进程也可将这份 JSON 通过管道传给 `python3 credentials.py configure --stdin`。不要用含真实 token 的 `echo` 命令、heredoc 或聊天片段构造输入。

配置会先实际签发一份 60 秒临时凭据，仅验证并丢弃，成功后原子保存长期 Key。默认目标是插件数据目录下的 `credentials/cloudflare.json`。已有文件覆盖需确认；非交互操作必须有用户授权并加 `--replace`。失败保留原文件。

存储是本地权限保护文件，不是加密 Keychain。长期 Key 不进入仓库、远端网关配置、状态栏或日志。正常运行的临时 TURN 凭据仅保留在本地 helper 内存中。

完成标准：`configure` 和 `check` 的脱敏 JSON 成功；只记录路径、是否验证、退出码。不得记录临时 TURN username/password 或长期 token。

## 4. 生成配置、安装和验证

按 README 执行 setup 和 install。使用发现得到的真实指纹；`config.example.json` 不能当作运行配置。安装之前如果后台正在运行，应向用户说明共享连接会受影响，再显式停止；不能为了安装偷偷杀进程。

切换必须使用插件原生命令，不打开原生连接对话框。验证至少包括：

- 后台实时状态 ready，原生 Host connected，出现实际双向转发；两种状态分开判断。
- 原 daemon 没有被替换，原 session/tab/pane 身份仍一致。
- 用户同意断路测试后，停止专用后台不会自动变成直连；原服务继续可用。
- 恢复并留下用户要求的连接状态。不要把一次成功当作长期 SLA 或更低延迟的证明。

## 5. 错误、撤销与交付

`credentials.py` 退出码：0 成功；2 输入／参数错误；3 未配置；4 隐藏终端输入不可用；5 Cloudflare 请求或响应验证失败；6 取消、缺少变更确认或并发修改；7 私有文件／存储错误；130 中断。遇到错误先读取脱敏说明，不把远端原始响应打印出来。

`remove-local` 仅移除本机凭据文件，不撤销 Cloudflare Key。云端撤销和账户 API Token 撤销是独立操作，必须明确授权。卸载保留配置、秘密、安装包和远端私有身份，便于恢复；不要递归删除共享目录。

交付时列出安装版本、运行状态、凭据保存位置、尚存限制、已执行的验证、仍运行的进程，以及如何升级／停止／卸载。无需包含任何秘密。
