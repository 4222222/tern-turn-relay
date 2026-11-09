-- Native, window-owned onboarding. Secrets never enter this VM or its snapshots.
local M = {}
local LIMIT = 65536
local ABOUT = "tern-turn-relay setup review"
local function plain(value)
    return tostring(value or "—"):gsub("[%c]", " "):gsub("[\\`*_<>|%[%]]", "\\%0")
end

function M.new(api, host)
    local tern = host or tern
    local self = { active = false }
    local epoch = 0
    local menu, inspect, chooseServer, discover, review
    local platform = require('./platform').new(tern.runtime, tern.plugin, tern.getenv)
    local binary = platform.binary
    local queue = require('./work-queue').new({ now = tern.now, timer = tern.timer },
        function(token) return token == epoch end,
        function(cx)
            self.active = false
            api.failed("设置操作已中断，请重新打开设置检查实际结果。")
            if cx then cx:toast("error", "TURN 设置已中断", "重新打开设置检查实际结果；不会自动重试配置变更。") end
        end)

    local function finish()
        self.active = false
        epoch += 1
        queue:wake()
    end
    local function fail(cx, message)
        finish()
        api.failed(message)
        if cx then cx:toast("error", "TURN 设置", message) end
    end
    local function pick(cx, title, items, callback)
        local token = epoch
        local receipt = queue:wait(token, 600000, function(result, fresh, timedOut)
            if result and result.error then fail(fresh, "选择窗口不可用，请重新打开设置。"); return end
            if timedOut or not result or result.answer == nil then finish(); return end
            callback(result.answer, fresh)
        end)
        cx:pick({ placeholder = title, items = items, action = "选择" }):next(function(answer, err, _cx)
            receipt({ answer = answer, error = err })
            queue:wake()
        end)
    end
    local function run(cx, argv, input, timeout, callback)
        local token = epoch
        local receipt = queue:wait(token, timeout + 3000, function(result, fresh, timedOut)
            if timedOut or (result and result.timed_out) then
                fail(fresh, "操作超时，结果未知。请重新打开设置检查；不会自动重试。")
                return
            end
            if not result or result.launchFailed or type(result.stdout) ~= "string" or #result.stdout > LIMIT then
                fail(fresh, "无法读取设置助手结果，请重新打开设置检查运行环境。")
                return
            end
            local ok, value = pcall(tern.json.decode, result.stdout)
            if not ok or type(value) ~= "table" or type(value.ok) ~= "boolean" then
                fail(fresh, "设置助手未返回有效结果；配置结果未知。")
                return
            end
            if not value.ok or result.status ~= 0 then
                if value.code == "cancelled" then finish(); return end
                local message = type(value.error) == "string" and value.error or "设置失败，请检查 SSH 与运行环境。"
                if value.code == "stopped-required" then
                    message = "连接仍在运行。先执行 TURN: Stop（会中断所有窗口及经插件入口的 SSH），再重新打开设置。"
                end
                fail(fresh, message)
                return
            end
            callback(value, fresh)
        end)
        local ok = pcall(function()
            tern.process.run(argv, { stdin = tern.json.encode(input), timeout_ms = timeout }, function(result, _cx)
                receipt(result)
                queue:wake()
            end)
        end)
        if not ok then receipt({ launchFailed = true }); queue:wake() end
    end
    local function backend(cx, action, input, callback)
        local argv = { "onboarding", action,
            "--data-dir", tern.plugin.data, "--package-dir", tern.plugin.dir }
        run(cx, platform.bootstrap("--exec", argv), input, action == "configure-credentials" and 330000 or ((action == "apply" or action == "update" or action == "migrate" or action == "discover" or action == "rebind-review" or action == "rebind-apply") and 240000 or 60000), callback)
    end
    local function credentials(cx, snapshot)
        local replacing = snapshot.credential_present == true or snapshot.credential_configured == true
        pick(cx, replacing and "替换现有 Cloudflare TURN Key？" or "配置自己的 Cloudflare TURN Key", {
            { label = replacing and "验证后替换" or "输入并验证", value = "configure",
                detail = platform.windows and "系统隐藏输入；Windows 用户级 DPAPI 加密保存；将向 Cloudflare 验证，费用由自己的账户承担" or "系统隐藏输入；本机私有文件保存；将向 Cloudflare 签发短期凭据验证，流量费用由自己的账户承担" },
            { label = "返回", value = "back" },
        }, function(answer, fresh)
            if answer.value == "back" then menu(snapshot, fresh); return end
            fresh:toast("info", "在系统安全输入窗口中填写 Key", "请使用 TURN-key API token，不是账户 Token；取消不会覆盖已有凭据。")
            backend(fresh, "configure-credentials", { replace = replacing }, function(_value, current) inspect(current) end)
        end)
    end
    review = function(value, cx)
        local plan = value.review
        if type(plan) ~= "table" or type(plan.configuration) ~= "table" then
            fail(cx, "服务器检查未返回可审核的配置。"); return
        end
        -- Luau drops JSON-null members; restore every reviewed absence sentinel.
        for _, field in ipairs({ "previous_config_sha256", "installation_sha256", "ssh_config_sha256" }) do
            if plan[field] == nil then plan[field] = tern.json.null end
        end
        local config = plan.configuration
        local target, gateway = config.target or {}, config.gateway or {}
        local rows = {
            "# TURN 配置确认", "", "仅在下一步选择「确认应用」后写入配置并部署专用网关。不会自动停止现有连接或切换 Host。", "",
            "| 项目 | 目标 |", "| --- | --- |",
            "| SSH 别名 | " .. plain(plan.ssh_destination) .. " |",
            "| 服务器 | " .. plain(target.user) .. "@" .. plain(target.host) .. ":" .. plain(target.port) .. " |",
            "| 原服务身份 | " .. plain(target.fingerprint) .. " |",
            "| 原状态目录 | " .. plain(plan.original_state_dir) .. " |",
            "| 复用 daemon socket | " .. plain(gateway.daemon_socket) .. " |",
            "| 独立网关目录 | " .. plain(gateway.state_dir) .. " |",
            "| 本机入口 | 127.0.0.1:" .. plain(config.listen_port) .. " |",
            "| SSH 规则文件 | " .. plain(plan.paths and plan.paths.ssh_config) .. " |",
            "| 私有凭据文件 | " .. plain(config.credential_file) .. " |", "", "## 将执行的变更",
        }
        for _, change in ipairs(plan.changes or {}) do table.insert(rows, "- " .. plain(change)) end
        table.insert(rows, "")
        table.insert(rows, "凭据保存在权限保护的本机文件中，不是 Keychain；不会显示秘密。保留原服务与工作区，连接失败不回退直连。")
        local found = false
        for _, pane in ipairs(cx.canvas:list()) do
            if pane.owner == "tern-turn-relay" and pane.about == ABOUT then
                cx.canvas:set(pane.pane, { md = table.concat(rows, "\n") })
                cx.layout:focus(pane.pane)
                found = true
                break
            end
        end
        if not found then
            local pane = cx.canvas:open({ title = "TURN 配置确认", about = ABOUT, md = table.concat(rows, "\n"), how = "tab" })
            if not pane then fail(cx, "无法显示配置审核，未应用任何更改。"); return end
        end
        self.reviewed = value
        finish()
        api.reviewChanged()
        cx:toast("info", "请阅读完整配置确认页", "阅读后点击「TURN · 确认配置」，或再次打开 TURN Settings，确认应用或取消。")
    end
    local function confirmReview(cx)
        local plan = self.reviewed.review
        pick(cx, "确认配置 " .. plan.configuration.target.user .. "@" .. plan.configuration.target.host, {
            { label = "确认应用", value = "apply", detail = "部署专用网关、保存配置及作用域限定的 SSH 规则；不更改原服务" },
            { label = "重新选择服务器", value = "choose" },
            { label = "取消，不应用", value = "cancel" },
        }, function(answer, current)
            self.reviewed = nil
            api.reviewChanged()
            if answer.value == "cancel" then finish(); return end
            if answer.value == "choose" then inspect(current); return end
            current:toast("info", "正在应用 TURN 配置", "正在校验依赖、SSH 身份与原工作区；请等待结果。")
            backend(current, "apply", { review = plan, authorize_replace = plan.previous_config_sha256 ~= nil and plan.previous_config_sha256 ~= tern.json.null },
                function(_result, applied)
                    api.configured()
                    applied:toast("success", "TURN 配置已保存", "可以从本机或对应服务器 Host 连接 TLS；配置本身不会切换连接。")
                    inspect(applied)
                end)
        end)
    end
    discover = function(cx, alias, candidate, port, socket)
        cx:toast("info", "正在检查服务器", "仅通过已信任 SSH 读取原服务、daemon 与实际监听端口。")
        local input = { ssh_destination = alias }
        if candidate then input.candidate_id = candidate end
        if port then input.listen_port = port end
        if socket then input.daemon_socket = socket end
        backend(cx, "discover", input, function(value, fresh)
            if value.code == "review" then review(value, fresh); return end
            if value.code ~= "choose" or type(value.candidates) ~= "table" then
                fail(fresh, "没有找到可验证的已有 Tern 服务；请先确保原服务正常运行。"); return
            end
            if #value.candidates == 0 then
                if socket then fail(fresh, "指定的 daemon socket 未通过核验；请确认它属于原服务使用的 daemon。"); return end
                -- `tern remote serve --user` with an independently started daemon cannot be
                -- paired by process parentage; the user names the socket and the remote
                -- helper still pins its owner, peer credentials and process identity.
                pick(fresh, "没有可自动关联的已有 Tern 服务", {
                    { label = "指定远端 daemon socket", value = "socket", detail = "适用于独立启动 daemon 的 tern remote serve --user，例如 /run/user/<uid>/tern/daemon.sock；仍核验属主与进程身份" },
                    { label = "取消", value = "cancel" },
                }, function(answer, current)
                    if answer.value ~= "socket" then finish(); return end
                    local receipt = queue:wait(epoch, 600000, function(result, later, timedOut)
                        if timedOut or not result or result.answer == nil then finish(); return end
                        if result.error or type(result.answer) ~= "string" or result.answer:sub(1, 1) ~= "/" or #result.answer > 4096 then
                            fail(later, "请输入远端 daemon socket 的绝对路径。"); return
                        end
                        discover(later, alias, nil, port, result.answer)
                    end)
                    current:prompt({ placeholder = "远端 daemon socket 绝对路径", action = "检查" }):next(function(answerText, err, _cx)
                        receipt({ answer = answerText, error = err })
                        queue:wake()
                    end)
                end)
                return
            end
            local items = {}
            for _, item in ipairs(value.candidates) do
                table.insert(items, { label = item.label, detail = item.detail, value = item.id })
            end
            pick(fresh, "选择要复用的已有 Tern 工作区", items, function(answer, current) discover(current, alias, answer.value, port, socket) end)
        end)
    end
    chooseServer = function(snapshot, cx, port)
        if not snapshot.credential_configured then
            cx:toast("info", "先配置 Cloudflare TURN Key", "凭据验证通过后才能应用服务器配置。")
            credentials(cx, snapshot)
            return
        end
        local items = {}
        for _, alias in ipairs(snapshot.ssh_aliases or {}) do
            table.insert(items, { label = alias.label, value = alias.value, detail = "已有 OpenSSH 别名；下一步严格验证" })
        end
        table.insert(items, { label = "输入其他 SSH 别名", value = false, detail = "必须已经可通过公钥登录且已核验主机密钥" })
        pick(cx, "选择服务器", items, function(answer, fresh)
            if answer.value then discover(fresh, answer.value, nil, port); return end
            local receipt = queue:wait(epoch, 600000, function(result, current, timedOut)
                if timedOut or not result or result.answer == nil then finish(); return end
                if result.error or type(result.answer) ~= "string" or #result.answer == 0 or #result.answer > 253 then
                    fail(current, "请输入有效的现有 SSH 别名。"); return
                end
                discover(current, result.answer, nil, port)
            end)
            fresh:prompt({ placeholder = "已有 SSH 别名，例如 my-server（不要输入密码）", action = "检查" }):next(function(answerText, err, _cx)
                receipt({ answer = answerText, error = err })
                queue:wake()
            end)
        end)
    end
    local function manage(snapshot, cx)
        pick(cx, "TURN 插件管理 · 配置和凭据保留", {
            { label = "更新插件", value = "update", detail = "从 github.com/jiwangyihao/tern-turn-relay 重新安装最新默认分支；会重载插件" },
            { label = "卸载插件", value = "uninstall", detail = platform.windows and "解除注册并撤销自有 SSH 规则；完整包保留至 retained-packages，配置和凭据保留" or "移除本机插件和本插件管理的 SSH 规则；保留凭据、配置、远端服务及工作区" },
            { label = "返回", value = "back" },
        }, function(answer, fresh)
            if answer.value == "back" then menu(snapshot, fresh); return end
            if snapshot.registration ~= "native" then
                fail(fresh, "旧版链接安装需先通过服务器配置确认页迁移为原生安装。"); return
            end
            local removing = answer.value == "uninstall"
            pick(fresh, removing and "确认卸载本机 TURN 插件？" or "确认从固定官方仓库更新？", {
                { label = removing and "确认卸载（保留私有数据）" or "确认更新并重载", value = "confirm",
                    detail = "运行中的连接不会被自动停止；请先显式 Stop。远端原服务和工作区不变。" },
                { label = "取消", value = "cancel" },
            }, function(consent, current)
                if consent.value ~= "confirm" then menu(snapshot, current); return end
                current:toast("info", removing and "正在卸载 TURN 插件" or "正在更新 TURN 插件", "成功后插件将重载或移除，当前设置窗口可能关闭；配置与凭据保留。")
                backend(current, answer.value, { confirm = true }, function(result, completed)
                    finish()
                    completed:toast("success", "TURN 插件管理完成", result.installed_package_preserved and "已解除注册；完整安装包保留在私有 retained-packages。配置、凭据和远端服务均保留。" or "配置、凭据和远端原服务均保留。")
                end)
            end)
        end)
    end
    local function reviewRebind(cx)
        backend(cx, "rebind-review", {}, function(value, fresh)
            local plan = value.review
            local remote = type(plan) == "table" and plan.remote
            if type(remote) ~= "table" or type(remote.old_identity) ~= "table" or type(remote.new_identity) ~= "table" then
                fail(fresh, "助手未返回完整的 daemon 身份审核；未更改绑定。")
                return
            end
            local rows = {
                "# TURN daemon 重绑确认", "",
                "仅用于你明确重启过远端 daemon 的情况。普通连接仍拒绝身份变化；不会停止或启动远端程序。", "",
                "| 项目 | 已核验值 |", "| --- | --- |",
                "| 原 daemon PID | " .. plain(remote.old_identity.pid) .. " |",
                "| 新 daemon PID | " .. plain(remote.new_identity.pid) .. " |",
                "| 原启动时间 | " .. plain(remote.old_identity.start_time) .. " |",
                "| 新启动时间 | " .. plain(remote.new_identity.start_time) .. " |",
                "| daemon socket | " .. plain(remote.new_identity.daemon_socket) .. " |",
                "| 网关目录 | " .. plain(remote.state_dir) .. " |",
                "| 网关指纹（保留） | " .. plain(remote.gateway_fingerprint) .. " |",
                "| 旧绑定备份 | " .. plain(remote.backup_path) .. " |", "",
                "确认时会重新核验全部身份；审核后有变化则拒绝。保留凭据、证书和 SSH 配置；成功后需手动连接。",
            }
            local pane = fresh.canvas:open({ title = "TURN daemon 重绑确认", about = ABOUT .. " daemon", md = table.concat(rows, "\n"), how = "tab" })
            if not pane then fail(fresh, "无法显示 daemon 审核；未更改绑定。"); return end
            self.rebindReviewed = plan
            finish()
            fresh:toast("info", "请阅读 daemon 重绑确认页", "再次打开 TURN Settings 后确认或取消；尚未修改身份绑定。")
        end)
    end
    local function confirmRebind(cx)
        local plan = self.rebindReviewed
        pick(cx, "确认接受已核验的新 daemon？", {
            { label = "确认重绑", value = "apply", detail = "备份旧绑定并核验后更新；不修改凭据，不自动连接" },
            { label = "取消，不修改绑定", value = "cancel" },
        }, function(answer, current)
            self.rebindReviewed = nil
            if answer.value ~= "apply" then finish(); return end
            backend(current, "rebind-apply", { review = plan, confirm = true }, function(_value, completed)
                finish()
                api.configured()
                completed:toast("success", "daemon 重绑完成", "旧绑定已备份；请选择原来的 TURN TLS 或 UDP 连接。")
            end)
        end)
    end
    menu = function(snapshot, cx)
        local target = snapshot.current_target
        local configured = snapshot.configured == true
        local items = {
            { label = configured and "重新选择服务器" or "选择服务器并配置", value = "server",
                detail = type(target) == "table" and (target.name or target.host or "已有配置") or "自动发现原服务、工作区与监听端口" },
            { label = snapshot.credential_configured and "更换 Cloudflare TURN Key" or "配置 Cloudflare TURN Key", value = "credentials",
                detail = snapshot.credential_reconfigure_required and "已有凭据需重新配置为当前 Windows 用户的加密存储；原文件保留，替换需确认" or (snapshot.credential_configured and "已有私有凭据；不会显示其内容" or "系统隐藏输入、验证成功后保存") },
        }
        if snapshot.migration_required then
            table.insert(items, 1, { label = "迁移到 Rust 后端", value = "migrate", detail = "先 Stop；保留 Key、服务器身份、原 daemon 和 SSH 规则；不自动连接" })
        end
        if configured then
            if not snapshot.migration_required then table.insert(items, 1, { label = "连接 TURN TLS", value = "connect", detail = "从本机或对应服务器 Host 连接；不切换无关 Host，不回退直连" }) end
            table.insert(items, { label = "查看连接详情", value = "status" })
            if not snapshot.migration_required then
                table.insert(items, { label = "恢复：审核重启后的 daemon", value = "rebind", detail = "先 Stop；核验新旧身份，确认后备份并重绑，不自动连接" })
            end
        end
        table.insert(items, { label = "高级：自定义本机端口", value = "port", detail = "仅在默认 18377 被占用时使用；更改将显示在配置确认页" })
        table.insert(items, { label = "插件管理：更新 / 卸载", value = "manage", detail = "原生安装管理，保留配置与凭据" })
        table.insert(items, { label = "关闭设置", value = "close" })
        pick(cx, snapshot.running and "TURN 设置 · 连接运行中，修改前需先 Stop" or "TURN 设置", items, function(answer, fresh)
            if answer.value == "server" then chooseServer(snapshot, fresh)
            elseif answer.value == "credentials" then credentials(fresh, snapshot)
            elseif answer.value == "manage" then manage(snapshot, fresh)
            elseif answer.value == "rebind" then reviewRebind(fresh)
            elseif answer.value == "migrate" then
                pick(fresh, "确认迁移现有配置到 Rust 后端？", {
                    { label = "确认迁移", value = "confirm", detail = "连接必须已停止；保留现有凭据、身份与工作区，旧运行环境不自动删除" },
                    { label = "取消", value = "cancel" },
                }, function(consent, current)
                    if consent.value ~= "confirm" then menu(snapshot, current); return end
                    backend(current, "migrate", { confirm = true }, function(_result, completed)
                        api.configured()
                        inspect(completed)
                    end)
                end)
            elseif answer.value == "port" then
                local receipt = queue:wait(epoch, 600000, function(result, current, timedOut)
                    if timedOut or not result or result.answer == nil then finish(); return end
                    local port = type(result.answer) == "string" and result.answer:match("^%d+$") and tonumber(result.answer)
                    if result.error or not port or port < 1024 or port > 65535 then
                        fail(current, "本机端口必须是 1024–65535 的整数。"); return
                    end
                    chooseServer(snapshot, current, port)
                end)
                fresh:prompt({ placeholder = "本机 UDP/TCP 入口端口", value = "18377", action = "继续选择服务器" }):next(function(answerText, err, _cx)
                    receipt({ answer = answerText, error = err })
                    queue:wake()
                end)
            elseif answer.value == "connect" then finish(); api.connect(fresh)
            elseif answer.value == "status" then finish(); api.status(fresh)
            else finish() end
        end)
    end
    inspect = function(cx)
        backend(cx, "inspect", {}, function(snapshot, fresh) api.inspected(); menu(snapshot, fresh) end)
    end
    function self.open(cx)
        if self.active then cx:toast("info", "TURN 设置已打开", "请完成当前选择或按 Esc 取消。"); return end
        if not platform.supported then cx:toast("error", "当前向导支持 macOS、Linux x86_64/arm64 与 Windows 10/11 x64"); return end
        if not api.available() then cx:toast("info", "连接操作仍在进行", "请等待结果后再打开设置。"); return end
        self.active = true
        epoch += 1
        if platform.windows then
            cx:toast("info", "Windows 局部保护", "信任当前 Tern 插件环境，不修改宿主目录权限；凭据使用用户级加密。能改写插件代码的本机程序仍可获取凭据。")
        end
        if self.reviewed then confirmReview(cx); return end
        if self.rebindReviewed then confirmRebind(cx); return end
        -- Only an explicit setup action can acquire a runtime; plugin loading never downloads.
        cx:toast("info", "正在准备 TURN 设置", "首次使用将下载并校验插件私有 Rust 程序；无需 Python 或本机编译。")
        run(cx, platform.bootstrap("--prepare"), {}, 320000,
            function(value, fresh)
                if not platform.ready(value) then fail(fresh, "运行环境版本、状态或路径不符合插件私有目录约束。"); return end
                api.runtimeReady(binary)
                inspect(fresh)
            end)
    end
    return self
end
return M
