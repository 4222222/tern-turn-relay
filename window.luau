local function install(tern)
-- Window-only: startup may resume an explicitly selected backend, never a native connection.
local platform = require('./platform').new(tern.runtime, tern.plugin, tern.getenv)
local configPath = tern.plugin.data .. "/config.json"
local stateDir = tern.plugin.data .. "/runtime"
local MAX_JSON = 16384
local POLL_MS = 3000
local CONNECT_MS = 45000
local STARTUP_MS = 30000
local HELPER_GRACE_MS = 2000
local STATUS_TIMEOUT_MS = 15000
local generation = 0
local busy = nil
local pending = nil
local timer = nil
local statusInFlight = false
local startup = nil
local startupTimer = nil
local startupSeen = false
local stopAfterResume = false
local alias = nil
local nativeState = "disconnected"
local lastError = nil
local cache = { state = "stopped", mode = nil, bytes_up = 0, bytes_down = 0, flows = 0, ssh_connections = 0,
    queued_packets = 0, queued_bytes = 0, queue_dropped_packets = 0, queue_dropped_bytes = 0, congested = false }
local statusText = "TURN · 已停止"
local schedule
local inspectNative
local disconnect
local runner
local failNative
local stepNative
local helperRequests = {}
local onboarding
local setupError
local nativeBinary = platform.binary
local helperReady = false
local hasConfig = false
do
    local ok, exists = pcall(tern.fs.exists, configPath)
    hasConfig = ok and exists
    local ready, installed = pcall(tern.fs.exists, nativeBinary)
    helperReady = ready and installed
    -- Existence is only a UI/preparation hint; every execution revalidates via bootstrap.
    if not hasConfig then statusText = "TURN · 待配置" elseif not helperReady then statusText = "TURN · 待升级" end
end

local function text(value, max)
    return type(value) == "string" and #value > 0 and #value <= max
end

local function count(value)
    return type(value) == "number" and value >= 0 and value < math.huge and value % 1 == 0
end

local function expiry(value)
    return type(value) == "number" and value >= 0 and value < math.huge
end

local function decode(raw)
    if type(raw) ~= "string" or #raw > MAX_JSON then
        return nil, "Helper response exceeds the 16 KiB limit."
    end
    local ok, value = pcall(tern.json.decode, raw)
    if not ok or type(value) ~= "table" or type(value.ok) ~= "boolean"
        or not ({ stopped = true, starting = true, ready = true, error = true })[value.state]
        or (value.mode ~= nil and value.mode ~= "tls" and value.mode ~= "udp")
        or (value.resume_mode ~= nil and value.resume_mode ~= "tls" and value.resume_mode ~= "udp")
        or not count(value.bytes_up) or not count(value.bytes_down) or not count(value.flows)
        or not count(value.ssh_connections)
        or not count(value.queued_packets) or not count(value.queued_bytes)
        or not count(value.queue_dropped_packets) or not count(value.queue_dropped_bytes)
        or (value.recovering_flows ~= nil and not count(value.recovering_flows))
        or (value.allocation_refreshes ~= nil and not count(value.allocation_refreshes))
        or (value.recovery_error ~= nil and not text(value.recovery_error, 4096))
        or (value.gateway_recovering ~= nil and type(value.gateway_recovering) ~= "boolean")
        or (value.gateway_reconnects ~= nil and not count(value.gateway_reconnects))
        or (value.gateway_failure_reason ~= nil and not text(value.gateway_failure_reason, 128))
        or (value.gateway_failure_message ~= nil and not text(value.gateway_failure_message, 4096))
        or type(value.congested) ~= "boolean"
        or (value.ssh_destination ~= nil and not text(value.ssh_destination, 256))
        or (value.relay_fingerprint ~= nil and not text(value.relay_fingerprint, 256))
        or (value.daemon_socket ~= nil and not text(value.daemon_socket, 4096))
        or (value.route_policy ~= nil and value.route_policy ~= "exclusive")
        or (value.error ~= nil and not text(value.error, 4096))
        or (value.service_id ~= nil and not text(value.service_id, 256))
        or (value.credentials_expires_at ~= nil and not expiry(value.credentials_expires_at))
        or (value.active_credentials_expires_at ~= nil and not expiry(value.active_credentials_expires_at))
        or (value.cached_credentials_expires_at ~= nil and not expiry(value.cached_credentials_expires_at)) then
        return nil, "Invalid helper status JSON; no native Host action was taken."
    end
    if value.target ~= nil then
        local t = value.target
        if type(t) ~= "table" or not text(t.name, 256) or not text(t.host, 256)
            or not text(t.user, 128) or not text(t.fingerprint, 256)
            or not count(t.port) or t.port < 1 or t.port > 65535 then
            return nil, "Invalid config-backed target in helper status."
        end
    end
    if value.address ~= nil then
        if not text(value.address, 256) then return nil, "Invalid helper loopback address." end
        local user, port = string.match(value.address, "^([%w_.-]+)@127%.0%.0%.1:(%d+)$")
        port = tonumber(port)
        if not value.target or not user or user ~= value.target.user or not port or port < 1 or port > 65535 then
            return nil, "Helper address is not the exact config-backed loopback alias."
        end
    end
    if value.state == "ready" and (not value.ok or not value.address or not value.target
        or not value.mode or not value.service_id or not value.relay_fingerprint
        or not value.daemon_socket or value.route_policy ~= "exclusive") then
        return nil, "Incomplete ready status; refusing native connection."
    end
    return value, nil
end

local BYTE_UNITS = { "B", "KiB", "MiB", "GiB", "TiB" }
local function bytes(value)
    local units = BYTE_UNITS
    local unit = 1
    while value >= 1024 and unit < #units do value /= 1024; unit += 1 end
    local rounded = math.floor(value * 10 + 0.5) / 10
    if rounded >= 1024 and unit < #units then value /= 1024; unit += 1 end
    return (unit == 1 and string.format("%.0f", value) or string.format("%.1f", value)) .. " " .. units[unit]
end

local function phaseLabel()
    if stopAfterResume or busy == "stop" then return "停止中" end
    if cache.gateway_recovering then return "网关恢复中" end
    if (cache.recovering_flows or 0) > 0 then return "恢复中" end
    if cache.state == "starting" and cache.recovery_error then return "等待重连" end
    if busy == "start" or busy == "resume" or cache.state == "starting" then return "启动中" end
    if cache.state == "error" then return "不可用" end
    if cache.state ~= "ready" then return "已停止" end
    if nativeState == "connected" then return "已连接" end
    if nativeState == "reconnecting" then return "重连中" end
    if nativeState == "connecting" or pending then return "连接中" end
    return "未连接"
end

local function refresh()
    statusText = "TURN" .. (cache.mode and " " .. string.upper(cache.mode) or "") .. " · " .. phaseLabel()
    if cache.state == "ready" then
        statusText ..= " · ↑" .. bytes(cache.bytes_up) .. " ↓" .. bytes(cache.bytes_down)
    end
    statusText ..= lastError and " · 异常" or (cache.congested and " · 拥塞" or "")
    tern.chrome.refresh()
end

local function report(cx, message)
    lastError = message:gsub("[%c]", " ")
    refresh()
    if cx then cx:toast("error", "TURN 异常", "点击状态栏查看详情") end
end

local function accept(value)
    local previousError = cache.error
    cache = value
    if value.address then alias = value.address end
    if value.error then lastError = value.error:gsub("[%c]", " ")
    elseif previousError and lastError == previousError:gsub("[%c]", " ") then lastError = nil end
end


local function supported(cx)
    if not platform.supported then
        report(cx, "当前客户端支持 macOS、Linux x86_64/arm64 与 Windows 10/11 x64；请从 Settings 显式准备私有运行时。")
        return false
    end
    return true
end

-- Process completions are receipts only. Parsing, UI and all Hosts operations run
-- in a new timer hook; neither process nor native callbacks retain their cx.
runner = require('./work-queue').new({ now = tern.now, timer = tern.timer },
    function(token) return token == false or token == generation end,
    function(cx, _message)
        if pending then
            -- A successor was armed before each native mutation. Do not replace
            -- reconciliation with failure merely because the hook was interrupted.
            report(cx, "Native step interrupted; queued reconciliation will inspect the actual Host state.")
            schedule()
        else
            busy = nil
            statusInFlight = false
            if cache.state == "starting" then cache.state = "error" end
            if stopAfterResume then
                stopAfterResume = false
                runner:post(false, function(fresh) disconnect(fresh) end)
            end
            report(cx, "A queued TURN operation failed. Its outcome is unknown; run Status.")
        end
    end)

local function helper(command, mode, token, _cx, callback)
    if not helperReady then
        if command ~= "stop" then
            callback(nil, "Open TURN Settings to prepare the verified native controller; no connection was changed.", _cx)
            return
        end
        if _cx then _cx:toast("info", "正在准备原生 Stop 控制程序", "仅此显式停止操作会准备缺失程序；校验失败会明确报告 Stop 未执行。") end
        local prepareTimeout = 320000
        local request = { token = token, deadline = tern.now() + prepareTimeout + HELPER_GRACE_MS }
        local function prepared(result, fresh, timedOut)
            if request.done then return end
            request.done = true
            helperRequests[request] = nil
            local parsed, value = false, nil
            if result and type(result.stdout) == "string" and #result.stdout <= MAX_JSON then parsed, value = pcall(tern.json.decode, result.stdout) end
            if timedOut or not result or result.timed_out or result.status ~= 0 or not parsed or not platform.ready(value) then
                callback(nil, "Stop was NOT performed: native controller preparation failed or timed out. The existing backend may still be running; retry Settings before Stop.", fresh)
                return
            end
            helperReady = true
            helper(command, mode, token, fresh, callback)
        end
        request.consume = prepared
        helperRequests[request] = true
        local receipt = runner:wait(token, prepareTimeout + HELPER_GRACE_MS, prepared)
        local ok = pcall(function()
            tern.process.run(platform.bootstrap("--prepare"), { timeout_ms = prepareTimeout }, function(result, _fresh)
                receipt(result)
                runner:wake()
            end)
        end)
        if not ok then receipt({ launchFailed = true }); runner:wake() end
        return
    end
    local argv = { "relay", command,
        "--config", configPath, "--state-dir", stateDir }
    if mode then table.insert(argv, "--mode"); table.insert(argv, mode) end
    local timeout = (command == "start" or command == "resume") and 120000 or (command == "stop" and 20000 or STATUS_TIMEOUT_MS)
    local request = { token = token, deadline = tern.now() + timeout + HELPER_GRACE_MS }
    local function consume(result, fresh, timedOut)
        if request.done then return end
        request.done = true
        helperRequests[request] = nil
        if timedOut or (result and result.timed_out) then
            callback(nil, "Helper " .. command .. " timed out; outcome unknown. Run Status before retrying.", fresh)
            return
        end
        if not result or result.launchFailed then
            callback(nil, "Cannot start the TURN helper. Open TURN: Settings to check its private runtime.", fresh)
            return
        end
        local value, err = decode(result.stdout)
        if not value then callback(nil, err, fresh); return end
        if command == "status" and value.state == "starting"
            and (value.gateway_recovering or (value.recovering_flows or 0) > 0 or value.recovery_error ~= nil) then
            callback(value, nil, fresh)
            return
        end
        if result.status ~= 0 or not value.ok then
            callback(value, value.error or "Helper command failed; no direct fallback was attempted.", fresh)
            return
        end
        callback(value, nil, fresh)
    end
    request.consume = consume
    helperRequests[request] = true
    local receipt = runner:wait(token, timeout + HELPER_GRACE_MS, consume)
    local ok = pcall(function()
        tern.process.run(platform.bootstrap("--exec", argv), { stdin = "", timeout_ms = timeout }, function(result, _fresh)
            receipt(result)
            runner:wake()
        end)
    end)
    if not ok then
        receipt({ launchFailed = true })
        runner:wake()
    end
end

-- One live status request per generation, shared by polling, traffic and commands.
-- Saved status.json is never read into the live cache or used as a Host gate.
local function queryStatus(token, cx, callback, subscriber)
    local previous = statusInFlight and statusInFlight.token == token and statusInFlight or nil
    if previous and tern.now() < previous.deadline then
        if subscriber and previous.subscribers[subscriber] then return end
        if subscriber then previous.subscribers[subscriber] = true end
        table.insert(previous.callbacks, callback)
        return
    end
    -- The helper receipt can be consumed before the host aborts its continuation.
    -- This independent lease must expire even when that continuation never returns.
    -- Preserve subscribers, but replace request identity so late results lose authority.
    local request = { token = token, deadline = tern.now() + STATUS_TIMEOUT_MS + HELPER_GRACE_MS,
        callbacks = previous and previous.callbacks or {}, subscribers = previous and previous.subscribers or {} }
    if not subscriber or not request.subscribers[subscriber] then
        table.insert(request.callbacks, callback)
    end
    if subscriber then request.subscribers[subscriber] = true end
    statusInFlight = request
    helper("status", nil, token, cx, function(value, err, _fresh)
        if statusInFlight ~= request then return end
        statusInFlight = false
        if err then
            cache.state = "error"
            cache.ok = false
            cache.gateway_recovering = false
            cache.recovering_flows = 0
            cache.resume_mode = nil
            cache.error = err
            value = nil
        elseif value then
            accept(value)
        end
        -- 查询失败不代表后台永久停止；先续订只读观察，再交付 UI 回调。
        schedule()
        for _, consume in ipairs(request.callbacks) do
            runner:post(token, function(current) consume(value, err, current) end)
        end
    end)
end

local function exactHost(cx, address)
    if not address then return nil end
    for _, host in ipairs(cx.hosts:list()) do
        if host.kind == "remote" and host.address == address then return host end
    end
    return nil
end


local function targetConfig(cx)
    local ok, value = pcall(function()
        local raw = tern.fs.read(configPath, MAX_JSON)
        if #raw > MAX_JSON then error("oversized config") end
        return tern.json.decode(raw)
    end)
    local t = ok and type(value) == "table" and value.target
    if not t or type(t) ~= "table" or (value.schema ~= 3 and value.schema ~= 4) or not text(value.ssh_destination, 253)
        or type(value.gateway) ~= "table" or not text(value.gateway.fingerprint, 256)
        or value.gateway.fingerprint == t.fingerprint or not text(value.gateway.daemon_socket, 4096)
        or not text(t.name, 64) or not text(t.host, 256) or not text(t.user, 128)
        or not text(t.fingerprint, 256) or not count(t.port) or t.port < 1 or t.port > 65535
        or not count(value.listen_port) or value.listen_port < 1 or value.listen_port > 65535 then
        report(cx, "TURN configuration is absent or invalid. Open TURN: Settings; no Host was changed.")
        return nil
    end
    return { target = t, address = t.user .. "@127.0.0.1:" .. tostring(value.listen_port),
        relayFingerprint = value.gateway.fingerprint, daemonSocket = value.gateway.daemon_socket,
        sshDestination = value.ssh_destination }
end

local function directAddress(address, config)
    local base = config.target.user .. "@" .. config.target.host
    return address == base or address == base .. ":" .. tostring(config.target.port)
end

local function sameTarget(value, config)
    local t, expected = value and value.target, config.target
    return t and value.address == config.address and t.name == expected.name
        and t.host == expected.host and t.port == expected.port and t.user == expected.user
        and t.fingerprint == expected.fingerprint and value.ssh_destination == config.sshDestination
        and value.relay_fingerprint == config.relayFingerprint
        and value.daemon_socket == config.daemonSocket and value.route_policy == "exclusive"
end

local function originalAddress(cx, source, config)
    local t = config.target
    local key = "original-direct:" .. config.address .. ":" .. t.fingerprint
    local ok, saved = pcall(tern.kv.get, key)
    if not ok then report(cx, "Cannot read the saved direct Host. No Host was changed."); return nil end
    if source and source.kind == "remote" and directAddress(source.address, config) then
        -- Persist before starting the relay or attaching anything. Keep this record on
        -- restore too, so reloads and repeated commands can recover the original spelling.
        local stored = pcall(tern.kv.set, key, source.address)
        if not stored then report(cx, "Cannot save the original direct address. Conversion refused."); return nil end
        return source.address
    end
    if source and source.kind == "remote" and source.address ~= config.address then
        report(cx, "Select the configured Host (" .. t.user .. "@" .. t.host
            .. ", optionally :" .. tostring(t.port) .. ") or its exact TURN alias. Unrelated Hosts are not supported.")
        return nil
    end
    if saved ~= nil then
        if type(saved) ~= "string" or not directAddress(saved, config) then
            report(cx, "Saved original address is invalid for the configured verified target. Restore refused.")
            return nil
        end
        return saved
    end
    return t.user .. "@" .. t.host .. ":" .. tostring(t.port)
end

local function selectedSource(cx)
    local ok, source = pcall(function() return cx.hosts:current() end)
    if not ok or not source or source.kind ~= "remote" or not source.address then
        report(cx, "Select the configured remote Host before converting or restoring.")
        return nil
    end
    return source
end

local function stillSelected(cx, source)
    local ok, current = pcall(function() return cx.hosts:current() end)
    return ok and current and current.id == source.id and current.address == source.address
end

local function queueNative(request, phase, delay)
    request.phase = phase
    request.ticket = (request.ticket or 0) + 1
    local ticket = request.ticket
    local function run(fresh)
        if pending == request and request.ticket == ticket then stepNative(fresh, request) end
    end
    if delay then
        runner:wait(request.token, delay, function(_result, fresh) run(fresh) end)
    else
        runner:post(request.token, run)
    end
end

local function mayFocus(cx, request)
    local ok, current = pcall(function() return cx.hosts:current() end)
    if not ok or not current or request.focusLost then return false end
    if (current.id == request.source.id and current.address == request.source.address)
        or current.address == request.address
        or (request.removingSource and current.address == request.original) then return true end
    -- Native add can temporarily select local while restoring remote sessions.
    if (request.removingSource or request.addIssued) and current.kind == "local" then return true end
    request.focusLost = true
    return false
end

failNative = function(cx, message)
    local request = pending
    busy = nil
    pending = nil
    nativeState = "failed"
    if request and request.action == "convert" then
        message ..= " Strict TURN did not connect; no automatic direct fallback was attempted. Restore direct remains an explicit command."
    end
    report(cx, message)
    schedule()
end

inspectNative = function(cx)
    if not cx then return end
    local request = pending
    local ok, host = pcall(exactHost, cx, request and request.address or alias)
    if not ok then
        if request then failNative(cx, "Cannot inspect native Hosts; connection outcome is unknown.")
        else report(cx, "Cannot inspect native Hosts in this runtime.") end
        return
    end
    nativeState = host and host.state or (request and "connecting" or "disconnected")
    if request then
        mayFocus(cx, request)
        if tern.now() >= request.deadline then queueNative(request, request.phase) end
    end
end

schedule = function()
    -- Native Tern reconnects independently; a disconnected Host must not stop
    -- observation of a live backend or freeze its last recovery snapshot.
    if timer or not (pending or busy or cache.state == "ready" or cache.state == "starting"
        or (hasConfig and helperReady and cache.state == "error")) then return end
    local token = generation
    timer = tern.timer(POLL_MS, function(_fresh)
        timer = nil
        if token ~= generation then schedule(); return end
        -- Keep the next observation armed before queued/native work can exhaust
        -- a timer hook's budget. Recovery must not depend on callback completion.
        schedule()
        runner:post(token, function(fresh)
            if busy or (pending and pending.action == "restore") then
                inspectNative(fresh)
                refresh()
                schedule()
                return
            end
            queryStatus(token, fresh, function(_value, err, current)
                if err then
                    if pending then failNative(current, err) else report(current, err) end
                end
                inspectNative(current)
                refresh()
                schedule()
            end, "poll")
        end)
    end)
end

stepNative = function(cx, request)
    if pending ~= request then return end
    if not cx then failNative(nil, "Native reconciliation has no fresh window context."); return end
    local phase = request.phase
    local ok, host = pcall(exactHost, cx, request.address)
    if not ok then failNative(cx, "Cannot inspect the exact native destination."); return end
    -- Observe actual state first: disconnect may finish after its hook is interrupted.
    if phase == "observe-detached" and not host then request.removed = true end
    if not mayFocus(cx, request) then
        failNative(cx, "Selected Host changed. No further Host action or focus switch was performed.")
        return
    end
    if tern.now() >= request.deadline then
        failNative(cx, "Native operation timed out in " .. phase .. "; connectivity was not confirmed.")
        return
    end
    if request.action == "convert" and (cache.state ~= "ready"
        or cache.service_id ~= request.service_id or not sameTarget(cache, request.config)) then
        failNative(cx, "Relay readiness or identity changed during reconnect.")
        return
    end
    local fingerprint = host and host.detail and host.detail.fingerprint
    if fingerprint and fingerprint ~= request.fingerprint then
        failNative(cx, "Native fingerprint does not match the independently verified target. Trust refused.")
        return
    end
    if (phase == "cleanup" or phase == "observe-cleanup" or phase == "finish")
        and (not host or host.id ~= request.connectedId or host.state ~= "connected") then
        failNative(cx, "Destination connectivity was lost before final cleanup completed.")
        return
    end
    if phase == "detach" then
        if not host then queueNative(request, "add"); return end
        if host.id ~= request.reconnectId then
            failNative(cx, "The exact TURN entry changed before detach; no replacement Host was removed.")
            return
        end
        request.removingSource = host.id == request.source.id
        request.nativeError = nil
        queueNative(request, "observe-detached")
        local detached = pcall(function() cx.hosts:disconnect(host.id) end)
        if not detached then request.nativeError = "Native detach was interrupted or rejected." end
    elseif phase == "observe-detached" then
        if not host then
            request.nativeError = nil
            queueNative(request, "add")
        elseif request.nativeError then
            failNative(cx, "The existing TURN entry is still present after detach failed. It was not silently reused.")
        else
            queueNative(request, "observe-detached", 100)
        end
    elseif phase == "add" then
        request.nativeError = nil
        if host then queueNative(request, "observe-connected"); return end
        local attemptAddress = request.address
        local receipt = runner:wait(request.token, math.max(1, request.deadline - tern.now()),
            function(result, _fresh, timedOut)
                if pending ~= request or request.address ~= attemptAddress
                    or request.phase ~= "observe-connected" then return end
                request.addResult = result
                request.addTimedOut = timedOut
                queueNative(request, "observe-connected")
            end)
        -- Persist and pre-arm reconciliation BEFORE the potentially blocking add.
        request.addIssued = true
        queueNative(request, "observe-connected")
        local added = pcall(function()
            cx.hosts:add(request.address):next(function(connected, err, _fresh)
                receipt({ failed = err ~= nil or connected == nil })
                runner:wake()
            end)
        end)
        if not added then request.nativeError = "Native add was interrupted or rejected." end
    elseif phase == "observe-connected" then
        nativeState = host and host.state or "connecting"
        if host and host.state == "connected" then
            request.connectedId = host.id
            queueNative(request, request.action == "convert" and "traffic" or "switch")
        elseif host and host.state == "verify" then
            if fingerprint ~= request.fingerprint then
                failNative(cx, "Native fingerprint is missing or mismatched. Trust refused.")
            elseif request.nativeError and request.trustRequested then
                failNative(cx, "Native trust was rejected; no pin was overwritten.")
            elseif not request.trustRequested then
                queueNative(request, "trust")
            else
                queueNative(request, "observe-connected", 100)
            end
        elseif (host and host.state == "failed") or (not host and request.nativeError)
            or (request.addResult and request.addResult.failed) or request.addTimedOut then
            failNative(cx, "Native destination did not connect. Existing trust pins were not overwritten.")
        else
            queueNative(request, "observe-connected", 100)
        end
    elseif phase == "trust" then
        if not host or host.state ~= "verify" then queueNative(request, "observe-connected"); return end
        if fingerprint ~= request.fingerprint then failNative(cx, "Native fingerprint changed before trust."); return end
        request.trustRequested = true
        queueNative(request, "observe-connected")
        local trusted = pcall(function() cx.hosts:trust(host.id, request.fingerprint) end)
        if not trusted then request.nativeError = "Native trust was interrupted or rejected." end
    elseif phase == "traffic" then
        queueNative(request, "wait-traffic", 100)
        -- Live counters, not the periodically published file, gate old-Host removal.
        queryStatus(request.token, cx, function(value, err, fresh)
            if pending ~= request or request.phase ~= "wait-traffic" then return end
            if value then accept(value) end
            if err then failNative(fresh, err); return end
            request.sawTraffic = value.bytes_up > request.bytesUpBefore
                and value.bytes_down > request.bytesDownBefore
            queueNative(request, "switch")
        end)
    elseif phase == "wait-traffic" then
        queueNative(request, "wait-traffic", 100)
    elseif phase == "switch" then
        if not host or host.id ~= request.connectedId or host.state ~= "connected" then
            failNative(cx, "Destination changed before switching; no old Host was removed.")
            return
        end
        request.nativeError = nil
        queueNative(request, "observe-switched")
        local switched = pcall(function() cx.hosts:switch(host.id) end)
        if not switched then request.nativeError = "Native switch was interrupted or rejected." end
    elseif phase == "observe-switched" then
        local selected = cx.hosts:current()
        if not host or host.state ~= "connected" or selected.id ~= request.connectedId
            or selected.address ~= request.address then
            failNative(cx, "Destination selection was not confirmed; no old Host was removed.")
            return
        end
        request.addIssued = false
        request.removingSource = false
        queueNative(request, "cleanup")
    elseif phase == "cleanup" then
        if request.action == "convert" and not request.sawTraffic then
            request.notice = "Dedicated Host connected, but this operation observed no new bidirectional gateway traffic. Original direct Host retained; inspect Status before retrying."
            queueNative(request, "finish")
            return
        end
        local old = request.cleanupHost
        local present = old and exactHost(cx, old.address)
        if not present or present.id ~= old.id or present.address == request.address then
            queueNative(request, "finish")
            return
        end
        request.nativeError = nil
        queueNative(request, "observe-cleanup")
        local detached = pcall(function() cx.hosts:disconnect(present.id) end)
        if not detached then request.nativeError = "Old Host detach was interrupted or rejected." end
    elseif phase == "observe-cleanup" then
        local old = request.cleanupHost
        local present = old and exactHost(cx, old.address)
        if present and present.id == old.id then
            request.notice = "Destination connected, but the old Host is still attached. Remote programs remain running."
        end
        queueNative(request, "finish")
    elseif phase == "finish" then
        pending = nil
        busy = nil
        nativeState = request.action == "convert" and "connected" or "disconnected"
        lastError = nil
        if request.notice then
            report(cx, request.notice)
        else
            refresh()
            cx:toast(request.action == "convert" and "info" or "success",
                request.action == "convert" and "Dedicated TURN entry connected" or "Original Host restored to direct",
                request.action == "convert"
                    and "Dedicated identity verified and gateway traffic observed. There is no automatic direct fallback. Remote session programs keep running."
                    or "Shared relay and SSH TCP sessions were not stopped; remote programs keep running.")
        end
        schedule()
    end
end

local function attach(action, config, original, source, token, cx)
    if not cx then report(nil, "No fresh window context; no Host action was taken."); return end
    if not stillSelected(cx, source) then report(cx, "Selected Host changed; no Host was detached or switched."); return end
    local address = action == "convert" and config.address or original
    local found, existing = pcall(exactHost, cx, address)
    if not found then report(cx, "Cannot inspect destination Host; no Host was changed."); return end
    local oldAddress = action == "convert" and original or config.address
    local inspected, old = pcall(exactHost, cx, oldAddress)
    if not inspected then report(cx, "Cannot inspect the original Host; no Host was changed."); return end
    local request = { action = action, config = config, source = source, address = address, token = token,
        original = original, fingerprint = action == "convert" and config.relayFingerprint or config.target.fingerprint,
        service_id = cache.service_id,
        deadline = tern.now() + CONNECT_MS, trustRequested = false, cleanupHost = old,
        reconnectId = existing and existing.id, bytesUpBefore = cache.bytes_up, bytesDownBefore = cache.bytes_down }
    pending = request
    nativeState = "connecting"
    -- Manual conversion of an exact existing alias always disconnects/re-adds it.
    queueNative(request, action == "convert" and existing and "detach" or "add")
    refresh()
    schedule()
end

local function cancelStartup()
    startupSeen = true
    startup = nil
    if startupTimer then startupTimer:cancel(); startupTimer = nil end
end

-- Discovery is startup-only and bounded. Only an authoritative helper response can
-- authorize resume; status.json is never evidence of durable intent or liveness.
local function discoverStartup(cx, request, authoritative)
    if startup ~= request or request.token ~= generation then return end
    if not cx or tern.now() >= request.deadline then cancelStartup(); return end
    local ok, host = pcall(exactHost, cx, request.config.address)
    if not ok then
        cancelStartup()
        report(cx, "Cannot inspect startup Hosts; no backend recovery was attempted.")
        return
    end
    inspectNative(cx)
    refresh()
    if not host then
        startupTimer = tern.timer(math.max(0, math.min(POLL_MS, request.deadline - tern.now())), function(fresh)
            startupTimer = nil
            discoverStartup(fresh, request, false)
        end)
        return
    end
    if not authoritative then
        -- Hosts may arrive after the first status. Recheck the helper before acting;
        -- another window may have stopped the backend and cleared its intent.
        queryStatus(request.token, cx, function(value, err, fresh)
            if startup ~= request then return end
            if value then accept(value) end
            if err or not sameTarget(value, request.config) then
                cancelStartup()
                report(fresh, err or "Startup helper target changed; recovery was refused.")
                return
            end
            request.status = value
            discoverStartup(fresh, request, true)
        end)
        return
    end
    local value = request.status
    cancelStartup() -- One attempt per load, including failure or an unknown outcome.
    if value.state ~= "stopped" or not value.resume_mode then schedule(); return end
    local config = targetConfig(cx)
    if not config or not sameTarget(value, config) then
        if config then report(cx, "Startup configuration changed; recovery was refused.") end
        return
    end
    local fingerprint = host.detail and host.detail.fingerprint
    if fingerprint and fingerprint ~= config.relayFingerprint then
        report(cx, "Startup Host fingerprint differs from the configured target; recovery was refused.")
        return
    end
    -- Never add, switch, disconnect or trust here. Native Tern owns reconnect and
    -- first-contact verification; restoring the local listener cannot pin a Host.
    busy = "resume"
    lastError = nil
    refresh()
    helper("resume", nil, request.token, cx, function(resumed, err, fresh)
        busy = nil
        if stopAfterResume then
            stopAfterResume = false
            disconnect(fresh)
            return
        end
        if resumed then accept(resumed) end
        if err then
            if cache.state == "starting" then cache.state = "error" end
            report(fresh, err)
        elseif not sameTarget(resumed, config) or resumed.state == "starting"
            or (resumed.state == "ready" and resumed.mode ~= value.resume_mode) then
            if cache.state == "starting" then cache.state = "error" end
            report(fresh, "Startup helper did not confirm the configured target and saved mode.")
        end
        inspectNative(fresh)
        refresh()
        schedule()
    end)
end

local function prepare(cx, allowLocal)
    cancelStartup()
    if not supported(cx) then return nil end
    if busy or pending then report(cx, "An operation is already in progress. Use Status and wait for its result."); return nil end
    if onboarding and onboarding.active then report(cx, "Finish or cancel TURN Settings before changing the connection."); return nil end
    local config = targetConfig(cx)
    if not config then return nil end
    local source
    if allowLocal then
        local ok, current = pcall(function() return cx.hosts:current() end)
        if not ok or not current then report(cx, "Cannot inspect the current local window."); return nil end
        source = current
    else
        source = selectedSource(cx)
    end
    if not source then return nil end
    local original = originalAddress(cx, source, config)
    if not original then return nil end
    local fingerprint = source.detail and source.detail.fingerprint
    local expectedFingerprint = source.address == config.address and config.relayFingerprint or config.target.fingerprint
    if source.kind == "remote" and fingerprint and fingerprint ~= expectedFingerprint then
        report(cx, "Selected Host fingerprint differs from the independently verified target; no connection was changed.")
        return nil
    end
    alias = config.address
    generation += 1
    statusInFlight = false
    lastError = nil
    return { config = config, source = source, original = original, token = generation }
end

local function convert(mode, cx, allowLocal)
    local request = prepare(cx, allowLocal)
    if not request then return end
    busy = "start"
    refresh()
    helper("start", mode, request.token, cx, function(value, err, fresh)
        busy = nil
        if stopAfterResume then
            stopAfterResume = false
            disconnect(fresh)
            return
        end
        if value then accept(value) end
        if err then
            if cache.state == "starting" then cache.state = "error" end
            report(fresh, err); schedule(); return
        end
        if value.state ~= "ready" or value.mode ~= mode or not sameTarget(value, request.config) then
            if cache.state == "starting" then cache.state = "error" end
            report(fresh, "Helper did not confirm the exact configured target and requested TURN mode. Source Host was retained.")
            schedule()
            return
        end
        attach("convert", request.config, request.original, request.source, request.token, fresh)
    end)
end

local function restore(cx)
    local request = prepare(cx, true)
    if not request then return end
    -- No helper stop: this backend may still serve SSH TCP or other windows.
    attach("restore", request.config, request.original, request.source, request.token, cx)
end

local DETAILS_TITLE = "TURN 连接详情"
local DETAILS_ABOUT = "tern-turn-relay connection diagnostics"

local function detailValue(value)
    return tostring(value == nil and "—" or value):gsub("[%c]", " "):gsub("(%p)", "\\%1")
end

local function showDetails(cx)
    if not cx then return end
    local rows = { "# TURN 连接详情", "", "本次查询快照；再次点击状态栏刷新。流量为本次后台实例累计值，不是速率。", "",
        "## 连接", "", "| 项目 | 状态 |", "| --- | --- |" }
    local function row(label, value)
        table.insert(rows, "| " .. label .. " | " .. detailValue(value) .. " |")
    end
    row("后台", cache.state)
    row("原生连接", nativeState .. (cache.state ~= "ready" and "（最近观察值；专用路由不可用）" or ""))
    row("传输", cache.mode and string.upper(cache.mode))
    row("入口", cache.address or alias)
    row("当前操作", busy or (pending and pending.phase) or (statusInFlight and "查询中") or "无")
    row("原生程序", nativeBinary)
    row("私有数据", tern.plugin.data)
    row("自动恢复模式", cache.resume_mode)
    table.insert(rows, "\n## 流量与队列\n\n| 项目 | 数值 |\n| --- | --- |")
    row("上传 / 下载", bytes(cache.bytes_up) .. " / " .. bytes(cache.bytes_down))
    row("TURN flows / SSH TCP", tostring(cache.flows) .. " / " .. tostring(cache.ssh_connections))
    row("恢复中的 flow", cache.recovering_flows or 0)
    row("成功续期次数", cache.allocation_refreshes or 0)
    row("网关恢复中", cache.gateway_recovering and "是" or "否")
    row("网关重连尝试次数", cache.gateway_reconnects or 0)
    row("最近网关事件", cache.gateway_failure_reason)
    row("最近网关故障阶段", cache.gateway_failure_message)
    row("当前恢复原因", cache.recovery_error)
    row("排队", tostring(cache.queued_packets) .. " 包 / " .. bytes(cache.queued_bytes))
    row("累计上行丢弃", tostring(cache.queue_dropped_packets) .. " 包 / " .. bytes(cache.queue_dropped_bytes))
    row("当前拥塞", cache.congested and "是（可恢复）" or "否")
    table.insert(rows, "\n历史丢包不等于当前拥塞；SSH TCP 使用原 SSH 服务，不经 TURN。\n\n## 身份与后台\n\n| 项目 | 值 |\n| --- | --- |")
    row("路由策略", cache.route_policy)
    row("专用指纹", cache.relay_fingerprint)
    row("原服务指纹", cache.target and cache.target.fingerprint)
    row("共享 daemon", cache.daemon_socket)
    row("后台实例", cache.service_id)
    row("最早凭据到期（Unix 秒）", cache.credentials_expires_at)
    row("现有连接凭据到期（Unix 秒）", cache.active_credentials_expires_at)
    row("缓存凭据到期（Unix 秒）", cache.cached_credentials_expires_at)
    table.insert(rows, "\n## 最近错误\n\n" .. detailValue(lastError or cache.error or "无"))
    local markdown = table.concat(rows, "\n")
    local ok, message = pcall(function()
        for _, panel in ipairs(cx.canvas:list()) do
            if panel.owner == "tern-turn-relay" and panel.about == DETAILS_ABOUT then
                cx.canvas:set(panel.pane, { md = markdown })
                cx.layout:focus(panel.pane)
                return
            end
        end
        local pane, err = cx.canvas:open({ title = DETAILS_TITLE, about = DETAILS_ABOUT,
            md = markdown, how = "tab" })
        if not pane then error(err or "Cannot open TURN details panel") end
    end)
    if not ok then
        lastError = tostring(message)
        refresh()
        cx:toast("error", "无法打开 TURN 详情", "当前 Host 的详情面板不可用")
    end
end

local function status(cx)
    cancelStartup()
    if not hasConfig then report(cx, "尚未配置；请显式打开 TURN Settings。查询状态不会下载运行时。"); showDetails(cx); return end
    if not supported(cx) then return end
    -- Status also recovers expired receipts if a timer was paused or interrupted.
    for request in pairs(helperRequests) do
        if request.token ~= generation then
            helperRequests[request] = nil
        elseif not request.done and tern.now() >= request.deadline then
            runner:post(request.token, function(fresh) request.consume(nil, fresh, true) end)
        end
    end
    if pending then queueNative(pending, pending.phase) end
    runner:wake()
    if busy then
        refresh()
        showDetails(cx)
        return
    end
    local token = generation
    queryStatus(token, cx, function(_value, err, fresh)
        if err then
            if pending and pending.action ~= "restore" then failNative(fresh, err) else report(fresh, err) end
        end
        inspectNative(fresh)
        refresh()
        showDetails(fresh)
        schedule()
    end, "details")
end

disconnect = function(cx)
    cancelStartup()
    if not supported(cx) then return end
    if busy == "resume" or busy == "start" then
        -- Serialize against this window's lifecycle request, including its timeout.
        -- The completion must honor Stop before it can attach any native Host.
        stopAfterResume = true
        refresh()
        cx:toast("info", "TURN Stop queued", "The outstanding start/resume will finish or time out before shared Stop; no reconnect will follow.")
        return
    end
    if busy == "stop" then refresh(); return end
    generation += 1
    local token = generation
    pending = nil
    statusInFlight = false
    busy = "stop"
    if timer then timer:cancel(); timer = nil end
    cx:toast("info", "Stopping TURN for ALL windows and SSH TCP sessions", "Active TCP sessions will be interrupted. Remote programs and direct Hosts are not closed.")
    -- Revoke durable backend intent FIRST. A slow native disconnect must not lose Stop.
    helper("stop", nil, token, cx, function(stopped, err, fresh)
        busy = nil
        if stopped then accept(stopped) end
        if err then
            if cache.state == "starting" then cache.state = "error" end
            report(fresh, err); schedule(); return
        end
        if stopped.state ~= "stopped" or stopped.resume_mode ~= nil then
            report(fresh, "Helper did not confirm stopped with resume intent revoked.")
            schedule(); return
        end
        local address = stopped.address
        runner:post(token, function(current)
            local ok, host = pcall(exactHost, current, address)
            -- Reconciliation is armed before the only native mutation in this tick.
            runner:post(token, function(observed)
                local inspected, remaining = pcall(exactHost, observed, address)
                nativeState = inspected and not remaining and "disconnected" or "failed"
                if not address then
                    report(observed, "TURN stopped and resume revoked. No validated alias was supplied; no unrelated Host was touched.")
                elseif not inspected or remaining then
                    report(observed, "TURN stopped and resume revoked, but the exact native alias is still attached or could not be inspected.")
                else
                    lastError = nil
                    refresh()
                    observed:toast("info", "TURN stopped for ALL windows and SSH TCP sessions", "TCP sessions were interrupted. Remote programs and original direct Hosts remain untouched.")
                end
            end)
            if ok and host then pcall(function() current.hosts:disconnect(host.id) end) end
        end)
    end)
end

local function commandTick(callback)
    return function(_cx)
        -- Commands survive generation changes caused by an earlier queued command.
        runner:post(false, callback)
        runner:wake()
    end
end

onboarding = require('./onboarding').new({
    available = function() return not busy and not pending end,
    runtimeReady = function(path) if path == nativeBinary then helperReady = true end end,
    configured = function() hasConfig = true; lastError = nil; refresh() end,
    reviewChanged = function() tern.chrome.refresh() end,
    failed = function(message)
        setupError = message:gsub("[%c]", " ")
        lastError = setupError
        if hasConfig then refresh() else statusText = "TURN · 配置失败"; tern.chrome.refresh() end
    end,
    inspected = function()
        if setupError and lastError == setupError then lastError = nil end
        setupError = nil
        if hasConfig then refresh() else statusText = "TURN · 待配置"; tern.chrome.refresh() end
    end,
    connect = function(cx) convert("tls", cx, true) end,
    status = status,
}, tern)
tern.command({ id = "setup", title = "Settings: server, Cloudflare Key and private runtime", group = "TURN",
    run = commandTick(function(cx) onboarding.open(cx) end) })

tern.command({ id = "convert-tls", title = "Connect configured Host via TURN TLS", group = "TURN",
    run = commandTick(function(cx) if hasConfig then convert("tls", cx, true) else report(cx, "请先显式打开 TURN Settings 完成配置；未改变 Host。") end end) })
tern.command({ id = "convert-udp", title = "Connect configured Host via TURN UDP", group = "TURN",
    run = commandTick(function(cx) if hasConfig then convert("udp", cx, true) else report(cx, "请先显式打开 TURN Settings 完成配置；未改变 Host。") end end) })
tern.command({ id = "restore-direct", title = "Restore configured Host to direct (keep relay and SSH)", group = "TURN", run = commandTick(restore) })
tern.command({ id = "disconnect", title = "Stop TURN for ALL windows and SSH TCP sessions (interrupts TCP)", group = "TURN", run = commandTick(disconnect) })
tern.command({ id = "status", title = "Status: TURN mode, native Host, SSH TCP, bytes and errors", group = "TURN", run = commandTick(status) })

-- Chrome is pure: cache only, never process spawning, file reads or native Host calls.
tern.chrome.status(function()
    local reviewing = onboarding and onboarding.reviewed ~= nil
    return { { text = reviewing and "TURN · 确认配置" or statusText, tone = lastError and "error" or ((cache.gateway_recovering or cache.congested or (cache.recovering_flows or 0) > 0) and "warn" or "muted"), command = (reviewing or not hasConfig or not helperReady) and "plugin.tern-turn-relay.setup" or "plugin.tern-turn-relay.status" } }
end)

-- A plugin reload need not emit window_start, and headless timer clocks may be
-- paused. One asynchronous status query supplies the fresh owner context on load.
if hasConfig and helperReady then
queryStatus(generation, nil, function(value, err, cx)
    if startupSeen then return end
    startupSeen = true
    if not cx then report(nil, "Startup status did not supply a fresh window context."); return end
    if not supported(cx) then return end
    local config = targetConfig(cx)
    if not config then return end
    alias = config.address
    if value then accept(value) end
    if err or not sameTarget(value, config) then
        report(cx, err or "Startup helper target does not match the configuration; recovery was refused.")
        return
    end
    local request = { config = config, token = generation, deadline = tern.now() + STARTUP_MS, status = value }
    startup = request
    discoverStartup(cx, request, true)
end)
end
end

-- Tern 直接加载窗口脚本；测试可注入同一接口而不复制状态机。
if tern then install(tern) end
return install
