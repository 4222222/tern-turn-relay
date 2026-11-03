local install = require('../window')
local cases = {}

local function fixture(os, configured, installed)
    local f = { calls = {}, commands = {}, timers = {}, time = 0, mutations = 0, toasts = {}, details = '', hosts = {}, reads = {} }
    f.config = { schema = 4, ssh_destination = 'server', listen_port = 18377,
        target = { name = 'server', host = '203.0.113.1', user = 'user', port = 22, fingerprint = 'original-pin' },
        gateway = { fingerprint = 'relay-pin', daemon_socket = '/private/daemon.sock' } }
    function f:value(state, resume)
        return { ok = true, state = state, resume_mode = resume, mode = state == 'ready' and 'tls' or nil,
            bytes_up = 0, bytes_down = 0, flows = 0, ssh_connections = 0, queued_packets = 0, queued_bytes = 0,
            queue_dropped_packets = 0, queue_dropped_bytes = 0, congested = false,
            target = self.config.target, address = 'user@127.0.0.1:18377', ssh_destination = 'server',
            relay_fingerprint = 'relay-pin', daemon_socket = '/private/daemon.sock', route_policy = 'exclusive', service_id = 'service-1' }
    end
    local host = {
        runtime = { os = os },
        plugin = { data = os == 'windows' and 'C:/用户/data' or '/Users/用户/data', dir = os == 'windows' and 'C:/用户/plugin' or '/Users/用户/plugin' },
        getenv = function() return 'C:/Windows' end,
        now = function() return f.time end,
        timer = function(ms, callback)
            local timer = { callback = callback, due = f.time + ms, active = true }
            function timer:cancel() self.active = false end
            table.insert(f.timers, timer)
            return timer
        end,
        fs = {
            exists = function(path)
                if path:sub(-12) == '/config.json' then return configured end
                return installed == true
            end,
            read = function(path)
                table.insert(f.reads, path)
                if path:sub(-12) == '/config.json' then return 'config' end
                return 'stale-status'
            end,
        },
        json = { encode = function(value) return value end, decode = function(raw)
            if raw == 'config' then return f.config end
            if raw == 'stale-status' then return f:value('ready') end
            return f.response
        end },
        process = { run = function(argv, options, callback) table.insert(f.calls, { argv = argv, options = options, callback = callback }) end },
        command = function(command) f.commands[command.id] = command end,
        chrome = { refresh = function()
            if f.interruptRefresh then
                f.interruptRefresh = false
                error('simulated interrupted timer hook')
            end
        end, status = function(callback) f.status = callback end },
    }
    function f:context()
        local function mutate() self.mutations += 1; error('不应修改 Host') end
        return {
            toast = function(_, _, title, detail) table.insert(self.toasts, title .. ' ' .. tostring(detail)) end,
            hosts = { list = function() return self.hosts end, current = function() return { kind = 'local', id = 'local' } end, add = mutate, disconnect = mutate, trust = mutate, switch = mutate },
            canvas = { list = function() return {} end, open = function(_, options) self.details = options.md; return 'pane' end },
        }
    end
    function f:tick()
        for _, timer in ipairs(self.timers) do
            if timer.active and timer.due <= self.time then
                timer.active = false
                timer.callback(self:context())
                return true
            end
        end
        return false
    end
    function f:flush()
        local count = 0
        while self:tick() do count += 1; assert(count < 100, '即时队列未收敛') end
    end
    function f:command(id)
        self.commands[id].run(self:context())
        assert(self:tick())
        self:flush()
    end
    function f:complete(value, status)
        self.response = value
        self.calls[#self.calls].callback({ stdout = '{}', status = status or 0 }, { expired = true })
        assert(self:tick())
        self:flush()
    end
    install(host)
    return f
end

function cases.loading_and_status_never_download()
    for _, os in ipairs({ 'windows', 'macos' }) do
        for _, configured in ipairs({ false, true }) do
            local f = fixture(os, configured)
            assert(#f.calls == 0)
            f:command('status')
            assert(#f.calls == 0 and f.mutations == 0)
        end
    end
end

function cases.unconfigured_load_never_runs_even_with_runtime_present()
    for _, os in ipairs({ 'windows', 'macos' }) do
        local f = fixture(os, false, true)
        f:flush()
        assert(#f.calls == 0 and f.mutations == 0)
        f:command('status'); f:command('convert-tls')
        assert(#f.calls == 0 and f.mutations == 0)
    end
end

function cases.unconfigured_connect_cannot_prepare_or_change_host()
    for _, id in ipairs({ 'convert-tls', 'convert-udp' }) do
        local f = fixture('windows', false)
        f:command(id)
        assert(#f.calls == 0 and f.mutations == 0)
    end
end

function cases.stop_preparation_failure_is_not_success()
    for _, os in ipairs({ 'windows', 'macos' }) do
        local f = fixture(os, true)
        f:command('disconnect')
        assert(#f.calls == 1 and f.calls[1].argv[#f.calls[1].argv] == '--prepare')
        f:complete({ ok = false }, 1)
        assert(#f.calls == 1 and f.mutations == 0 and f.status()[1].tone == 'error')
        f:command('status')
        assert(#f.calls == 1 and f.mutations == 0)
        for _, toast in ipairs(f.toasts) do assert(not toast:find('TURN stopped for ALL', 1, true)) end
    end
end

function cases.stop_bad_runtime_identity_and_timeout_preserve_hosts()
    for _, scenario in ipairs({ 'path', 'timeout' }) do
        local f = fixture('windows', true)
        f:command('disconnect')
        if scenario == 'timeout' then
            f.time = 322001
            assert(f:tick())
        else
            f:complete({ ok = true, runtime_ready = true, version = '0.5.5', binary = 'C:/wrong.exe' })
        end
        assert(#f.calls == 1 and f.mutations == 0 and f.status()[1].tone == 'error')
        f:command('status')
        assert(#f.calls == 1 and f.mutations == 0)
    end
end

function cases.successful_prepare_still_requires_real_stop_result()
    local f = fixture('windows', true)
    f:command('disconnect')
    f:complete({ ok = true, runtime_ready = true, version = '0.5.5', binary = 'C:/用户/data/native-runtime/0.5.5/tern-turn-relay.exe' })
    assert(#f.calls == 2 and f.calls[2].argv[10] == '--exec' and f.calls[2].argv[11] == 'relay' and f.calls[2].argv[12] == 'stop')
    assert(f.mutations == 0)
    f:complete({ ok = true, state = 'stopped' }) -- 缺失状态 schema，不能伪报成功。
    assert(f.mutations == 0)
    for _, toast in ipairs(f.toasts) do assert(not toast:find('TURN stopped for ALL', 1, true)) end
end

function cases.existing_runtime_is_never_execution_authority()
    for _, os in ipairs({ 'windows', 'macos' }) do
        local f = fixture(os, true, true)
        local argv = f.calls[1].argv
        local offset = os == 'windows' and 10 or 4
        assert(argv[offset] == '--exec' and argv[offset + 1] == 'relay' and argv[offset + 2] == 'status')
        f:complete({ ok = false, error = 'verification failed' }, 1)
        assert(f.mutations == 0 and f.status()[1].tone == 'error')
        f:command('disconnect')
        assert(f.calls[2].argv[offset] == '--exec' and f.calls[2].argv[offset + 2] == 'stop')
        f:complete({ ok = false }, 1)
        assert(f.mutations == 0)
    end
end

function cases.startup_resume_requires_intent_matching_config_and_exact_host()
    for _, os in ipairs({ 'windows', 'macos' }) do
        for _, missing in ipairs({ 'none', 'intent', 'config', 'host', 'pin' }) do
            local f = fixture(os, true, true)
            f.hosts = { { kind = 'remote', id = 'relay', address = missing == 'host' and 'user@127.0.0.1:18378' or 'user@127.0.0.1:18377',
                state = 'disconnected', detail = { fingerprint = missing == 'pin' and 'wrong' or 'relay-pin' } } }
            local value = f:value('stopped', missing ~= 'intent' and 'tls' or nil)
            if missing == 'config' then value.ssh_destination = 'other-server' end
            f:complete(value)
            assert(#f.calls == (missing == 'none' and 2 or 1), missing)
            assert(f.mutations == 0)
            if missing == 'none' then
                local offset = os == 'windows' and 10 or 4
                assert(f.calls[2].argv[offset + 2] == 'resume')
                f:complete(f:value('ready'))
                assert(f.mutations == 0)
            end
        end
    end
end

function cases.periodic_status_is_live_deduplicated_and_failure_invalidates_ready()
    local f = fixture('windows', true, true)
    f.hosts = { { kind = 'remote', id = 'relay', address = 'user@127.0.0.1:18377', state = 'connected', detail = { fingerprint = 'relay-pin' } } }
    f:complete(f:value('ready'))
    f.time = 3000; f:flush()
    assert(#f.calls == 2 and f.calls[2].argv[12] == 'status')
    f:command('status'); f:command('status')
    assert(#f.calls == 2, '并发 Status 不得重复查询')
    f:complete({ ok = false, error = 'control unavailable' }, 1)
    assert(f.status()[1].text:find('不可用') and not f.status()[1].text:find('已连接'))
    assert(f.details:find('error', 1, true), '等待中的详情订阅应显示实时失败结果')
    assert(f.mutations == 0)
    for _, path in ipairs(f.reads) do assert(not path:find('status.json', 1, true)) end
    f:command('status'); f:complete(f:value('ready'))
    assert(f.status()[1].text:find('已连接'))
end

function cases.disconnected_host_does_not_freeze_recovery_status()
    for _, os in ipairs({ 'macos', 'windows' }) do
        local f = fixture(os, true, true)
        f.hosts = { { kind = 'remote', id = 'relay', address = 'user@127.0.0.1:18377',
            state = 'disconnected', detail = { fingerprint = 'relay-pin' } } }
        local recovering = f:value('ready')
        recovering.recovering_flows = 1
        f:complete(recovering)
        assert(f.status()[1].text:find('恢复中'))
        -- Native Tern reconnects independently; no plugin command wakes polling.
        f.hosts[1].state = 'connected'
        f.time = 3000; f:flush()
        assert(#f.calls == 2, '断开期间不能停止读取后台状态，否则恢复文字会永久冻结')
        f:complete(f:value('ready'))
        assert(f.status()[1].text:find('已连接') and not f.status()[1].text:find('恢复中'))
        assert(f.mutations == 0, '观察恢复不能修改原生 Host')
    end
end

function cases.interrupted_refresh_does_not_stop_future_status_observation()
    local f = fixture('macos', true, true)
    f.hosts = { { kind = 'remote', id = 'relay', address = 'user@127.0.0.1:18377',
        state = 'connected', detail = { fingerprint = 'relay-pin' } } }
    f:complete(f:value('ready'))
    f.time = 3000; f:flush()
    f.interruptRefresh = true
    f:complete(f:value('ready'))
    f.time = 6000; f:flush()
    assert(#f.calls == 3, '刷新回调被中断后，下一次状态观察仍必须发生')
    local recovering = f:value('ready')
    recovering.recovering_flows = 1
    f:complete(recovering)
    assert(f.status()[1].text:find('恢复中'), '中断后必须继续反映真实状态变化')
    f.time = 9000; f:flush()
    f:complete(f:value('ready'))
    assert(f.status()[1].text:find('已连接') and not f.status()[1].text:find('恢复中'))
    assert(f.mutations == 0)
end

function cases.live_status_timeout_discards_late_ready()
    local f = fixture('windows', true, true)
    f.hosts = { { kind = 'remote', id = 'relay', address = 'user@127.0.0.1:18377', state = 'connected', detail = { fingerprint = 'relay-pin' } } }
    f:complete(f:value('ready'))
    f.time = 3000; f:flush()
    local late = f.calls[2].callback
    f.time = 20001; f:flush()
    assert(f.status()[1].text:find('不可用'))
    f.response = f:value('ready'); late({ stdout = '{}', status = 0 }, {})
    f:flush()
    assert(f.status()[1].text:find('不可用') and f.mutations == 0)
end

function cases.failed_observation_recovers_without_user_command()
    for _, os in ipairs({ 'windows', 'macos' }) do
        for _, initiallyReady in ipairs({ false, true }) do
            local f = fixture(os, true, true)
            f.hosts = { { kind = 'remote', id = 'relay', address = 'user@127.0.0.1:18377', state = 'connected', detail = { fingerprint = 'relay-pin' } } }
            if initiallyReady then
                f:complete(f:value('ready'))
                f.time = 3000; f:flush()
            end
            for _ = 1, 2 do
                f:complete({ ok = false, error = 'control unavailable' }, 1)
                assert(f.status()[1].text:find('不可用'))
                local previous = #f.calls
                f.time += 3000; f:flush()
                assert(#f.calls == previous + 1, '状态查询失败后必须继续观察，不依赖手工 Status')
            end
            f:complete(f:value('ready'))
            assert(f.status()[1].text:find('已连接') and not f.status()[1].text:find('异常'))
            assert(f.mutations == 0, '查询恢复不能启动后台或修改 Host')
        end
    end
end

function cases.stop_generation_discards_previous_status()
    local f = fixture('windows', true, true)
    local late = f.calls[1].callback
    f:command('disconnect')
    assert(#f.calls == 2 and f.calls[2].argv[12] == 'stop')
    f:complete(f:value('stopped'))
    f.response = f:value('ready'); late({ stdout = '{}', status = 0 }, {})
    f:flush()
    assert(f.status()[1].text:find('已停止') and f.mutations == 0)
end

return { run = function()
    local count = 0
    for name, test in pairs(cases) do
        local ok, err = pcall(test)
        assert(ok, name .. ': ' .. tostring(err))
        count += 1
    end
    return count
end }
