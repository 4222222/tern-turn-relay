local Onboarding = require('../onboarding')
local cases = {}

local function fixture(os)
    local f = { calls = {}, errors = {}, timers = {}, time = 0, changes = 0, inspected = 0 }
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
        json = { encode = function(value) return value end, decode = function(_raw) return f.response end },
        process = { run = function(argv, options, callback) table.insert(f.calls, { argv = argv, options = options, callback = callback }) end },
    }
    local api = {
        available = function() return true end,
        failed = function(message) table.insert(f.errors, message) end,
        runtimeReady = function() f.changes += 1 end,
        configured = function() f.changes += 1 end,
        inspected = function() f.inspected += 1 end,
        reviewChanged = function() f.changes += 1 end,
        connect = function() f.changes += 1 end,
    }
    f.wizard = Onboarding.new(api, host)
    function f:context()
        return { toast = function() end, pick = function()
            return { next = function() end }
        end }
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
    function f:complete(value, status)
        self.response = value
        self.calls[#self.calls].callback({ stdout = '{}', status = status or 0 }, { invalidOldContext = true })
        assert(self:tick())
    end
    return f
end

function cases.construction_does_not_prepare_or_connect()
    for _, os in ipairs({ 'windows', 'macos' }) do
        local f = fixture(os)
        assert(#f.calls == 0 and #f.timers == 0 and f.changes == 0)
        f.wizard.open(f:context())
        assert(#f.calls == 1)
        assert(f.calls[1].argv[#f.calls[1].argv] == '--prepare')
    end
end

function cases.failed_preparation_does_not_run_backend_or_mutate_hosts()
    for _, os in ipairs({ 'windows', 'macos' }) do
        local f = fixture(os)
        f.wizard.open(f:context())
        f:complete({ ok = false, error = '下载失败' }, 1)
        assert(#f.calls == 1 and f.changes == 0 and #f.errors == 1 and not f.wizard.active)
    end
end

function cases.wrong_binary_or_version_never_reaches_inspect()
    for _, value in ipairs({
        { ok = true, runtime_ready = true, version = '0.4.0', binary = 'C:/用户/data/native-runtime/0.5.4/tern-turn-relay.exe' },
        { ok = true, runtime_ready = true, version = '0.5.4', binary = 'C:/other.exe' },
    }) do
        local f = fixture('windows')
        f.wizard.open(f:context())
        f:complete(value)
        assert(#f.calls == 1 and f.changes == 0 and #f.errors == 1)
    end
end

function cases.valid_preparation_uses_exact_private_exe()
    local f = fixture('windows')
    f.wizard.open(f:context())
    f:complete({ ok = true, runtime_ready = true, version = '0.5.4', binary = 'C:\\用户\\data\\native-runtime\\0.5.4\\tern-turn-relay.exe' })
    assert(#f.calls == 2 and f.changes == 1)
    local argv = f.calls[2].argv
    assert(argv[1] == 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe' and argv[10] == '--exec' and argv[11] == 'onboarding' and argv[12] == 'inspect')
    f:complete({ ok = true, configured = false, running = false })
    assert(f.inspected == 1 and f.changes == 1)
end

function cases.runtime_reverification_failure_never_reaches_inspect()
    local f = fixture('windows')
    f.wizard.open(f:context())
    f:complete({ ok = true, runtime_ready = true, version = '0.5.4', binary = 'C:/用户/data/native-runtime/0.5.4/tern-turn-relay.exe' })
    assert(f.calls[2].argv[10] == '--exec')
    f:complete({ ok = false, error = 'runtime changed' }, 1)
    assert(f.inspected == 0 and #f.errors == 1 and not f.wizard.active)
end

function cases.timeout_has_unknown_outcome_and_no_retry()
    local f = fixture('windows')
    f.wizard.open(f:context())
    f.time = 323001
    assert(f:tick())
    assert(#f.errors == 1 and f.errors[1]:find('未知') and #f.calls == 1 and f.changes == 0)
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
