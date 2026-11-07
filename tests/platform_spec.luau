local Platform = require('../platform')
local cases = {}
local function new(runtime, plugin)
    return Platform.new(runtime, plugin, function(name) assert(name == 'SystemRoot'); return 'D:\\WINDOWS' end)
end

function cases.windows_paths_are_separate_arguments()
    local p = new({ os = 'windows' }, { data = 'C:\\用户\\我的 Tern\\data', dir = 'C:/用户/我的 Tern/plugin' })
    assert(p.supported and p.binary == 'C:/用户/我的 Tern/data/native-runtime/0.5.10/tern-turn-relay.exe')
    local argv = p.bootstrap('--prepare')
    assert(argv[1] == 'D:/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe')
    assert(argv[7] == '-File' and argv[8] == 'C:/用户/我的 Tern/plugin/bootstrap-runtime.ps1')
    assert(argv[9] == 'C:/用户/我的 Tern/data' and argv[10] == '--prepare')
    local exec = p.bootstrap('--exec', { 'onboarding', 'inspect', '--data-dir', 'C:/用户/我的 Tern/data' })
    assert(exec[10] == '--exec' and exec[14] == 'C:/用户/我的 Tern/data')
end

function cases.exec_preserves_all_argument_boundaries()
    local args = { 'onboarding', '--literal', '', '中文 空格', 'a"b', 'trailing\\', 'space \\', 'quote\\"end' }
    for _, os in ipairs({ 'windows', 'macos', 'linux' }) do
        local p = new({ os = os }, { data = os == 'windows' and 'C:/data' or '/Users/data', dir = os == 'windows' and 'C:/plugin' or '/Users/plugin' })
        local argv = p.bootstrap('--exec', args)
        local offset = os == 'windows' and 10 or 4
        assert(argv[offset] == '--exec')
        for i, arg in ipairs(args) do assert(argv[offset + i] == arg) end
    end
end

function cases.report_never_promotes_to_prepare()
    for _, os in ipairs({ 'macos', 'linux', 'windows' }) do
        local p = new({ os = os }, { data = os == 'windows' and 'C:/用户/data' or '/Users/用户/data', dir = os == 'windows' and 'C:/用户/plugin' or '/Users/用户/plugin' })
        for _, arg in ipairs(p.bootstrap('report')) do assert(arg ~= '--prepare') end
        assert(not p.ready({ ok = true, binary = p.binary, runtime_ready = true, version = '0.4.0' }))
        assert(not p.ready({ ok = true, binary = p.binary, runtime_ready = false, version = '0.5.10' }))
        assert(not p.ready({ ok = false, binary = p.binary, runtime_ready = true, version = '0.5.10' }))
        assert(p.ready({ ok = true, binary = p.binary, runtime_ready = true, version = '0.5.10' }))
    end
end

function cases.unix_clients_share_the_sh_bootstrap()
    for _, os in ipairs({ 'macos', 'linux' }) do
        local p = Platform.new({ os = os }, { data = '/home/a b/data', dir = '/home/a b/plugin' })
        assert(p.supported)
        local argv = p.bootstrap('--prepare')
        assert(#argv == 4 and argv[1] == '/bin/sh' and argv[2] == '/home/a b/plugin/bootstrap-runtime.sh')
        assert(argv[3] == '/home/a b/data' and argv[4] == '--prepare')
        assert(p.binary == '/home/a b/data/native-runtime/0.5.10/tern-turn-relay')
    end
    local ios = Platform.new({ os = 'ios' }, { data = '/tmp/data', dir = '/tmp/plugin' })
    assert(not ios.supported)
    assert(not pcall(function() ios.bootstrap('--prepare') end))
end

function cases.unsafe_paths_and_runtime_substitution_are_rejected()
    for _, path in ipairs({ '//server/share', 'C:/data/../escape', 'C:/data:stream', 'C:/data//child', 'C:/data/child.' }) do
        assert(not new({ os = 'windows' }, { data = path, dir = 'C:/plugin' }).supported)
    end
    local p = new({ os = 'windows' }, { data = 'C:/data', dir = 'C:/plugin' })
    assert(p.ready({ ok = true, runtime_ready = true, version = '0.5.10', binary = '\\\\?\\C:\\data\\native-runtime\\0.5.10\\tern-turn-relay.exe' }))
    assert(not p.ready({ ok = true, runtime_ready = true, version = '0.5.10', binary = 'C:/data/native-runtime/0.5.10/../evil.exe' }))
end

function cases.untrusted_or_missing_system_root_fails_closed()
    local plugin = { data = 'C:/data', dir = 'C:/plugin' }
    for _, root in ipairs({ '//server/share', 'C:/Windows/..', 'C:/Windows:stream' }) do
        assert(not Platform.new({ os = 'windows' }, plugin, function() return root end).supported)
    end
    assert(not Platform.new({ os = 'windows' }, plugin, function() return nil end).supported)
end

return { run = function()
    local passed = 0
    for name, test in pairs(cases) do
        local ok, err = pcall(test)
        assert(ok, name .. ': ' .. tostring(err))
        passed += 1
    end
    return passed
end }
