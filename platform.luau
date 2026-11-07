-- 平台边界不执行进程；所有参数均以 argv 元素传递。
local M = { version = "0.5.10" }

local function windowsPath(path, reported)
    if type(path) ~= "string" then return nil end
    path = path:gsub("\\", "/")
    if reported and path:match("^//%?/[A-Za-z]:/") then path = path:sub(5) end
    if not path:match("^[A-Za-z]:/") or path:find("[%c<>\"|?*]") or path:sub(3):find(":", 1, true) then return nil end
    for part in path:sub(4):gmatch("[^/]+") do
        if part == "." or part == ".." or part:match("[. ]$") then return nil end
        local base = part:match("^[^.]+")
        base = base and base:upper()
        if base == "CON" or base == "PRN" or base == "AUX" or base == "NUL" or (base and (base:match("^COM[1-9]$") or base:match("^LPT[1-9]$"))) then return nil end
    end
    if path:find("//", 1, true) then return nil end
    return path
end

function M.new(runtime, plugin, getenv)
    local windows = runtime.os == "windows"
    local supported = runtime.os == "macos" or runtime.os == "linux" or windows
    local systemRoot = windows and getenv and windowsPath(getenv("SystemRoot"), false) or nil
    if windows and not systemRoot then supported = false end
    local data, package = plugin.data, plugin.dir
    if windows then
        data, package = windowsPath(data, false), windowsPath(package, false)
        supported = supported and data ~= nil and package ~= nil
    end
    local self = { supported = supported, windows = windows }
    self.binary = (data or plugin.data) .. "/native-runtime/" .. M.version .. "/tern-turn-relay" .. (windows and ".exe" or "")
    function self.bootstrap(mode, nativeArgs)
        assert(self.supported, "当前平台或插件路径不受支持")
        assert(mode == "report" or mode == "--prepare" or mode == "--exec", "无效运行时操作")
        local argv
        if windows then
            -- 固定系统执行器，绝不搜索 PATH；脚本再次核验实际系统目录与架构。
            argv = { systemRoot .. "/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", package .. "/bootstrap-runtime.ps1", data, mode }
        else
            argv = { "/bin/sh", package .. "/bootstrap-runtime.sh", data }
            if mode ~= "report" then table.insert(argv, mode) end
        end
        if nativeArgs then
            assert(mode == "--exec" and #nativeArgs > 0, "无效原生参数")
            for _, arg in ipairs(nativeArgs) do table.insert(argv, arg) end
        end
        return argv
    end
    function self.ready(value)
        if type(value) ~= "table" or value.ok ~= true or value.runtime_ready ~= true or value.version ~= M.version then return false end
        local path = windows and windowsPath(value.binary, true) or value.binary
        return path == self.binary
    end
    return self
end
return M
