# 仅显式 --prepare 下载；report / --exec 绝不准备缺失的运行时。
# PowerShell 是短命启动器；转发、凭据和生命周期仍由 Rust 实现。
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$handles = New-Object 'System.Collections.Generic.List[System.IDisposable]'
$stage = $null
$mutex = $null
$locked = $false
$exitCode = 1
try {
    if ($args.Count -lt 1) { throw 'arguments' }
    $dataArgument = [string]$args[0]
    $mode = if ($args.Count -gt 1) { [string]$args[1] } else { 'report' }
    $nativeArgs = @()
    if ($mode -eq '--exec') {
        if ($args.Count -lt 3) { throw 'arguments' }
        $nativeArgs = @($args[2..($args.Count - 1)])
    } elseif (($mode -ne 'report' -and $mode -ne '--prepare') -or $args.Count -gt 2) { throw 'arguments' }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess) { throw 'platform' }
    # IsWow64Process2 区分原生 AMD64 与 ARM64 仿真，不把后者声称为支持平台。
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RelayBootstrapNative {
    [StructLayout(LayoutKind.Sequential)] public struct Info {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    public static SafeFileHandle Pin(string path, bool directory) {
        var handle=CreateFile(path, 0x80000000, directory ? 3u : 1u, IntPtr.Zero, 3, 0x00200000u | (directory ? 0x02000000u : 0u), IntPtr.Zero);
        Info info;
        if(handle.IsInvalid || !GetFileInformationByHandle(handle,out info) || (info.Attributes & 0x400)!=0 || (!directory && info.Links!=1)) {
            handle.Dispose(); throw new IOException("Unsafe object");
        }
        return handle;
    }
    public static string Quote(string value) {
        var b=new System.Text.StringBuilder("\""); int slashes=0;
        foreach(char c in value) {
            if(c=='\\') { slashes++; continue; }
            if(c=='\"') { b.Append('\\',slashes*2+1); b.Append(c); slashes=0; continue; }
            b.Append('\\',slashes); slashes=0; b.Append(c);
        }
        b.Append('\\',slashes*2); return b.Append('"').ToString();
    }
    public static string BoundedRead(TextReader reader, int limit) {
        var b=new System.Text.StringBuilder(); var buffer=new char[4096]; int n;
        while((n=reader.Read(buffer,0,buffer.Length))!=0) {
            if(b.Length+n>limit) throw new IOException("Output limit"); b.Append(buffer,0,n);
        }
        return b.ToString();
    }
    public static System.Threading.Tasks.Task<string> ReadAsync(TextReader reader, int limit) {
        return System.Threading.Tasks.Task.Run(() => BoundedRead(reader,limit));
    }
}
'@
    [uint16]$processMachine = 0; [uint16]$nativeMachine = 0
    if (-not [RelayBootstrapNative]::IsWow64Process2([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$processMachine, [ref]$nativeMachine) -or $nativeMachine -ne 0x8664) { throw 'architecture' }
    $expectedShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    if (-not [string]::Equals([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName, $expectedShell, [StringComparison]::OrdinalIgnoreCase)) { throw 'executor' }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $trusted = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
    $trustedOwners = $trusted + @('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    function Canonical([string]$path) {
        $path = $path.Replace('/', '\')
        if ($path -notmatch '^[A-Za-z]:\\' -or $path.Substring(2).Contains(':') -or $path -match '[\x00-\x1f\x7f<>"|?*]' -or $path.Contains('\\')) { throw 'path' }
        foreach ($part in $path.Substring(3).Split('\')) {
            if (-not $part -or $part -eq '.' -or $part -eq '..' -or $part -match '[. ]$' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'path' }
        }
        if ([IO.Path]::GetFullPath($path) -cne $path) { throw 'path' }
        return $path
    }
    function CheckAcl([string]$path, [bool]$private, [bool]$directory) {
        # 普通宿主资源属于已接受的信任环境；仅专用运行时强制私有 ACL。
        if (-not $private) { return }
        $acl = Get-Acl -LiteralPath $path
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if (($private -and $owner -ne $sid.Value) -or (-not $private -and $trustedOwners -notcontains $owner)) { throw 'owner' }
        if ($private -and -not $acl.AreAccessRulesProtected) { throw 'inheritance' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            if ($trusted -contains $rule.IdentityReference.Value) { continue }
            # 祖先允许列目录/创建其他子项，但不允许替换当前受保护子目录。
            $mask = if ($private) { 0x1f01ff } elseif ($directory) { 0x000d0040 } else { 0x000d0116 }
            if (([int]$rule.FileSystemRights -band $mask) -ne 0) { throw 'acl' }
        }
    }
    function Pin([string]$path, [bool]$private, [bool]$directory) {
        $handle = [RelayBootstrapNative]::Pin($path, $directory)
        $handles.Add($handle)
        CheckAcl $path $private $directory
    }
    function Ancestors([string]$path) {
        $parent = [IO.Path]::GetDirectoryName($path)
        if (-not $parent) { return }
        $chain = New-Object 'System.Collections.Generic.List[string]'
        while ($parent) { $chain.Add($parent); $parent = [IO.Path]::GetDirectoryName($parent) }
        for ($i = $chain.Count - 1; $i -ge 0; $i--) {
            if ([IO.Directory]::Exists($chain[$i]) -or [IO.File]::Exists($chain[$i])) { Pin $chain[$i] $false $true }
        }
    }
    function PrivateAcl([bool]$directory) {
        $acl = if ($directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
        $acl.SetOwner($sid)
        $acl.SetAccessRuleProtection($true, $false)
        $inherit = if ($directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
        foreach ($identity in $trusted) {
            $id = New-Object Security.Principal.SecurityIdentifier($identity)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($id, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($rule)
        }
        return $acl
    }
    function EnsurePrivate([string]$path) {
        if ([IO.Directory]::Exists($path) -or [IO.File]::Exists($path)) {
            if ($mode -eq '--prepare') {
                Pin $path $false $true
                $existing = Get-Acl -LiteralPath $path
                if ($existing.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'owner' }
                # Tern 创建的数据目录可能继承只读权限；只在明确准备时收紧本用户目录。
                [IO.Directory]::SetAccessControl($path, (PrivateAcl $true))
            }
            Pin $path $true $true
            return
        }
        if ($mode -ne '--prepare') { throw 'missing-runtime' }
        # 现有祖先已 pin；缺失祖先逐级以私有 DACL 创建，查询绝不写目录。
        $parent = [IO.Path]::GetDirectoryName($path)
        if (-not [IO.Directory]::Exists($parent)) { EnsurePrivate $parent }
        [void][IO.Directory]::CreateDirectory($path, (PrivateAcl $true))
        Pin $path $true $true
    }
    $data = Canonical $dataArgument
    $package = Canonical $PSScriptRoot
    Ancestors $data
    $packageHandleStart = $handles.Count
    Ancestors $package
    Pin $package $false $true
    $manifest = Join-Path $package 'release.json'
    Pin $manifest $false $false
    if ((Get-Acl -LiteralPath $manifest).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'manifest-owner' }
    $info = Get-Item -LiteralPath $manifest
    if ($info.Length -lt 1 -or $info.Length -gt 65536) { throw 'manifest-size' }
    $manifestBytes = [IO.File]::ReadAllBytes($manifest)
    $release = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    $version = '0.5.0'
    $asset = 'tern-turn-relay-windows-x86_64.exe'
    if ($release.schema -isnot [int] -or $release.schema -ne 1 -or $release.version -isnot [string] -or $release.version -cne $version) { throw 'manifest-version' }
    $entry = $release.assets.$asset
    if ($entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or ($entry.size -isnot [int] -and $entry.size -isnot [long]) -or $entry.size -le 0 -or $entry.size -gt 67108864) { throw 'manifest-asset' }
    $packageHandleCount = $handles.Count - $packageHandleStart
    if (-not [IO.Directory]::Exists($data)) {
        if ($mode -ne '--prepare') { throw 'missing-runtime' }
        [void][IO.Directory]::CreateDirectory($data)
    }
    Pin $data $false $true
    $root = Join-Path $data 'native-runtime'
    EnsurePrivate $root
    $runtime = Join-Path $root $version
    $binary = Join-Path $runtime 'tern-turn-relay.exe'
    function VerifyRuntime {
        Pin $runtime $true $true
        Pin $binary $true $false
        Pin (Join-Path $runtime 'release.json') $true $false
        if ((Get-Item -LiteralPath $binary).Length -ne $entry.size -or (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'binary-verification' }
        if ((Get-Item -LiteralPath (Join-Path $runtime 'release.json')).Length -ne $manifestBytes.Length) { throw 'runtime-manifest-size' }
        $stored = [IO.File]::ReadAllBytes((Join-Path $runtime 'release.json'))
        if ($stored.Length -ne $manifestBytes.Length -or [Convert]::ToBase64String($stored) -cne [Convert]::ToBase64String($manifestBytes)) { throw 'runtime-manifest' }
    }
    if (-not [IO.Directory]::Exists($runtime)) {
        if ($mode -ne '--prepare') { throw 'missing-runtime' }
        $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($data))
        if ($drive.AvailableFreeSpace -lt 268435456) { throw 'storage' }
        # 内核互斥体不留下 PID 锁；崩溃后的 abandoned mutex 只授予锁，不杀进程。
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $lockId = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($data.ToLowerInvariant())))).Replace('-', '') } finally { $sha.Dispose() }
        $mutexAcl = New-Object Security.AccessControl.MutexSecurity
        $mutexAcl.SetAccessRuleProtection($true, $false)
        foreach ($identity in $trusted) { $mutexAcl.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule((New-Object Security.Principal.SecurityIdentifier($identity)), [Security.AccessControl.MutexRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))) }
        $created = $false
        $mutex = [Threading.Mutex]::new($false, ('Global\TernTurnRelayBootstrap-' + $lockId), [ref]$created, $mutexAcl)
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'busy' }
        if ([IO.Directory]::Exists($runtime) -or [IO.File]::Exists($runtime)) { throw 'runtime-appeared' }
        $stage = Join-Path $root ('.stage-' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($stage, (PrivateAcl $true))
        CheckAcl $stage $true $true
        $download = Join-Path $stage 'tern-turn-relay.exe'
        $url = 'https://github.com/jiwangyihao/tern-turn-relay/releases/download/v' + $version + '/' + $asset
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $response = $null; $stream = $null; $file = $null
        try {
            for ($redirects = 0; ; $redirects++) {
                if ($redirects -gt 5 -or $watch.Elapsed.TotalSeconds -ge 180) { throw 'download-limit' }
                $uri = New-Object Uri($url)
                if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Port -ne 443 -or ($uri.Host -ne 'github.com' -and $uri.Host -ne 'release-assets.githubusercontent.com' -and $uri.Host -ne 'objects.githubusercontent.com')) { throw 'download-origin' }
                $request = [Net.HttpWebRequest]::Create($uri)
                $request.Proxy = $null; $request.AllowAutoRedirect = $false
                $request.Timeout = [Math]::Max(1, [Math]::Min(15000, [int](180000 - $watch.ElapsedMilliseconds))); $request.ReadWriteTimeout = $request.Timeout
                $response = $request.GetResponse()
                if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
                    $url = (New-Object Uri($uri, $response.Headers['Location'])).AbsoluteUri
                    $response.Dispose(); $response = $null; continue
                }
                if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -gt $entry.size) { throw 'download-size' }
                break
            }
            $stream = $response.GetResponseStream()
            $file = New-Object IO.FileStream($download, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 65536, [IO.FileOptions]::None, (PrivateAcl $false))
            $buffer = New-Object byte[] 65536
            [long]$total = 0
            while ($true) {
                if ($watch.Elapsed.TotalSeconds -ge 180) { throw 'download-limit' }
                $stream.ReadTimeout = [Math]::Max(1, [Math]::Min(15000, [int](180000 - $watch.ElapsedMilliseconds)))
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -eq 0) { break }
                $total += $read
                if ($total -gt $entry.size -or $watch.Elapsed.TotalSeconds -ge 180) { throw 'download-limit' }
                $file.Write($buffer, 0, $read)
            }
            if ($total -ne $entry.size -or $watch.Elapsed.TotalSeconds -ge 180) { throw 'download-size' }
            $file.Flush($true)
        } finally {
            if ($file) { $file.Dispose() }; if ($stream) { $stream.Dispose() }; if ($response) { $response.Dispose() }
        }
        if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'download-sha256' }
        $manifestCopy = Join-Path $stage 'release.json'
        $file = New-Object IO.FileStream($manifestCopy, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, (PrivateAcl $false))
        try { $file.Write($manifestBytes, 0, $manifestBytes.Length); $file.Flush($true) } finally { $file.Dispose() }
        # 同卷目录 rename；目标若已存在则失败，不覆盖旧版本或其他归属目录。
        [IO.Directory]::Move($stage, $runtime)
        $stage = $null
    }
    VerifyRuntime
    if ($mode -eq '--exec') {
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $binary
        $start.Arguments = (($nativeArgs | ForEach-Object { [RelayBootstrapNative]::Quote([string]$_) }) -join ' ')
        $start.UseShellExecute = $false; $start.CreateNoWindow = $true
        $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
        $start.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
        $child = New-Object Diagnostics.Process
        $child.StartInfo = $start
        try {
            $inputText = [RelayBootstrapNative]::BoundedRead([Console]::In, 65536)
            # 校验已经绑定到私有 runtime 中的副本。执行管理命令前释放注册树，
            # 否则没有 FILE_SHARE_DELETE 的包/清单句柄会阻止 update/uninstall 移动注册。
            # 数据祖先、runtime 目录、二进制和其清单仍固定到子进程退出。
            for ($i = $packageHandleStart; $i -lt $packageHandleStart + $packageHandleCount; $i++) { $handles[$i].Dispose() }
            $handles.RemoveRange($packageHandleStart, $packageHandleCount)
            if (-not $child.Start()) { throw 'launch' }
            $out = [RelayBootstrapNative]::ReadAsync($child.StandardOutput, 65536)
            $err = [RelayBootstrapNative]::ReadAsync($child.StandardError, 4096)
            $child.StandardInput.Write($inputText); $child.StandardInput.Close(); $inputText = $null
            if (-not $child.WaitForExit(360000)) { $child.Kill(); throw 'timeout' }
            $outputText = $out.GetAwaiter().GetResult()
            if ($outputText.Length -gt 65536 -or $err.GetAwaiter().GetResult().Length -gt 0) { throw 'output' }
            [void]($outputText | ConvertFrom-Json)
            [Console]::Out.Write($outputText)
            $exitCode = $child.ExitCode
        } finally { $child.Dispose() }
    } else {
        @{ ok = $true; runtime_ready = $true; binary = $binary; version = $version } | ConvertTo-Json -Compress
        $exitCode = 0
    }
} catch {
    # 不输出异常对象、URL、argv 或 stdin；这些内容可能包含秘密。
    [Console]::Out.WriteLine('{"ok":false,"error":"原生运行时校验或准备失败；已有配置、凭据及运行时保持不变。请检查平台、私有目录权限和网络后显式重试 Settings。"}')
} finally {
    foreach ($handle in $handles) { $handle.Dispose() }
    if ($stage -and [IO.Directory]::Exists($stage)) {
        try {
            if (((Get-Item -LiteralPath $stage -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                foreach ($name in @('tern-turn-relay.exe', 'release.json')) {
                    $item = Join-Path $stage $name
                    if ([IO.File]::Exists($item)) { [IO.File]::Delete($item) }
                }
                [IO.Directory]::Delete($stage, $false)
            }
        } catch { }
    }
    if ($locked) { $mutex.ReleaseMutex() }
    if ($mutex) { $mutex.Dispose() }
}
exit $exitCode
