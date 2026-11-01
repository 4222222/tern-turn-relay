param([Parameter(Mandatory=$true)][string]$Binary)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$source = Split-Path -Parent $PSScriptRoot
$systemShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('relay-test 中文 ' + [Guid]::NewGuid().ToString('N'))
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
function Secure([string]$path, [bool]$directory) {
    $acl = if ($directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true, $false)
    $inherit = if ($directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($identity in @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($identity)), [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    if ($directory) { [IO.Directory]::SetAccessControl($path, $acl) } else { [IO.File]::SetAccessControl($path, $acl) }
}
function Assert([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
function InvokeBootstrap([string]$data, [string[]]$arguments) {
    $output = '{}' | & $systemShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $package 'bootstrap-runtime.ps1') $data @arguments
    $code = $LASTEXITCODE
    $text = $output -join "`n"
    Assert ($text.Length -le 65536) '输出超过上限'
    $value = $text | ConvertFrom-Json
    return @{ code = $code; value = $value }
}
try {
    [void][IO.Directory]::CreateDirectory($root); Secure $root $true
    $package = Join-Path $root 'plugin 中文'
    [void][IO.Directory]::CreateDirectory($package); Secure $package $true
    Copy-Item -LiteralPath (Join-Path $source 'bootstrap-runtime.ps1') -Destination $package
    Secure (Join-Path $package 'bootstrap-runtime.ps1') $false
    $version = '0.5.2'
    $asset = 'tern-turn-relay-windows-x86_64.exe'
    $entry = @{ size = (Get-Item -LiteralPath $binaryPath).Length; sha256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    $manifest = @{ schema = 1; version = $version; assets = @{ $asset = $entry } } | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $package 'release.json'), $manifest, (New-Object Text.UTF8Encoding($false)))
    Secure (Join-Path $package 'release.json') $false
    $data = Join-Path $root 'data 中文'
    foreach ($mode in @('report', '--exec')) {
        $arguments = if ($mode -eq '--exec') { @('--exec', '--version') } else { @('report') }
        $result = InvokeBootstrap $data $arguments
        Assert ($result.code -ne 0 -and -not $result.value.ok) '缺运行时必须失败'
        Assert (-not [IO.Directory]::Exists($data)) '查询或 exec 不得创建数据目录/下载'
    }
    foreach ($path in @(($data + ':stream'), ($data + '\..\escape'), '\\server\share\data')) {
        $result = InvokeBootstrap $path @('report')
        Assert ($result.code -ne 0 -and -not $result.value.ok) '危险路径必须失败'
    }
    [void][IO.Directory]::CreateDirectory($data); Secure $data $true
    $runtimeRoot = Join-Path $data 'native-runtime'
    [void][IO.Directory]::CreateDirectory($runtimeRoot); Secure $runtimeRoot $true
    $runtime = Join-Path $runtimeRoot $version
    [void][IO.Directory]::CreateDirectory($runtime); Secure $runtime $true
    $exe = Join-Path $runtime 'tern-turn-relay.exe'
    Copy-Item -LiteralPath $binaryPath -Destination $exe; Secure $exe $false
    Copy-Item -LiteralPath (Join-Path $package 'release.json') -Destination $runtime
    Secure (Join-Path $runtime 'release.json') $false
    # 宿主/普通数据目录允许额外写权限；查询与准备不得修改其 ACL。
    foreach ($ordinary in @($root, $package, $data)) {
        $acl = Get-Acl -LiteralPath $ordinary
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), [Security.AccessControl.FileSystemRights]::Modify, [Security.AccessControl.AccessControlType]::Allow)))
        [IO.Directory]::SetAccessControl($ordinary, $acl)
    }
    $dataAclBefore = (Get-Acl -LiteralPath $data).Sddl
    $packageAclBefore = (Get-Acl -LiteralPath $package).Sddl
    $result = InvokeBootstrap $data @('report')
    Assert ($result.code -eq 0 -and $result.value.runtime_ready -and $result.value.binary -eq $exe) '已验证运行时报告错误'
    $result = InvokeBootstrap $data @('--exec', '--version')
    Assert ($result.code -eq 0 -and $result.value.version -eq $version -and $result.value.runtime -eq 'rust') 'exec 未调用真实二进制'
    $result = InvokeBootstrap $data @('--prepare')
    Assert ($result.code -eq 0 -and $result.value.runtime_ready) '已安装运行时应离线复用'
    Assert ((Get-Acl -LiteralPath $data).Sddl -eq $dataAclBefore) '准备不得收紧普通数据目录权限'
    Assert ((Get-Acl -LiteralPath $package).Sddl -eq $packageAclBefore) '准备不得收紧宿主插件目录权限'
    $sentinel = Join-Path $data 'credentials.json'
    [IO.File]::WriteAllText($sentinel, 'preserve-me'); Secure $sentinel $false
    [IO.File]::AppendAllText($exe, 'corrupted')
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    $result = InvokeBootstrap $data @('--prepare')
    Assert ($result.code -ne 0 -and -not $result.value.ok) '损坏的已有程序必须拒绝'
    Assert ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -eq $hash -and [IO.File]::ReadAllText($sentinel) -eq 'preserve-me') '失败不应覆盖原文件'
    Remove-Item -LiteralPath $exe
    $linkTarget = Join-Path $root 'linked.exe'
    Copy-Item -LiteralPath $binaryPath -Destination $linkTarget; Secure $linkTarget $false
    New-Item -ItemType HardLink -Path $exe -Target $linkTarget | Out-Null
    $result = InvokeBootstrap $data @('report')
    Assert ($result.code -ne 0 -and -not $result.value.ok) '硬链接程序必须拒绝'
    Remove-Item -LiteralPath $exe
    $junction = Join-Path $root 'junction'
    New-Item -ItemType Junction -Path $junction -Target $data | Out-Null
    $result = InvokeBootstrap $junction @('report')
    Assert ($result.code -ne 0 -and -not $result.value.ok) 'junction 必须拒绝'
    [IO.Directory]::Delete($junction)
    # 在真实 --exec 调用期间移动注册目录，锁定共享句柄回归；不调用生产更新或联网。
    Add-Type -OutputAssembly $exe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.IO;
public static class BootstrapHandleProbe {
    public static int Main(string[] args) {
        try {
            Directory.Move(args[0],args[1]);
            Directory.Move(args[1],args[0]);
            bool protectedBinary=false;
            try { File.Move(args[2],args[2]+".moved"); File.Move(args[2]+".moved",args[2]); }
            catch(IOException) { protectedBinary=true; }
            catch(UnauthorizedAccessException) { protectedBinary=true; }
            if(!protectedBinary) return 2;
            Console.WriteLine("{\"ok\":true,\"registration_movable\":true,\"binary_protected\":true}");
            return 0;
        } catch { Console.WriteLine("{\"ok\":false}"); return 1; }
    }
}
'@
    Secure $exe $false
    $entry = @{ size = (Get-Item -LiteralPath $exe).Length; sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() }
    $probeManifest = @{ schema = 1; version = $version; assets = @{ $asset = $entry } } | ConvertTo-Json -Depth 5
    foreach ($manifestPath in @((Join-Path $package 'release.json'), (Join-Path $runtime 'release.json'))) {
        [IO.File]::WriteAllText($manifestPath, $probeManifest, (New-Object Text.UTF8Encoding($false)))
        Secure $manifestPath $false
    }
    $result = InvokeBootstrap $data @('--exec', $package, ($package + ' moved'), $exe)
    Assert ($result.code -eq 0 -and $result.value.registration_movable -and $result.value.binary_protected) '--exec 应允许注册目录移动，同时继续保护已验证程序'
    Write-Output 'Windows 准备器行为测试通过（无网络下载/无真实凭据）'
} finally {
    $junctionPath = Join-Path $root 'junction'
    if ([IO.Directory]::Exists($junctionPath)) { [IO.Directory]::Delete($junctionPath) }
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
& (Join-Path $PSScriptRoot 'bootstrap_exec_spec.ps1')
