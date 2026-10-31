# 仅验证隔离的启动器边界，不使用真实 native 程序、凭据、网络或生产安装。
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Split-Path -Parent $PSScriptRoot
$script = Join-Path $source 'bootstrap-runtime.ps1'
$bytes = [IO.File]::ReadAllBytes($script)
if ($bytes.Length -lt 6 -or [BitConverter]::ToString($bytes, 0, 3) -ne 'EF-BB-BF' -or [BitConverter]::ToString($bytes, 3, 3) -eq 'EF-BB-BF') { throw 'bootstrap 必须恰好一个 UTF-8 BOM' }
$tokens = $null; $errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'bootstrap Parser 失败' }
$root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('relay-exec-test 中文 ' + [Guid]::NewGuid().ToString('N'))
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
function PrivateAcl([bool]$directory) {
    $acl = if ($directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true, $false)
    $inherit = if ($directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($identity in @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($identity)), [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    return $acl
}
function Assert([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
# 用与原生 Windows argv 一致的 CRT 引号规则启动 PowerShell，避免测试本身经 PS5 的旧式 native 参数封送损坏双引号/空参数。
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Text;
public static class BootstrapTestProcess {
    static string Quote(string value) {
        var b=new StringBuilder("\""); int slashes=0;
        foreach(char c in value) {
            if(c=='\\') { slashes++; continue; }
            if(c=='\"') { b.Append('\\',slashes*2+1); b.Append(c); slashes=0; continue; }
            b.Append('\\',slashes); slashes=0; b.Append(c);
        }
        b.Append('\\',slashes*2); return b.Append('"').ToString();
    }
    public static object[] Run(string exe, string[] args, string input) {
        var start=new ProcessStartInfo(exe);
        start.UseShellExecute=false; start.CreateNoWindow=true;
        start.RedirectStandardInput=true; start.RedirectStandardOutput=true; start.RedirectStandardError=true;
        start.StandardOutputEncoding=new UTF8Encoding(false); start.StandardErrorEncoding=new UTF8Encoding(false);
        start.Arguments=String.Join(" ",Array.ConvertAll(args,Quote));
        using(var p=Process.Start(start)) {
            var stdout=p.StandardOutput.ReadToEndAsync(); var stderr=p.StandardError.ReadToEndAsync();
            var bytes=Encoding.UTF8.GetBytes(input);
            p.StandardInput.BaseStream.Write(bytes,0,bytes.Length); p.StandardInput.Close();
            if(!p.WaitForExit(45000)) { p.Kill(); p.WaitForExit(); throw new Exception("launcher deadline"); }
            return new object[] { p.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult() };
        }
    }
}
'@
function InvokeProbe([string[]]$arguments, [string]$inputText = '{}') {
    $argv = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $package 'bootstrap-runtime.ps1'),$data,'--exec') + $arguments
    $result = [BootstrapTestProcess]::Run($systemShell, $argv, $inputText)
    Assert ($result[2].Length -eq 0) '启动器不得向 stderr 输出错误/额外文本'
    Assert ($result[1].Length -le 65536) '启动器输出必须有界'
    return @{ code = $result[0]; value = ($result[1] | ConvertFrom-Json) }
}
try {
    [void][IO.Directory]::CreateDirectory($root, (PrivateAcl $true))
    $package = Join-Path $root 'plugin 中文'
    $data = Join-Path $root 'data 中文'
    $runtimeRoot = Join-Path $data 'native-runtime'
    $runtime = Join-Path $runtimeRoot '0.5.0'
    foreach ($directory in @($package, $data, $runtimeRoot, $runtime)) { [void][IO.Directory]::CreateDirectory($directory, (PrivateAcl $true)) }
    $systemShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    Copy-Item -LiteralPath $script -Destination $package
    $exe = Join-Path $runtime 'tern-turn-relay.exe'
    Add-Type -OutputAssembly $exe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Text;
public static class BootstrapBoundaryProbe {
    public static int Main(string[] args) {
        Console.InputEncoding=new UTF8Encoding(false); Console.OutputEncoding=new UTF8Encoding(false);
        string input=Console.In.ReadToEnd();
        if(args[0]=="nonzero") { Console.Write("{\"ok\":false}"); return 23; }
        if(args[0]=="stderr") { Console.Error.Write("probe diagnostic"); Console.Write("{\"ok\":true}"); return 0; }
        if(args[0]=="oversize") { Console.Write(new string('x',1048576)); return 0; }
        if(args[0]=="invalid-json") { Console.Write("not-json"); return 0; }
        var encoded=Array.ConvertAll(args,s=>"\""+Convert.ToBase64String(Encoding.UTF8.GetBytes(s))+"\"");
        Console.Write("{\"ok\":true,\"args\":["+String.Join(",",encoded)+"],\"input\":\""+Convert.ToBase64String(Encoding.UTF8.GetBytes(input))+"\"}");
        return 0;
    }
}
'@
    [IO.File]::SetAccessControl($exe, (PrivateAcl $false))
    $entry = @{ size = (Get-Item -LiteralPath $exe).Length; sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() }
    $manifest = @{ schema = 1; version = '0.5.0'; assets = @{ 'tern-turn-relay-windows-x86_64.exe' = $entry } } | ConvertTo-Json -Depth 5
    foreach ($manifestPath in @((Join-Path $package 'release.json'), (Join-Path $runtime 'release.json'))) {
        [IO.File]::WriteAllText($manifestPath, $manifest, (New-Object Text.UTF8Encoding($false)))
        [IO.File]::SetAccessControl($manifestPath, (PrivateAcl $false))
    }
    $arguments = @('echo', '--leading', '', '中文 空格', 'a"b', 'tail\', 'space \', 'quote\"end')
    $inputText = '{"note":"中文 UTF-8","count":7}'
    $result = InvokeProbe $arguments $inputText
    Assert ($result.code -eq 0 -and $result.value.ok) '真实 --exec 边界未执行探针'
    Assert ($result.value.args.Count -eq $arguments.Count) 'argv 元素数变化'
    for ($i = 0; $i -lt $arguments.Count; $i++) {
        $actual = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.value.args[$i]))
        Assert ($actual -ceq $arguments[$i]) ('argv 元素变化：' + $i)
    }
    Assert ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.value.input)) -ceq $inputText) 'stdin UTF-8 内容变化'
    $result = InvokeProbe @('nonzero')
    Assert ($result.code -eq 23 -and -not $result.value.ok) '必须保留子程序非零退出码'
    foreach ($mode in @('stderr', 'oversize', 'invalid-json')) {
        $result = InvokeProbe @($mode)
        Assert ($result.code -ne 0 -and -not $result.value.ok) ('无效结果必须失败关闭：' + $mode)
    }
    [IO.File]::AppendAllText($exe, 'changed-after-prepare')
    $result = InvokeProbe @('echo')
    Assert ($result.code -ne 0 -and -not $result.value.ok) '每次 exec 必须复验程序，不能仅因路径存在就执行'
    Write-Output 'PowerShell 5.1 启动器边界通过：单BOM/Parser、argv、UTF-8 stdin、退出码、stderr、输出上限、无效JSON、损坏拒绝（隔离探针；无真实native/网络/凭据）'
} finally {
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
