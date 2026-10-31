//! Owned Windows subprocesses. A suspended child enters a kill-on-close job before it runs.
use crate::common::{Error, Result};
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Component, Path},
    process::{Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    time::timeout,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        SystemInformation::GetSystemDirectoryW,
        Threading::{
            GetProcessIdOfThread, OpenThread, ResumeThread, CREATE_NEW_PROCESS_GROUP,
            CREATE_NO_WINDOW, CREATE_SUSPENDED, THREAD_QUERY_LIMITED_INFORMATION,
            THREAD_SUSPEND_RESUME,
        },
    },
};

fn failure(code: &'static str) -> Error {
    Error::new(
        code,
        "Cannot securely control the owned Windows subprocess; private diagnostics withheld.",
    )
}

/// 子进程必须只继承显式配置的 stdio，不能保留启动器的响应管道写端。
pub(crate) fn prevent_stdio_inheritance() -> Result<()> {
    use windows_sys::Win32::{
        Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT},
        System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE},
    };
    for stream in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe { GetStdHandle(stream) };
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE
            && unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0
        {
            return Err(failure("process-stdio"));
        }
    }
    Ok(())
}

/// Resolve a fixed relative executable below the OS-reported system directory, never PATH.
pub(crate) fn system_program(relative: &str) -> Result<String> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(failure("process-path"));
    }
    let mut buffer = vec![0u16; 260];
    let mut length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 {
        return Err(failure("process-path"));
    }
    if length as usize >= buffer.len() {
        buffer.resize(length as usize + 1, 0);
        length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 || length as usize >= buffer.len() {
            return Err(failure("process-path"));
        }
    }
    let base =
        String::from_utf16(&buffer[..length as usize]).map_err(|_| failure("process-path"))?;
    let path = Path::new(&base).join(relative);
    if !path.is_file() {
        return Err(Error::new(
            "required-program-missing",
            "A required Windows system program is not installed.",
        ));
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| failure("process-path"))
}

pub(crate) struct OwnedJob {
    handle: OwnedHandle,
    // Keep the executable and its directory ancestry pinned across spawn and execution.
    _executable: crate::windows_security::Opened,
}

impl OwnedJob {
    fn new(executable: crate::windows_security::Opened) -> Result<Self> {
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(failure("process-job"));
        }
        let job = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw) },
            _executable: executable,
        };
        job.set_kill_on_close(true)?;
        Ok(job)
    }

    fn set_kill_on_close(&self, enabled: bool) -> Result<()> {
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        if enabled {
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        let ok = unsafe {
            SetInformationJobObject(
                self.handle.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(failure("process-job"));
        }
        Ok(())
    }

    pub(crate) fn terminate(&self) -> Result<()> {
        if unsafe { TerminateJobObject(self.handle.as_raw_handle() as HANDLE, 1) } == 0 {
            return Err(failure("process-stop"));
        }
        Ok(())
    }

    /// Only a successfully authenticated, ready background service may outlive its launcher.
    pub(crate) fn release(self) -> Result<()> {
        self.set_kill_on_close(false)
    }
}

fn resume_owned_threads(pid: u32) -> Result<()> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(failure("process-resume"));
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut present = unsafe { Thread32First(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    let mut resumed = false;
    while present != 0 {
        if entry.th32OwnerProcessID == pid {
            let raw = unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    entry.th32ThreadID,
                )
            };
            if raw.is_null() {
                return Err(failure("process-resume"));
            }
            let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
            if unsafe { GetProcessIdOfThread(thread.as_raw_handle() as HANDLE) } != pid
                || unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } == u32::MAX
            {
                return Err(failure("process-resume"));
            }
            resumed = true;
        }
        present = unsafe { Thread32Next(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    }
    if !resumed {
        return Err(failure("process-resume"));
    }
    Ok(())
}

/// No untrusted child code runs before assignment to the owned job.
pub(crate) fn spawn(command: &mut Command, detached: bool) -> Result<(Child, OwnedJob)> {
    let executable =
        crate::windows_security::open(Path::new(command.as_std().get_program()), false, true)?
            .ok_or_else(|| failure("process-path"))?;
    let job = OwnedJob::new(executable)?;
    command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    command.kill_on_drop(!detached);
    let mut child = command.spawn().map_err(|_| failure("process-start"))?;
    let handle = child
        .raw_handle()
        .ok_or_else(|| failure("process-ownership-lost"))?;
    if unsafe { AssignProcessToJobObject(job.handle.as_raw_handle() as HANDLE, handle as HANDLE) }
        == 0
    {
        let _ = child.start_kill();
        return Err(failure("process-job"));
    }
    let pid = child
        .id()
        .ok_or_else(|| failure("process-ownership-lost"))?;
    if let Err(error) = resume_owned_threads(pid) {
        let _ = job.terminate();
        let _ = child.start_kill();
        return Err(error);
    }
    Ok((child, job))
}

async fn bounded_output<R: AsyncRead + Unpin>(reader: R) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .await
        .map_err(|_| failure("process-io"))?;
    if data.len() > 1024 * 1024 {
        return Err(Error::new(
            "response-limit",
            "Owned subprocess output exceeded its limit.",
        ));
    }
    Ok(data)
}

pub(crate) async fn run(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    deadline: Duration,
) -> Result<Output> {
    run_with_env(program, args, input, deadline, &[]).await
}

pub(crate) async fn run_with_env(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    deadline: Duration,
    environment: &[(&str, &str)],
) -> Result<Output> {
    let mut command = Command::new(program);
    command
        .args(args)
        .envs(environment.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (mut child, job) = spawn(&mut command, false)?;
    let mut stdin = child.stdin.take().ok_or_else(|| failure("process-io"))?;
    let stdout = child.stdout.take().ok_or_else(|| failure("process-io"))?;
    let stderr = child.stderr.take().ok_or_else(|| failure("process-io"))?;
    let operation = async {
        let send = async {
            if let Some(data) = input {
                stdin
                    .write_all(data)
                    .await
                    .map_err(|_| failure("process-io"))?;
            }
            drop(stdin);
            Ok::<_, Error>(())
        };
        let exit = async {
            let status = child.wait().await.map_err(|_| failure("process-wait"))?;
            job.terminate()?;
            Ok::<_, Error>(status)
        };
        let (stdout, stderr, (), status) =
            tokio::try_join!(bounded_output(stdout), bounded_output(stderr), send, exit,)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    };
    match timeout(deadline, operation).await {
        Ok(Ok(output)) => Ok(output),
        failed => {
            let _ = job.terminate();
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(3), child.wait()).await;
            match failed {
                Ok(Err(error)) => Err(error),
                _ => Err(Error::new(
                    "process-timeout",
                    "Owned subprocess exceeded its operation deadline.",
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn powershell() -> String {
        system_program(r"WindowsPowerShell\v1.0\powershell.exe").unwrap()
    }
    fn args(script: &str) -> Vec<String> {
        ["-NoProfile", "-NonInteractive", "-Command", script]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    #[tokio::test]
    async fn nonzero_exit_preserves_separate_streams() {
        let output = run(
            &powershell(),
            &args("[Console]::Out.Write('stdout'); [Console]::Error.Write('stderr'); exit 7"),
            None,
            Duration::from_secs(20),
        )
        .await
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
    }

    #[tokio::test]
    async fn excessive_output_is_rejected_and_owned_process_stops() {
        let error = run(
            &powershell(),
            &args("[Console]::Out.Write(('x' * 1048577)); Start-Sleep -Seconds 60"),
            None,
            Duration::from_secs(20),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "response-limit");
    }

    #[tokio::test]
    async fn deadline_terminates_an_owned_sleeping_process() {
        let error = run(
            &powershell(),
            &args("Start-Sleep -Seconds 60"),
            None,
            Duration::from_millis(300),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "process-timeout");
    }

    #[test]
    fn system_program_rejects_escape_and_absolute_paths() {
        for path in [
            "",
            "../cmd.exe",
            r"..\cmd.exe",
            r"C:\Windows\cmd.exe",
            r"\\server\cmd.exe",
        ] {
            assert!(
                system_program(path).is_err(),
                "unexpected trusted system path"
            );
        }
    }

    #[tokio::test]
    async fn cancelling_an_owned_job_stops_descendants_but_not_another_job() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use windows_sys::Win32::{
            Foundation::WAIT_OBJECT_0,
            System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS},
        };
        let executable = powershell();
        let mut unrelated_command = Command::new(&executable);
        unrelated_command
            .args(args("Start-Sleep -Seconds 60"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut unrelated, unrelated_job) = spawn(&mut unrelated_command, false).unwrap();
        let script = r#"$p = [Diagnostics.ProcessStartInfo]::new(); $p.FileName = [IO.Path]::Combine($PSHOME,'powershell.exe'); $p.Arguments = '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 60"'; $p.UseShellExecute = $false; $p.CreateNoWindow = $true; $child = [Diagnostics.Process]::Start($p); [Console]::Out.WriteLine($child.Id); [Console]::Out.Flush(); Start-Sleep -Seconds 60"#;
        let mut command = Command::new(&executable);
        command
            .args(args(script))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let (mut child, job) = spawn(&mut command, false).unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        timeout(Duration::from_secs(20), output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let descendant_pid = line.trim().parse::<u32>().unwrap();
        let raw = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, descendant_pid) };
        assert!(
            !raw.is_null(),
            "cannot pin the owned descendant before cancellation"
        );
        let descendant = unsafe { OwnedHandle::from_raw_handle(raw) };
        assert!(
            child.try_wait().unwrap().is_none(),
            "owned process exited before cancellation"
        );
        drop(job);
        timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(descendant.as_raw_handle() as HANDLE, 10000) },
            WAIT_OBJECT_0
        );
        assert!(
            unrelated.try_wait().unwrap().is_none(),
            "cancellation escaped its owned job"
        );
        drop(unrelated_job);
        timeout(Duration::from_secs(10), unrelated.wait())
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    #[ignore = "由响应管道回归测试在独立进程中调用"]
    async fn detached_stdio_helper() {
        prevent_stdio_inheritance().unwrap();
        let mut command = Command::new(powershell());
        command.args(args("Start-Sleep -Seconds 60"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        let (mut child, job) = spawn(&mut command, true).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        job.release().unwrap();
        println!("detached-child-started");
    }

    #[tokio::test]
    async fn detached_service_does_not_hold_launcher_response_pipe_open() {
        let executable = crate::windows_security::normalize_system_path(&std::env::current_exe().unwrap()).unwrap();
        let mut command = Command::new(executable);
        command.args(["--ignored", "--exact", "windows_process::tests::detached_stdio_helper", "--nocapture"])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let (child, job) = spawn(&mut command, false).unwrap();
        // 外层 Job 始终拥有整个测试进程树，包括 helper 释放的嵌套 Job。
        let output = timeout(Duration::from_secs(20), child.wait_with_output()).await;
        drop(job);
        let output = output.expect("后台继承了响应管道，启动器退出后仍未收到 EOF").unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("detached-child-started"));
    }
}
