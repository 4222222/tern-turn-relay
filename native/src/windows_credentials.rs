//! Hidden Windows credential input. Secret values only leave the dialog through its owned stdout pipe.
use crate::common::{Error, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::windows::io::AsRawHandle,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        FlushConsoleInputBuffer, GetConsoleMode, ReadConsoleInputW, SetConsoleMode,
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, INPUT_RECORD, KEY_EVENT,
    },
};

fn cancelled() -> Error {
    Error::with_exit("cancelled", "Local credential change cancelled.", 6)
}
fn invalid() -> Error {
    Error::with_exit(
        "credential-error",
        "Hidden Windows credential input failed; private diagnostics withheld.",
        4,
    )
}

/// DPAPI 仅绑定当前 Windows 用户，不使用机器级保护，也不允许交互提示。
pub(crate) fn protect_storage(input: &[u8]) -> Result<Vec<u8>> {
    storage_transform(input, false)
}

pub(crate) fn unprotect_storage(input: &[u8]) -> Result<Vec<u8>> {
    storage_transform(input, true)
}

fn storage_transform(input: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };
    if input.is_empty() || input.len() > 65536 {
        return Err(invalid());
    }
    let source = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_ptr().cast_mut() };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let success = unsafe {
        if decrypt {
            CryptUnprotectData(&source, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        } else {
            CryptProtectData(&source, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        }
    };
    if success == 0 {
        return Err(Error::with_exit("credential-protection", "Windows 用户级凭据保护失败；请使用原 Windows 用户重新配置凭据。", 4));
    }
    let result = if output.pbData.is_null() || output.cbData == 0 || output.cbData > 65536 {
        Err(invalid())
    } else {
        Ok(unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec())
    };
    if !output.pbData.is_null() {
        unsafe {
            for offset in 0..output.cbData as usize {
                std::ptr::write_volatile(output.pbData.add(offset), 0);
            }
            windows_sys::Win32::Foundation::LocalFree(output.pbData.cast());
        }
    }
    result
}

#[cfg(test)]
thread_local! {
    static BEFORE_MODE_RESTORE: std::cell::RefCell<Option<Box<dyn FnOnce(HANDLE)>>> = std::cell::RefCell::new(None);
}

struct ConsoleMode<'a> {
    file: &'a File,
    original: u32,
    active: bool,
}
impl ConsoleMode<'_> {
    fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let handle = self.file.as_raw_handle() as HANDLE;
        // 先丢弃整次粘贴剩余的输入，再允许 shell 恢复回显；清理失败不得恢复回显。
        if unsafe { FlushConsoleInputBuffer(handle) } == 0 {
            return Err(invalid());
        }
        #[cfg(test)]
        BEFORE_MODE_RESTORE.with(|hook| {
            if let Some(callback) = hook.borrow_mut().take() {
                callback(handle);
            }
        });
        if unsafe { SetConsoleMode(handle, self.original) } == 0 {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Drop for ConsoleMode<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(crate) fn hidden_line(prompt: &[u8], limit: usize) -> Result<String> {
    // SetConsoleMode 和 FlushConsoleInputBuffer 均需要可写的控制台输入句柄。
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .map_err(|_| invalid())?;
    let mut output = OpenOptions::new()
        .write(true)
        .open("CONOUT$")
        .map_err(|_| invalid())?;
    let mut original = 0;
    if unsafe { GetConsoleMode(input.as_raw_handle() as HANDLE, &mut original) } == 0 {
        return Err(invalid());
    }
    let mode = original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    if unsafe { SetConsoleMode(input.as_raw_handle() as HANDLE, mode) } == 0 {
        return Err(invalid());
    }
    let mut guard = ConsoleMode {
        file: &input,
        original,
        active: true,
    };
    output.write_all(prompt).map_err(|_| invalid())?;
    output.flush().map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    // 直接消费按键事件，避免 ReadFile 的控制台字符转换吞掉 Escape 等取消键。
    'input: loop {
        let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
        let mut count = 0;
        if unsafe { ReadConsoleInputW(input.as_raw_handle() as HANDLE, &mut record, 1, &mut count) }
            == 0
            || count != 1
        {
            return Err(cancelled());
        }
        if record.EventType != KEY_EVENT as u16 {
            continue;
        }
        let key = unsafe { record.Event.KeyEvent };
        if key.bKeyDown == 0 {
            continue;
        }
        if key.wVirtualKeyCode == 27 {
            return Err(cancelled());
        }
        let unit = unsafe { key.uChar.UnicodeChar };
        if unit == 0 {
            continue;
        }
        for _ in 0..key.wRepeatCount {
            match unit {
                13 | 10 => break 'input,
                3 => {
                    return Err(Error::with_exit(
                        "cancelled",
                        "Credential operation interrupted.",
                        130,
                    ))
                }
                4 | 27 => return Err(cancelled()),
                8 | 127 => {
                    bytes.pop();
                }
                value if (32..=126).contains(&value) && bytes.len() < limit => {
                    bytes.push(value as u8)
                }
                _ => return Err(invalid()),
            }
        }
    }
    output.write_all(b"\r\n").map_err(|_| invalid())?;
    let value = String::from_utf8(bytes).map_err(|_| invalid())?;
    guard.restore()?;
    Ok(value)
}

pub(crate) fn terminal_key() -> Result<(String, String)> {
    let id = hidden_line(b"Cloudflare TURN key ID (hidden): ", 128)?;
    let token = hidden_line(b"Cloudflare TURN-key API token (hidden): ", 8192)?;
    Ok((id, token))
}

const DIALOG: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$form = [System.Windows.Forms.Form]::new()
$form.Text = 'Tern - Cloudflare TURN Key'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = [System.Drawing.Size]::new(520, 280)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.Font = [System.Drawing.Font]::new('Segoe UI', 10)
$notice = [System.Windows.Forms.Label]::new()
$notice.Text = 'Enter your TURN Key ID and TURN-key API token (not an account token). Validate and Save sends them to Cloudflare for verification, then saves them privately on this Windows device.'
$notice.SetBounds(16, 12, 488, 60)
$idLabel = [System.Windows.Forms.Label]::new()
$idLabel.Text = 'TURN Key ID'
$idLabel.SetBounds(16, 82, 488, 23)
$idBox = [System.Windows.Forms.TextBox]::new()
$idBox.SetBounds(16, 107, 488, 28)
$idBox.UseSystemPasswordChar = $true
$idBox.MaxLength = 128
$tokenLabel = [System.Windows.Forms.Label]::new()
$tokenLabel.Text = 'TURN-key API token'
$tokenLabel.SetBounds(16, 146, 488, 23)
$tokenBox = [System.Windows.Forms.TextBox]::new()
$tokenBox.SetBounds(16, 171, 488, 28)
$tokenBox.UseSystemPasswordChar = $true
$tokenBox.MaxLength = 8192
$save = [System.Windows.Forms.Button]::new()
$save.Text = 'Validate and Save'
$save.SetBounds(320, 223, 184, 34)
$save.DialogResult = [System.Windows.Forms.DialogResult]::OK
$cancel = [System.Windows.Forms.Button]::new()
$cancel.Text = 'Cancel'
$cancel.SetBounds(206, 223, 104, 34)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.AcceptButton = $save
$form.CancelButton = $cancel
$form.Controls.AddRange(@($notice, $idLabel, $idBox, $tokenLabel, $tokenBox, $save, $cancel))
try {
    if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        [Console]::Write('__CANCELLED__')
    } else {
        [Console]::Write($idBox.Text + "`n" + $tokenBox.Text + "`n")
    }
} finally {
    $idBox.Clear()
    $tokenBox.Clear()
    $form.Dispose()
}
"#;

pub(crate) async fn native_input() -> Result<Vec<u8>> {
    let executable =
        crate::windows_process::system_program(r"WindowsPowerShell\v1.0\powershell.exe")?;
    let output = crate::windows_process::run(
        &executable,
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-STA".into(),
            "-Command".into(),
            DIALOG.into(),
        ],
        None,
        Duration::from_secs(300),
    )
    .await
    .map_err(|_| invalid())?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(invalid());
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::process::CommandExt,
        process::{Child, Command, Stdio},
        thread,
        time::Instant,
    };
    use windows_sys::Win32::System::{
        Console::{
            FlushConsoleInputBuffer, GetConsoleProcessList, PeekConsoleInputW, WriteConsoleInputW,
            INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
            LEFT_CTRL_PRESSED,
        },
        Threading::{GetCurrentProcessId, CREATE_NEW_CONSOLE},
    };

    struct OwnedTestChild(Option<Child>);
    impl Drop for OwnedTestChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn hidden_input_clears_tail_in_an_isolated_console() {
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "windows_credentials::tests::isolated_console_input_helper",
                "--nocapture",
            ])
            .env("TERN_TURN_RELAY_TEST_ISOLATED_CONSOLE", "1")
            .creation_flags(CREATE_NEW_CONSOLE)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = OwnedTestChild(Some(child));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "独立控制台输入回归超时");
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "独立控制台回归失败：\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "仅由父测试在独立新控制台中调用，禁止在用户控制台执行"]
    fn isolated_console_input_helper() {
        assert_eq!(
            std::env::var("TERN_TURN_RELAY_TEST_ISOLATED_CONSOLE").as_deref(),
            Ok("1")
        );
        let mut processes = [0u32; 16];
        let count =
            unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
        assert_eq!(count, 1, "测试必须独占新控制台");
        assert_eq!(processes[0], unsafe { GetCurrentProcessId() });
        let input = OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .unwrap();
        let handle = input.as_raw_handle() as HANDLE;
        let mut baseline = 0;
        assert_ne!(unsafe { GetConsoleMode(handle, &mut baseline) }, 0);
        baseline |= ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
        assert_ne!(unsafe { SetConsoleMode(handle, baseline) }, 0);
        let cases = [
            (
                "控制字符",
                "\tFAKE_TOKEN_NEVER_REAL\r",
                64,
                Some(("credential-error", 4)),
                None,
            ),
            (
                "Escape取消",
                "\u{1b}FAKE_TOKEN_NEVER_REAL\r",
                64,
                Some(("cancelled", 6)),
                None,
            ),
            (
                "Ctrl-C取消",
                "\u{3}FAKE_TOKEN_NEVER_REAL\r",
                64,
                Some(("cancelled", 130)),
                None,
            ),
            (
                "Ctrl-D取消",
                "\u{4}FAKE_TOKEN_NEVER_REAL\r",
                64,
                Some(("cancelled", 6)),
                None,
            ),
            (
                "超长输入",
                "12345FAKE_TOKEN_NEVER_REAL\r",
                4,
                Some(("credential-error", 4)),
                None,
            ),
            (
                "成功后残留",
                "FAKE_ID\rFAKE_TOKEN_NEVER_REAL\r",
                64,
                None,
                Some("FAKE_ID"),
            ),
        ];
        for (label, text, limit, expected_error, expected_value) in cases {
            assert_ne!(unsafe { FlushConsoleInputBuffer(handle) }, 0);
            let injector = thread::spawn(move || {
                let input = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("CONIN$")
                    .unwrap();
                let handle = input.as_raw_handle() as HANDLE;
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    let mut mode = 0;
                    assert_ne!(unsafe { GetConsoleMode(handle, &mut mode) }, 0);
                    if mode & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) == 0
                    {
                        break;
                    }
                    assert!(Instant::now() < deadline, "隐藏输入未进入无回显模式");
                    thread::sleep(Duration::from_millis(1));
                }
                let records: Vec<INPUT_RECORD> = text
                    .encode_utf16()
                    .map(|unit| INPUT_RECORD {
                        EventType: KEY_EVENT as u16,
                        Event: INPUT_RECORD_0 {
                            KeyEvent: KEY_EVENT_RECORD {
                                bKeyDown: 1,
                                wRepeatCount: 1,
                                wVirtualKeyCode: match unit {
                                    3 => b'C' as u16,
                                    4 => b'D' as u16,
                                    9 => 9,
                                    13 => 13,
                                    27 => 27,
                                    _ => 0,
                                },
                                wVirtualScanCode: 0,
                                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                                dwControlKeyState: if matches!(unit, 3 | 4) {
                                    LEFT_CTRL_PRESSED
                                } else {
                                    0
                                },
                            },
                        },
                    })
                    .collect();
                let mut written = 0;
                assert_ne!(
                    unsafe {
                        WriteConsoleInputW(
                            handle,
                            records.as_ptr(),
                            records.len() as u32,
                            &mut written,
                        )
                    },
                    0
                );
                assert_eq!(written as usize, records.len());
            });
            BEFORE_MODE_RESTORE.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |handle| {
                    let mut mode = 0;
                    assert_ne!(unsafe { GetConsoleMode(handle, &mut mode) }, 0);
                    assert_eq!(mode & ENABLE_ECHO_INPUT, 0, "{label}：清空输入前已恢复回显");
                    assert_no_pending_keys(handle, label);
                }))
            });
            let result = hidden_line(b"isolated test input: ", limit);
            injector.join().unwrap();
            match expected_error {
                Some((code, exit_code)) => {
                    let error = match result {
                        Err(error) => error,
                        Ok(_) => panic!("{label}：错误输入被接受"),
                    };
                    assert_eq!(error.code, code, "{label}");
                    assert_eq!(error.exit_code, exit_code, "{label}");
                }
                None => assert_eq!(result.unwrap().as_str(), expected_value.unwrap(), "{label}"),
            }
            let mut restored = 0;
            assert_ne!(unsafe { GetConsoleMode(handle, &mut restored) }, 0);
            assert_eq!(restored, baseline, "{label}：控制台模式未恢复");
            assert_no_pending_keys(handle, label);
        }
        // 使用真实只读句柄触发 Flush 的拒绝，确认失败路径不会重新开启回显。
        let hidden = baseline & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
        assert_ne!(unsafe { SetConsoleMode(handle, hidden) }, 0);
        let readonly = OpenOptions::new().read(true).open("CONIN$").unwrap();
        let mut guard = ConsoleMode {
            file: &readonly,
            original: baseline,
            active: true,
        };
        assert!(guard.restore().is_err());
        drop(guard);
        let mut still_hidden = 0;
        assert_ne!(unsafe { GetConsoleMode(handle, &mut still_hidden) }, 0);
        assert_eq!(still_hidden, hidden);
        assert_ne!(unsafe { FlushConsoleInputBuffer(handle) }, 0);
        assert_ne!(unsafe { SetConsoleMode(handle, baseline) }, 0);
    }

    fn assert_no_pending_keys(handle: HANDLE, label: &str) {
        let mut records: [INPUT_RECORD; 512] = unsafe { std::mem::zeroed() };
        let mut count = 0;
        assert_ne!(
            unsafe {
                PeekConsoleInputW(
                    handle,
                    records.as_mut_ptr(),
                    records.len() as u32,
                    &mut count,
                )
            },
            0
        );
        assert!(
            (count as usize) < records.len(),
            "{label}：输入队列检查被截断"
        );
        assert!(
            records[..count as usize]
                .iter()
                .all(|record| record.EventType != KEY_EVENT as u16),
            "{label}：仍有未消费的按键输入"
        );
    }
}
