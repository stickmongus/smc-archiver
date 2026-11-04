use anyhow::{Context, Result};
use std::env;
use winreg::enums::*;
use winreg::RegKey;

const PROG_ID: &str = "SMC.Archive.1";

/// Checks whether .smc file association is currently registered in HKCU\Software\Classes
pub fn is_explorer_registered() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(ext_key) = hkcu.open_subkey(r"Software\Classes\.smc") {
        if let Ok(val) = ext_key.get_value::<String, _>("") {
            return val == PROG_ID;
        }
    }
    false
}

/// Registers .smc (and .s01 split volume) file association, custom icon, and right-click context menus in Windows Explorer
pub fn register_explorer_integration() -> Result<()> {
    let exe_path = env::current_exe().context("현재 실행 파일(.exe) 경로를 확인할 수 없습니다.")?;
    let exe_str = exe_path.to_string_lossy().to_string();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes = hkcu
        .open_subkey_with_flags(r"Software\Classes", KEY_WRITE)
        .or_else(|_| hkcu.create_subkey(r"Software\Classes").map(|(k, _)| k))
        .context("HKCU\\Software\\Classes 레지스트리 열기 실패")?;

    // 1. Associate .smc and .s01 extensions with SMC.Archive.1
    let (ext_key, _) = classes.create_subkey(".smc")?;
    ext_key.set_value("", &PROG_ID)?;
    let (s01_key, _) = classes.create_subkey(".s01")?;
    s01_key.set_value("", &PROG_ID)?;

    // 2. Define SMC.Archive.1 ProgID (with embedded custom icon, double-click open, and right-click extract)
    let (prog_key, _) = classes.create_subkey(PROG_ID)?;
    prog_key.set_value("", &"SMC 초고속 압축 아카이브 (.smc)")?;

    let (icon_key, _) = prog_key.create_subkey("DefaultIcon")?;
    icon_key.set_value("", &format!("\"{}\",0", exe_str))?;

    let (open_cmd_key, _) = prog_key.create_subkey(r"shell\open\command")?;
    open_cmd_key.set_value("", &format!("\"{}\" \"%1\"", exe_str))?;

    let (extract_key, _) = prog_key.create_subkey(r"shell\SMCExtract")?;
    extract_key.set_value("", &"📂 여기에 SMC 압축 풀기")?;
    extract_key.set_value("Icon", &format!("\"{}\",0", exe_str))?;
    let (extract_cmd_key, _) = extract_key.create_subkey("command")?;
    extract_cmd_key.set_value("", &format!("\"{}\" --extract \"%1\"", exe_str))?;

    // 3. Context menu on any file (*\shell\SMCPack)
    let (file_shell, _) = classes.create_subkey(r"*\shell\SMCPack")?;
    file_shell.set_value("", &"⚡ SMC로 초고속 압축 (.smc)")?;
    file_shell.set_value("Icon", &format!("\"{}\",0", exe_str))?;
    let (file_cmd, _) = file_shell.create_subkey("command")?;
    file_cmd.set_value("", &format!("\"{}\" --pack \"%1\"", exe_str))?;

    // 4. Context menu on any folder (Directory\shell\SMCPack)
    let (dir_shell, _) = classes.create_subkey(r"Directory\shell\SMCPack")?;
    dir_shell.set_value("", &"⚡ SMC로 초고속 압축 (.smc)")?;
    dir_shell.set_value("Icon", &format!("\"{}\",0", exe_str))?;
    let (dir_cmd, _) = dir_shell.create_subkey("command")?;
    dir_cmd.set_value("", &format!("\"{}\" --pack \"%1\"", exe_str))?;

    // 5. Non-intrusive right-click menu on .zip and .7z (keeps default double-click app intact!)
    for ext in [".zip", ".7z"] {
        let open_path = format!(r"SystemFileAssociations\{}\shell\SMCOpen", ext);
        if let Ok((k, _)) = classes.create_subkey(&open_path) {
            let _ = k.set_value("", &"👁 SMC 뷰어로 열기 / 미리보기");
            let _ = k.set_value("Icon", &format!("\"{}\",0", exe_str));
            if let Ok((cmd, _)) = k.create_subkey("command") {
                let _ = cmd.set_value("", &format!("\"{}\" \"%1\"", exe_str));
            }
        }
        let ext_path = format!(r"SystemFileAssociations\{}\shell\SMCExtract", ext);
        if let Ok((k, _)) = classes.create_subkey(&ext_path) {
            let _ = k.set_value("", &"📂 여기에 SMC 스마트 압축 풀기");
            let _ = k.set_value("Icon", &format!("\"{}\",0", exe_str));
            if let Ok((cmd, _)) = k.create_subkey("command") {
                let _ = cmd.set_value("", &format!("\"{}\" --extract \"%1\"", exe_str));
            }
        }
    }

    notify_shell_change();
    Ok(())
}

/// Removes .smc file association and right-click context menus from HKCU\Software\Classes
pub fn unregister_explorer_integration() -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(classes) = hkcu.open_subkey_with_flags(r"Software\Classes", KEY_WRITE) {
        let _ = classes.delete_subkey_all(".smc");
        let _ = classes.delete_subkey_all(".s01");
        let _ = classes.delete_subkey_all(PROG_ID);
        let _ = classes.delete_subkey_all(r"*\shell\SMCPack");
        let _ = classes.delete_subkey_all(r"Directory\shell\SMCPack");
        for ext in [".zip", ".7z"] {
            let _ = classes.delete_subkey_all(format!(r"SystemFileAssociations\{}\shell\SMCOpen", ext));
            let _ = classes.delete_subkey_all(format!(r"SystemFileAssociations\{}\shell\SMCExtract", ext));
        }
    }
    notify_shell_change();
    Ok(())
}

/// Notifies Windows Explorer that file associations have changed so icons/menus update immediately
fn notify_shell_change() {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "shell32")]
        extern "system" {
            fn SHChangeNotify(wEventId: i32, uFlags: u32, dwItem1: usize, dwItem2: usize);
        }
        const SHCNE_ASSOCCHANGED: i32 = 0x08000000;
        const SHCNF_IDLIST: u32 = 0x0000;
        unsafe {
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, 0, 0);
        }
    }
}
