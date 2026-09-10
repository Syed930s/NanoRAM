/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2026, Syed930s
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// NanoRAM: NANO is named after my friend tech youtuber go fucking subscribe to him u silly goose

#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::mem;
use std::ptr;

type HANDLE = *mut c_void;
type HKEY = HANDLE;
type BOOL = i32;
type DWORD = u32;
type LPCWSTR = *const u16;
type LPWSTR = *mut u16;
type LSTATUS = i32;
type REGSAM = u32;
type SIZE_T = usize;

#[repr(C)]
struct LUID {
    LowPart: DWORD,
    HighPart: i32,
}

#[repr(C)]
struct LUID_AND_ATTRIBUTES {
    Luid: LUID,
    Attributes: DWORD,
}

#[repr(C)]
struct TOKEN_PRIVILEGES_MULTI {
    PrivilegeCount: DWORD,
    Privileges: [LUID_AND_ATTRIBUTES; 8],
}

#[repr(C)]
struct PROCESSENTRY32W {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ProcessID: DWORD,
    th32DefaultHeapID: usize,
    th32ModuleID: DWORD,
    cntThreads: DWORD,
    th32ParentProcessID: DWORD,
    pcPriClassBase: i32,
    dwFlags: DWORD,
    szExeFile: [u16; 260],
}

const TOKEN_QUERY: DWORD = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;

const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
const INVALID_HANDLE_VALUE: HANDLE = (-1isize) as *mut c_void;

const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
const PROCESS_SET_QUOTA: DWORD = 0x0100;

const QUOTA_LIMITS_HARDWS_MIN_DISABLE: DWORD = 0x00000002;
const QUOTA_LIMITS_HARDWS_MAX_DISABLE: DWORD = 0x00000004;

const HKEY_CURRENT_USER: HKEY = 0x80000001usize as *mut c_void;
const KEY_SET_ACCESS: REGSAM = 0x20006;
const REG_OPTION_NON_VOLATILE: DWORD = 0;
const REG_SZ: DWORD = 1;

// SYSTEM_INFORMATION_CLASS value for SystemMemoryListInformation.
// This is Windows-internal. If it changes/is blocked, the call simply fails.
const SYSTEM_MEMORY_LIST_INFORMATION_CLASS: i32 = 80;

// SYSTEM_MEMORY_LIST_COMMAND values commonly used by Windows internals tools.
const MEM_CMD_EMPTY_WORKING_SET: i32 = 2;
const MEM_CMD_FLUSH_MODIFIED_LIST: i32 = 3;
const MEM_CMD_FLUSH_STANDBY_LIST: i32 = 4;
const MEM_CMD_FLUSH_COMBINED_STANDBY_LIST: i32 = 5;
const MEM_CMD_FLUSH_WORKING_SET: i32 = 6;

#[link(name = "kernel32")]
#[link(name = "advapi32")]
#[link(name = "psapi")]
#[link(name = "ntdll")]
extern "system" {
    fn GetCurrentProcess() -> HANDLE;
    fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: DWORD,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    fn LookupPrivilegeValueW(
        lpSystemName: LPCWSTR,
        lpName: LPCWSTR,
        lpLuid: *mut LUID,
    ) -> BOOL;

    fn AdjustTokenPrivileges(
        TokenHandle: HANDLE,
        DisableAllPrivileges: BOOL,
        NewState: *mut c_void,
        BufferLength: DWORD,
        PreviousState: *mut c_void,
        ReturnLength: *mut DWORD,
    ) -> BOOL;

    fn CloseHandle(hObject: HANDLE) -> BOOL;

    fn CreateToolhelp32Snapshot(
        dwFlags: DWORD,
        th32ProcessID: DWORD,
    ) -> HANDLE;

    fn Process32FirstW(
        hSnapshot: HANDLE,
        lppe: *mut PROCESSENTRY32W,
    ) -> BOOL;

    fn Process32NextW(
        hSnapshot: HANDLE,
        lppe: *mut PROCESSENTRY32W,
    ) -> BOOL;

    fn OpenProcess(
        dwDesiredAccess: DWORD,
        bInheritHandle: BOOL,
        dwProcessId: DWORD,
    ) -> HANDLE;

    fn EmptyWorkingSet(hProcess: HANDLE) -> BOOL;

    fn SetProcessWorkingSetSizeEx(
        hProcess: HANDLE,
        dwMinimumWorkingSetSize: SIZE_T,
        dwMaximumWorkingSetSize: SIZE_T,
        dwFlags: DWORD,
    ) -> BOOL;

    fn GetModuleFileNameW(
        hModule: HANDLE,
        lpFilename: LPWSTR,
        nSize: DWORD,
    ) -> DWORD;

    fn RegCreateKeyExW(
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        Reserved: DWORD,
        lpClass: LPWSTR,
        dwOptions: DWORD,
        samDesired: REGSAM,
        lpSecurityAttributes: *mut c_void,
        phkResult: *mut HKEY,
        lpdwDisposition: *mut DWORD,
    ) -> LSTATUS;

    fn RegSetValueExW(
        hKey: HKEY,
        lpValueName: LPCWSTR,
        Reserved: DWORD,
        dwType: DWORD,
        lpData: *const u8,
        cbData: DWORD,
    ) -> LSTATUS;

    fn RegCloseKey(hKey: HKEY) -> LSTATUS;

    fn NtSetSystemInformation(
        SystemInformationClass: i32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
    ) -> i32;
}

fn wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn enable_privileges() {
    let names = [
        "SeDebugPrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeIncreaseWorkingSetPrivilege",
    ];

    unsafe {
        let mut token: HANDLE = ptr::null_mut();

        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return;
        }

        let mut tp: TOKEN_PRIVILEGES_MULTI = mem::zeroed();
        let mut count: DWORD = 0;

        for name in names.iter() {
            if count >= tp.Privileges.len() as DWORD {
                break;
            }

            let wide_name = wide_null(*name);
            let mut luid: LUID = mem::zeroed();

            if LookupPrivilegeValueW(ptr::null(), wide_name.as_ptr(), &mut luid) != 0 {
                tp.Privileges[count as usize].Luid = luid;
                tp.Privileges[count as usize].Attributes = SE_PRIVILEGE_ENABLED;
                count += 1;
            }
        }

        if count > 0 {
            tp.PrivilegeCount = count;

            AdjustTokenPrivileges(
                token,
                0,
                &mut tp as *mut TOKEN_PRIVILEGES_MULTI as *mut c_void,
                mem::size_of::<TOKEN_PRIVILEGES_MULTI>() as DWORD,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }

        CloseHandle(token);
    }
}

fn module_path_wide() -> Option<Vec<u16>> {
    unsafe {
        let mut buffer = vec![0u16; 32768];

        let len = GetModuleFileNameW(
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as DWORD,
        );

        if len == 0 {
            return None;
        }

        buffer.truncate(len as usize);
        Some(buffer)
    }
}

fn install_startup() {
    let exe = match module_path_wide() {
        Some(v) => v,
        None => return,
    };

    let mut value: Vec<u16> = Vec::with_capacity(exe.len() + 3);
    value.push(b'"' as u16);
    value.extend_from_slice(&exe);
    value.push(b'"' as u16);
    value.push(0);

    let subkey = wide_null("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let value_name = wide_null("NanoRAM");

    unsafe {
        let mut key: HKEY = ptr::null_mut();

        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_ACCESS,
            ptr::null_mut(),
            &mut key,
            ptr::null_mut(),
        ) == 0
        {
            RegSetValueExW(
                key,
                value_name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr() as *const u8,
                (value.len() * mem::size_of::<u16>()) as DWORD,
            );

            RegCloseKey(key);
        }
    }
}

fn clear_process_working_sets() {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut pe: PROCESSENTRY32W = mem::zeroed();
        pe.dwSize = mem::size_of::<PROCESSENTRY32W>() as DWORD;

        if Process32FirstW(snapshot, &mut pe) != 0 {
            loop {
                let pid = pe.th32ProcessID;

                // Skip idle and System.
                if pid != 0 && pid != 4 {
                    let access = PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA;
                    let process = OpenProcess(access, 0, pid);

                    if !process.is_null() {
                        EmptyWorkingSet(process);

                        SetProcessWorkingSetSizeEx(
                            process,
                            !0usize,
                            !0usize,
                            QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE,
                        );

                        CloseHandle(process);
                    }
                }

                pe.dwSize = mem::size_of::<PROCESSENTRY32W>() as DWORD;

                if Process32NextW(snapshot, &mut pe) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }
}

fn clear_memory_lists() {
    unsafe {
        let commands = [
            MEM_CMD_EMPTY_WORKING_SET,
            MEM_CMD_FLUSH_MODIFIED_LIST,
            MEM_CMD_FLUSH_STANDBY_LIST,
            MEM_CMD_FLUSH_COMBINED_STANDBY_LIST,
            MEM_CMD_FLUSH_WORKING_SET,
        ];

        for command in commands.iter() {
            let mut cmd: i32 = *command;

            NtSetSystemInformation(
                SYSTEM_MEMORY_LIST_INFORMATION_CLASS,
                &mut cmd as *mut i32 as *mut c_void,
                mem::size_of::<i32>() as u32,
            );
        }
    }
}

fn trim_self() {
    unsafe {
        let process = GetCurrentProcess();

        EmptyWorkingSet(process);

        SetProcessWorkingSetSizeEx(
            process,
            !0usize,
            !0usize,
            QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE,
        );
    }
}

fn main() {
    // If anything panics, abort silently instead of printing diagnostics.
    std::panic::set_hook(Box::new(|_| std::process::abort()));

    enable_privileges();
    install_startup();
    clear_process_working_sets();
    clear_memory_lists();
    trim_self();
}
