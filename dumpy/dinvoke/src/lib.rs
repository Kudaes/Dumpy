#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use std::ptr;
use std::ffi::CString;
use data::{CloseHandle, DLL_PROCESS_ATTACH, EntryPoint, LdrGetProcedureAddress, LoadLibraryA, OpenProcess, PVOID, PeMetadata, GUID};
use libc::c_void;
use litcrypt::lc;
use winproc::Process;

use bindings::Windows::Win32::{Foundation::{HANDLE, HINSTANCE, PSTR, BOOL}, System::{WindowsProgramming::{OBJECT_ATTRIBUTES, CLIENT_ID, IO_STATUS_BLOCK}, Diagnostics::Debug::{MINIDUMP_EXCEPTION_INFORMATION, MINIDUMP_USER_STREAM_INFORMATION, MINIDUMP_CALLBACK_INFORMATION}}, Security::SECURITY_ATTRIBUTES};


/// Retrieves the base address of a module loaded in the current process.
///
/// In case that the module can't be found in the current process, it will
/// return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     println!("The base address of ntdll.dll is 0x{:X}.", ntdll);
/// }
/// ```
pub fn get_module_base_address (module_name: &str) -> isize
{
    let process = Process::current();
    let modules = process.module_list().unwrap();
    for m in modules
    {
        if m.name().unwrap().to_lowercase() == module_name.to_ascii_lowercase()
        {
            let handle = m.handle();
            return handle as isize;
        }
    }

    0
}

/// Retrieves the address of an exported function from the specified module.
///
/// This functions is analogous to GetProcAddress from Win32. The exported 
/// function's address is obtained by walking and parsing the EAT of the  
/// specified module.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let addr = dinvoke::get_function_address(ntdll, "NtCreateThread");    
///     println!("The address where NtCreateThread is located at is 0x{:X}.", addr);
/// }
/// ```
pub fn get_function_address(module_base_address: isize, function: &str) -> isize {

    unsafe
    {
        
        let mut function_ptr:*mut i32 = ptr::null_mut();
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: isize = module_base_address + (pe_header as isize) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: isize;

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as isize + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as isize + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as isize + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as isize + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as isize + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as isize + x as isize * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as isize) as *mut u8;
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.to_lowercase() == function.to_lowercase() 
            {
                let function_ordinal = *((module_base_address + ordinals_rva as isize + x as isize * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as isize + (4 * (function_ordinal - ordinal_base)) as isize )) as *mut i32);
                function_ptr = (module_base_address + function_rva as isize) as *mut i32;

                break;
            }

        }

        let mut ret: isize = 0;

        if function_ptr != ptr::null_mut()
        {
            ret = function_ptr as isize;
        }
    
        ret

    }
}

/// Calls the module's entry point with the option DLL_ATTACH_PROCESS.
///
/// # Examples
///
/// ```ignore
///    let pe = manualmap::read_and_map_module("c:\\some\\random\\file.dll").unwrap();
///    let ret = dinvoke::call_module_entry_point(&pe.0, pe.1);
/// ```
pub fn call_module_entry_point(pe_info: &PeMetadata, module_base_address: isize) -> Result<(), String> {

    let entry_point: isize;
    if pe_info.is_32_bit 
    {
        entry_point = module_base_address + pe_info.opt_header_32.AddressOfEntryPoint as isize;
    }
    else 
    {
        entry_point = module_base_address + pe_info.opt_header_64.address_of_entry_point as isize;

    }

    unsafe 
    {
        let main: EntryPoint = std::mem::transmute(entry_point);
        let module = HINSTANCE {0: entry_point as isize};
        let ret = main(module, DLL_PROCESS_ATTACH, ptr::null_mut());

        if !ret.as_bool()
        {
            return Err(lc!("[x] Failed to call module's entry point (DllMain -> DLL_PROCESS_ATTACH)."));
        }

        Ok(())
    }
}

/// Retrieves the address of an exported function from the specified module by its ordinal.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// This functions internally calls LdrGetProcedureAddress.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let ordinal: u32 = 8; 
///     let addr = dinvoke::get_function_address_ordinal(ntdll, 8);    
///     println!("The function with ordinal 8 is located at 0x{:X}.", addr);
/// }
/// ```
pub fn get_function_address_by_ordinal(module_base_address: isize, ordinal: u32) -> isize {

    let ret = ldr_get_procedure_address(module_base_address, "", ordinal);

    match ret {
    Ok(r) => return r,
    Err(_) => return 0, 
    }
    
}

/// Retrieves the address of an exported function from the specified module either by its name 
/// or by its ordinal number.
///
/// This functions internally calls LdrGetProcedureAddress.
///
/// In case that the function's address can't be retrieved, it will return an Err with a 
/// descriptive error message.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let ordinal: u32 = 8; // Ordinal 8 represents the function RtlDispatchAPC
///     let ret = dinvoke::ldr_get_procedure_address(ntdll,"", 8);
///     match ret {
///         Ok(addr) => println!("The address where RtlDispatchAPC is located at is 0x{:X}.", addr),
///         Err(e) => println!("{}",e),
///     }
///     
/// }
/// ```
pub fn ldr_get_procedure_address (module_handle: isize, function_name: &str, ordinal: u32) -> Result<isize, String> {

    unsafe 
    {   
        let mut result: isize = 0;
        
        let module_base_address = get_module_base_address(&lc!("ntdll.dll")); 
        if module_base_address != 0
        {
            let function_address: isize = get_function_address(module_base_address, &lc!("LdrGetProcedureAddress"));

            if function_address != 0 
            {
                let hmodule: PVOID = std::mem::transmute(module_handle);
                let func_ptr: LdrGetProcedureAddress = std::mem::transmute(function_address);  
                let return_address: *mut c_void = std::mem::transmute(&u64::default());
                let return_address: *mut PVOID = std::mem::transmute(return_address);
                let mut fun_name: *mut String = std::mem::transmute(&String::default());

                if function_name == ""
                {
                    fun_name = ptr::null_mut();
                }
                else 
                {
                    *fun_name = function_name.to_string();
                }

                let ret = func_ptr(hmodule, fun_name, ordinal, return_address);

                if ret == 0
                {
                    result = *return_address as isize;
                }
            }
            else 
            {
                return Err(lc!("[x] Error obtaining LdrGetProcedureAddress address."));
            }
        }
        else 
        {
            return Err(lc!("[x] Error obtaining ntdll.dll base address."));
        }

        Ok(result)
    }
}

/// Loads and retrieves a module's base address by dynamically calling LoadLibraryA.
///
/// It will return either the module's base address or an Err with a descriptive error message.
///
/// # Examples
///
/// ```
/// let ret = dinvoke::load_library_a("ntdll.dll");
///
/// match ret {
///     Ok(addr) => if addr != 0 {println!("ntdll.dll base address is 0x{:X}.", addr)},
///     Err(e) => println!("{}",e),
/// }
/// ```
pub fn load_library_a(module: &str) -> Result<isize, String> {

    unsafe 
    {    

        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        let result;
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, &lc!("LoadLibraryA"));

            if function_address != 0 
            {
                let function_ptr: LoadLibraryA = std::mem::transmute(function_address); 
                let name = CString::new(module.to_string()).expect("CString::new failed");
                let function_name = PSTR{0: name.as_ptr() as *mut u8};

                result = function_ptr(function_name);
            }
            else 
            {
                return Err(lc!("[x] Error obtaining LoadLibraryA address."));
            }
        } 
        else 
        {
            return Err(lc!("[x] Error obtaining kernel32.dll base address."));
        }

        Ok(result.0 as isize)
    }

}

/// Opens a HANDLE to a process.
///
/// It will return either a HANDLE object or an Err with a descriptive error message. If the function
/// fails the HANDLE will have value -1 or 0.
///
/// # Examples
///
/// ```
/// let pid = 792u32;
/// let handle = dinvoke::open_process(0x0040, 0, pid).unwrap(); //PROCESS_DUP_HANDLE access right.
/// 
/// if handle.0 != 0 && handle.0 != -1
/// {
///     println!("Handle to process with id {} with PROCESS_DUP_HANDLE access right successfully obtained.", pid);
/// }
/// ```
pub fn open_process(desired_access: u32, inherit_handle: i32, process_id: u32) -> Result<HANDLE, String> {

    unsafe 
    {    

        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        let handle;
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, &lc!("OpenProcess"));

            if function_address != 0 
            {
                let function_ptr: OpenProcess = std::mem::transmute(function_address); 
  

                handle = function_ptr(desired_access,inherit_handle,process_id);
            }
            else 
            {
                return Err(lc!("[x] Error obtaining OpenProcess address."));
            }
        } 
        else 
        {
            return Err(lc!("[x] Error obtaining kernel32.dll base address."));
        }

        Ok(handle)
    }

}

/// Closes a HANDLE object.
///
/// It will return either a boolean value or an Err with a descriptive error message. If the function
/// fails the bool value returned will be false.
///
/// # Examples
///
/// ```
/// let pid = 792u32;
/// let handle = dinvoke::open_process(0x0040, 0, pid).unwrap(); //PROCESS_DUP_HANDLE access right.
/// 
/// if handle.0 != 0 && handle.0 != -1
/// {
///     let r = dinvoke::close_handle(handle).unwrap();
///     if r
///     {
///         println!("Handle to process with id {} closed.", pid);
///     }
/// }
/// ```
pub fn close_handle(handle: HANDLE) -> Result<bool,String> {
    unsafe 
    {    

        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        let ret;
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, &lc!("CloseHandle"));

            if function_address != 0 
            {
                let function_ptr: CloseHandle = std::mem::transmute(function_address); 
  

                ret = function_ptr(handle);
            }
            else 
            {
                return Err(lc!("[x] Error obtaining CloseHandle address."));
            }
        } 
        else 
        {
            return Err(lc!("[x] Error obtaining kernel32.dll base address."));
        }

       if ret == 0
       {
           return Ok(false);
       }

       Ok(true)
    }
}

/// Dynamically calls QueryFullProcessImageNameW.
///
pub fn query_full_process_image_name(process_handle: HANDLE, flags: u32, name: *mut u16, size: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::QueryFullProcessImageNameW;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("QueryFullProcessImageNameW"),func_ptr,ret,process_handle,flags,name,size);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }   
}

/// Dynamically calls CreateTransaction.
///
pub fn create_transaction(attributes: *mut SECURITY_ATTRIBUTES,uow: *mut GUID, options: u32, isolation_level: u32, isolation_flags: u32, timeout: u32, description: *mut u16) -> HANDLE {
    
    unsafe 
    {
        let ret: Option<HANDLE>;
        let func_ptr: data::CreateTransaction;
        let ktmv = load_library_a(&lc!("KtmW32.dll")).unwrap();
        dynamic_invoke!(ktmv,&lc!("CreateTransaction"),func_ptr,ret,attributes,uow,options,isolation_level,isolation_flags,timeout,description);

        match ret {
            Some(x) => return x,
            None => return HANDLE { 0: 0 } ,
        }
    }   
}

/// Dynamically calls CreateFileTransactedA.
///
pub fn create_file_transacted(name: *mut u8, access: u32, mode: u32, attributes: *const SECURITY_ATTRIBUTES, disposition: u32, flags: u32, template: HANDLE, transaction: HANDLE, version: *const u32, extended: PVOID) -> HANDLE {
    
    unsafe 
    {
        let ret: Option<HANDLE>;
        let func_ptr: data::CreateFileTransactedA;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("CreateFileTransactedW"),func_ptr,ret,name,access,mode,attributes,disposition,flags,template,transaction,version,extended);

        match ret {
            Some(x) => return x,
            None => return HANDLE { 0: 0 } ,
        }
    }   
}

/// Dynamically calls MiniDumpWriteDump.
///
pub fn mini_dump_write_dump (process: HANDLE, process_id: u32, file: HANDLE, dump_type: u32, exception: *mut MINIDUMP_EXCEPTION_INFORMATION, stream: *mut MINIDUMP_USER_STREAM_INFORMATION, callback: *mut MINIDUMP_CALLBACK_INFORMATION) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::MiniDumpWriteDump;
        let dbg = load_library_a(&lc!("Dbgcore.dll")).unwrap();
        dynamic_invoke!(dbg,&lc!("MiniDumpWriteDump"),func_ptr,ret,process,process_id,file,dump_type,exception,stream,callback);

        match ret {
            Some(x) => return x,
            None => return 0,
        }
    }   
}

/// Dynamically calls GetFileSize.
///
pub fn get_file_size(handle: HANDLE, size: *mut u32) -> u32 {
    
    unsafe 
    {
        let ret: Option<u32>;
        let func_ptr: data::GetFileSize;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("GetFileSize"),func_ptr,ret,handle,size);

        match ret {
            Some(x) => return x,
            None => return 0,
        }
    }   
}

/// Dynamically calls CreateFileMappingW.
///
pub fn create_file_mapping (file: HANDLE, attributes: *const SECURITY_ATTRIBUTES, protect: u32, max_size_high: u32, max_size_low: u32, name: *mut u8) -> HANDLE {
    
    unsafe 
    {
        let ret: Option<HANDLE>;
        let func_ptr: data::CreateFileMapping;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("CreateFileMappingW"),func_ptr,ret,file,attributes,protect,max_size_high,max_size_low,name);

        match ret {
            Some(x) => return x,
            None => return HANDLE { 0: 0 } ,
        }
    }   
}

/// Dynamically calls MapViewOfFile.
///
pub fn map_view_of_file (file: HANDLE, access: u32, off_high: u32, off_low: u32, bytes: usize) -> PVOID {
    
    unsafe 
    {
        let ret: Option<PVOID>;
        let func_ptr: data::MapViewOfFile;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("MapViewOfFile"),func_ptr,ret,file,access,off_high,off_low,bytes);

        match ret {
            Some(x) => return x,
            None => return ptr::null_mut() ,
        }
    }   
}

/// Dynamically calls UnmapViewOfFile.
///
pub fn unmap_view_of_file (base_address: PVOID) -> bool {
    
    unsafe 
    {
        let ret: Option<BOOL>;
        let func_ptr: data::UnmapViewOfFile;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("UnmapViewOfFile"),func_ptr,ret,base_address);

        match ret {
            Some(x) => return x.as_bool(),
            None => return false ,
        }
    }   
}

/// Dynamically calls RollbackTransaction.
///
pub fn rollback_transaction(transaction: HANDLE) -> bool {
    
    unsafe 
    {
        let ret: Option<BOOL>;
        let func_ptr: data::RollbackTransaction;
        let ktmv = load_library_a(&lc!("KtmW32.dll")).unwrap();
        dynamic_invoke!(ktmv,&lc!("RollbackTransaction"),func_ptr,ret,transaction);

        match ret {
            Some(x) => return x.as_bool(),
            None => return false ,
        }
    }   
}

/// Dynamically calls SetHandleInformation.
///
pub fn set_handle_information (object: HANDLE, mask: u32, flags: u32) -> bool {
    
    unsafe 
    {
        let ret: Option<BOOL>;
        let func_ptr: data::SetHandleInformation;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("SetHandleInformation"),func_ptr,ret,object,mask,flags);

        match ret {
            Some(x) => return x.as_bool(),
            None => return false ,
        }
    }   
}

/// Dynamically calls NtWriteVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_write_virtual_memory (handle: HANDLE, base_address: PVOID, buffer: PVOID, size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtWriteVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtWriteVirtualMemory"),func_ptr,ret,handle,base_address,buffer,size,bytes_written);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }

}

/// Dynamically calls NtAllocateVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_allocate_virtual_memory (handle: HANDLE, base_address: *mut PVOID, zero_bits: usize, size: *mut usize, allocation_type: u32, protection: u32) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtAllocateVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtAllocateVirtualMemory"),func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }   
}

/// Dynamically calls NtProtectVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_protect_virtual_memory (handle: HANDLE, base_address: *mut PVOID, size: *mut usize, new_protection: u32, old_protection: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtProtectVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtProtectVirtualMemory"),func_ptr,ret,handle,base_address,size,new_protection,old_protection);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryInformationProcess.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_information_process (handle: HANDLE, process_information_class: u32, process_information: PVOID, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryInformationProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryInformationProcess"),func_ptr,ret,handle,process_information_class,process_information,length,return_length);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls RtlAdjustPrivilege.
///
/// It will return the NTSTATUS value returned by the call.
pub fn rtl_adjust_privilege(privilege: u32, enable: u8, current_thread: u8, enabled: *mut u8) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::RtlAdjustPrivilege;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("RtlAdjustPrivilege"),func_ptr,ret,privilege,enable,current_thread,enabled);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQuerySystemInformation.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_system_information(system_information_class: u32, system_information: PVOID, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQuerySystemInformation;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQuerySystemInformation"),func_ptr,ret,system_information_class,system_information,length,return_length);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryInformationThread.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_information_thread(handle: HANDLE, thread_information_class: u32, thread_information: PVOID, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryInformationProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryInformationThread"),func_ptr,ret,handle,thread_information_class,thread_information,length,return_length);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryInformationFile.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_information_file(handle: HANDLE, io: *mut IO_STATUS_BLOCK, file_information: PVOID, length: u32,file_information_class: u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryInformationFile;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryInformationFile"),func_ptr,ret,handle,io,file_information,length,file_information_class);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}


/// Dynamically calls NtOpenProcess.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_open_process(handle: *mut HANDLE, desired_access: u32, attributes: *mut OBJECT_ATTRIBUTES, client_id: *mut CLIENT_ID) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtOpenProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtOpenProcess"),func_ptr,ret,handle,desired_access,attributes,client_id);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtDuplicateObject.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_duplicate_object(source_phandle: HANDLE, source_handle:HANDLE, target_phandle: HANDLE, target_handle: *mut HANDLE, desired_access: u32, attributes: u32, options: u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtDuplicateObject;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtDuplicateObject"),func_ptr,ret,source_phandle,source_handle,target_phandle,target_handle,desired_access,attributes,options);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryObject.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_object(handle: HANDLE, object_information_class: u32, object_information: PVOID, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryObject;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryObject"),func_ptr,ret,handle,object_information_class,object_information,length,return_length);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls an exported function from the specified module.
///
/// This macro will use the dinvoke crate functions to obtain an exported
/// function address of the specified module in the runtime by walking process structures 
/// and PE headers.
///
/// In case that this macro is used to call a dll entry point (DllMain), it will return true
/// or false (using the 3rd argument passed to the macro) depending on the success of the call.
/// In any other case, it will return the same data type that the called function would return
/// using the 4th argument passed to the macro.
///
/// # Example - Calling a dll entry point
///
/// ```ignore
/// let a = manualmap::read_and_map_module("c:\\some\\random\\file.dll").unwrap();
/// let ret: bool = false;
/// dinvoke::dynamic_invoke(&a.0, a.1, ret); // dinvoke::dynamic_invoke(&PeMetadata, i64, bool)
/// if ret { println!("Entry point successfully called.");}
/// ```
/// # Example - Dynamically calling LoadLibraryA
///
/// ```ignore
/// let kernel32 = manualmap::read_and_map_module("c:\\windows\\system32\\kernel32.dll").unwrap();
/// let mut ret:Option<HINSTANCE>;
/// let function_ptr: data::LoadLibraryA;
/// let name = CString::new("ntdll.dll").expect("CString::new failed");
/// let module_name = PSTR{0: name.as_ptr() as *mut u8};
/// //dinvoke::dynamic_invoke(i64,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke(a.1, "LoadLibraryA", function_ptr, ret, module_name);
///
/// match ret {
///     Some(x) => if x.0 == 0 {println!("ntdll base address is 0x{:X}",x.0);},
///     None => println!("Error calling LdrGetProcedureAddress"),
/// }
/// ```
/// # Example - Dynamically calling with referenced arguments
///
/// ```ignore
/// let ptr = dinvoke::get_module_base_address("ntdll.dll");
/// let function_ptr: LdrGetProcedureAddress;
/// let ret: Option<i32>;
/// let hmodule: PVOID = std::mem::transmute(ptr);
/// let fun_name: *mut String = ptr::null_mut();
/// let ordinal = 8 as u32;
/// let return_address: *mut c_void = std::mem::transmute(&u64::default());
/// let return_address: *mut PVOID = std::mem::transmute(return_address);
/// //dinvoke::dynamic_invoke(i64,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke!(ptr,"LdrGetProcedureAddress",function_ptr,ret,hmodule,fun_name,ordinal,return_address);
///
/// match ret {
///     Some(x) => if x == 0 {println!("RtlDispatchAPC is located at the address: 0x{:X}",*return_address as u64);},
///     None => println!("Error calling LdrGetProcedureAddress"),
/// }
/// ```
#[macro_export]
macro_rules! dynamic_invoke {

    ($a:expr, $b:expr, $c:expr) => {
        
        let ret = $crate::call_module_entry_point(&$a,$b);

        match ret {
            Ok(_) => $c = true,
            Err(_) => $c = false,
        }

    };

    ($a:expr, $b:expr, $c:expr, $d:expr, $($e:tt)*) => {

        let function_ptr = $crate::get_function_address($a, $b);
        if function_ptr != 0
        {
            $c = std::mem::transmute(function_ptr);
            $d = Some($c($($e)*));
        }
        else
        {
            $d = None;
        }

    };
}
