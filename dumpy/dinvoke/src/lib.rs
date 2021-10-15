#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use std::ptr;
use std::ffi::CString;
use data::{CloseHandle, DLL_PROCESS_ATTACH, EAT, EntryPoint, LdrGetProcedureAddress, LoadLibraryA, MEM_COMMIT, MEM_RESERVE, OpenProcess, PAGE_EXECUTE_READ, PAGE_READWRITE, PVOID, PeMetadata};
use libc::c_void;
use litcrypt::lc;
use winproc::Process;

use bindings::Windows::Win32::{Foundation::{HANDLE, HINSTANCE, PSTR}, {System::Threading::{GetCurrentProcess}}};


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
pub fn get_module_base_address (module_name: &str) -> i64
{
    let process = Process::current();
    let modules = process.module_list().unwrap();
    for m in modules
    {
        if m.name().unwrap().to_lowercase() == module_name.to_ascii_lowercase()
        {
            let handle = m.handle();
            return handle as i64;
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
pub fn get_function_address(module_base_address: i64, function: &str) -> i64 {

    unsafe
    {
        
        let mut function_ptr:*mut i32 = ptr::null_mut();
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: i64 = module_base_address + (pe_header as i64) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: i64;

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as i64 + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as i64 + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as i64 + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as i64 + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as i64 + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as i64 + x as i64 * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as i64) as *mut u8;
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.to_lowercase() == function.to_lowercase() 
            {
                let function_ordinal = *((module_base_address + ordinals_rva as i64 + x as i64 * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as i64 + (4 * (function_ordinal - ordinal_base)) as i64 )) as *mut i32);
                function_ptr = (module_base_address + function_rva as i64) as *mut i32;

                break;
            }

        }

        let mut ret: i64 = 0;

        if function_ptr != ptr::null_mut()
        {
            ret = function_ptr as i64;
        }
    
        ret

    }
}

/// Returns a BTreeMap<i64,String> composed of pairs (memory address, function name)
/// with all the Nt exported functions on ntdll.dll. 
///
/// This functions will only return valid data if the parameter passed is the base address of
/// ntdll.dll. This function is usefull to dynamically get a syscall id as it is shown in the
/// example.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let mut j = 0;  
///     for (a,b) in eat.iter()
///     {
///         if b == "NtCreateThreadEx"
///         {
///             println!("The syscall id for NtCreateThreadEx is {}.",j);
///             break;
///         }
///         j = j + 1;
///     }
/// }
/// ```
pub fn get_ntdll_eat(module_base_address: i64) -> EAT {

    unsafe
    {
        let mut eat:EAT = EAT::default();

        let mut function_ptr:*mut i32;
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: i64 = module_base_address + (pe_header as i64) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: i64;

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as i64 + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as i64 + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as i64 + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as i64 + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as i64 + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as i64 + x as i64 * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as i64) as *mut u8;
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.starts_with("Zw")
            {
                let function_ordinal = *((module_base_address + ordinals_rva as i64 + x as i64 * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as i64 + (4 * (function_ordinal - ordinal_base)) as i64 )) as *mut i32);
                function_ptr = (module_base_address + function_rva as i64) as *mut i32;

                function_name = function_name.replace("Zw", "Nt");
                eat.insert(function_ptr as i64,function_name );
            }

        }
    
        eat

    }
}

/// Returns the syscall id that correspond to the function specified.
///
/// This functions will return -1 in case that the syscall id of the function
/// specified could not be found.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let id = dinvoke::get_syscall_id(eat, "NtCreateThreadEx");
///     
///     if id != -1
///     {
///         println!("The syscall id for NtCreateThreadEx is {}.",id);
///     }
/// }
/// ```
pub fn get_syscall_id(eat:EAT, function_name: &str) -> i32 {

    let mut i = 0;
    for (_a,b) in eat.iter()
    {
        if b == function_name
        {
            return i;
        }

        i = i + 1;
    }

    -1
}

/// Given a valid syscall id, it will allocate the required shellcode to execute 
/// that specific syscall.
///
/// This functions will return the memory address where the shellcode has been written. If any 
/// error has ocurred, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let id = dinvoke::get_syscall_id(eat, "NtCreateThreadEx");
///     
///     if id != -1
///     {
///         let addr = dinvoke::prepare_syscall(id as u32);
///         println!("NtCreateThreadEx syscall ready to be executed at address 0x{:X}", addr);
///     }
/// }
/// ```
pub fn prepare_syscall(id: u32) -> i64 {

    let mut sh: [u8;11] = 
    [ 
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    ];

    unsafe 
    {
        let mut ptr: *mut u8 = std::mem::transmute(&id);

        for i in 0..4
        {
            sh[4 + i] = *ptr;
            ptr = ptr.add(1);
        }

        let handle = GetCurrentProcess();
        let base_address: *mut PVOID = std::mem::transmute(&u64::default());
        let nsize: usize = sh.len() as usize;
        let size: *mut usize = std::mem::transmute(&(nsize+1));
        let old_protection: *mut u32 = std::mem::transmute(&u32::default());
        let ret = nt_allocate_virtual_memory(handle, base_address, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if ret != 0
        {
            return 0;
        }
        
        let buffer: *mut c_void = std::mem::transmute(sh.as_ptr());
        let bytes_written: *mut usize = std::mem::transmute(&usize::default());
        let ret = nt_write_virtual_memory(handle, *base_address, buffer, nsize, bytes_written);

        if ret != 0
        {
            return 0;
        }

        let ret = nt_protect_virtual_memory(handle, base_address, size, PAGE_EXECUTE_READ, old_protection);

        if ret != 0
        {
            return 0;
        }

        *base_address as i64
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
pub fn call_module_entry_point(pe_info: &PeMetadata, module_base_address: i64) -> Result<(), String> {

    let entry_point;
    if pe_info.is_32_bit 
    {
        entry_point = module_base_address + pe_info.opt_header_32.AddressOfEntryPoint as i64;
    }
    else 
    {
        entry_point = module_base_address + pe_info.opt_header_64.address_of_entry_point as i64;

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
pub fn get_function_address_by_ordinal(module_base_address: i64, ordinal: u32) -> i64 {

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
pub fn ldr_get_procedure_address (module_handle: i64, function_name: &str, ordinal: u32) -> Result<i64, String> {

    unsafe 
    {   
        let mut result: i64 = 0;
        
        let module_base_address = get_module_base_address(&lc!("ntdll.dll")); 
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, &lc!("LdrGetProcedureAddress"));

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
                    result = *return_address as i64;
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
pub fn load_library_a(module: &str) -> Result<i64, String> {

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

        Ok(result.0 as i64)
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

/// Dynamically calls NtWriteVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_write_virtual_memory (handle: HANDLE, base_address: PVOID, buffer: PVOID, size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtWriteVirtualMemory;
        let ntdll = get_module_base_address("ntdll.dll");
        dynamic_invoke!(ntdll,"NtWriteVirtualMemory",func_ptr,ret,handle,base_address,buffer,size,bytes_written);

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
        let ntdll = get_module_base_address("ntdll.dll");
        dynamic_invoke!(ntdll,"NtAllocateVirtualMemory",func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);

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
        let ntdll = get_module_base_address("ntdll.dll");
        dynamic_invoke!(ntdll,"NtProtectVirtualMemory",func_ptr,ret,handle,base_address,size,new_protection,old_protection);

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
        let ntdll = get_module_base_address("ntdll.dll");
        dynamic_invoke!(ntdll,"NtQueryInformationProcess",func_ptr,ret,handle,process_information_class,process_information,length,return_length);

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
        let ntdll = get_module_base_address("ntdll.dll");
        dynamic_invoke!(ntdll,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled);

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

/// Dynamically execute a direct syscall.
///
/// This function expects as parameters the name of the Nt function whose syscall 
/// wants to be executed, a variable with the function header, an Option variable with the same
/// inner type that the original syscall would return and all the parameters expected by the syscall.
///
/// # Examples - Executing NtQueryInformationProcess with direct syscall
///
/// ```ignore      
/// let function_type:NtQueryInformationProcess;
/// let mut ret: Option<i32> = None; //NtQueryInformationProcess returns a NTSTATUS, which is a i32.
/// let handle = GetCurrentProcess();
/// let process_information: *mut c_void = std::mem::transmute(&PROCESS_BASIC_INFORMATION::default()); 
/// let return_length: *mut u32 = std::mem::transmute(&u32::default());
/// dinvoke::execute_syscall!(
///     "NtQueryInformationProcess",
///     function_type,
///     ret,
///     handle,
///     0,
///     process_information,
///     size_of::<PROCESS_BASIC_INFORMATION>() as u32,
///     return_length
/// );
/// match ret {
///     Some(x) => if x == 0 {println!("Process information struct available at address 0x{:X}",process_information as u64);},
///     None => println!("Error executing direct syscall for NtQueryInformationProcess."),
/// }
/// ```
#[macro_export]
macro_rules! execute_syscall {

    ($a:expr, $b:expr, $c:expr, $($d:tt)*) => {

        let eat = $crate::get_ntdll_eat($crate::get_module_base_address("ntdll.dll"));
        let id = $crate::get_syscall_id(eat, $a);
        if id != -1
        {
            let function_ptr = $crate::prepare_syscall(id as u32);
            if function_ptr != 0
            {
                $b = std::mem::transmute(function_ptr);
                $c = Some($b($($d)*));
            }
            else
            {
                $c = None;
            }
        }
        else
        {
            $c = None;
        }

    }
}
