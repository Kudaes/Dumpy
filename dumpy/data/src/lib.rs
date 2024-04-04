use std::{collections::BTreeMap, ffi::c_void};
use bindings::Windows::Win32::{Foundation::{BOOL, HANDLE, HINSTANCE, PSTR}, Security::SECURITY_ATTRIBUTES, System::{Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER, MINIDUMP_CALLBACK_INFORMATION, MINIDUMP_EXCEPTION_INFORMATION, MINIDUMP_USER_STREAM_INFORMATION}, WindowsProgramming::{CLIENT_ID, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK}, Threading::{STARTUPINFOW, PROCESS_INFORMATION}}};

pub type PVOID = *mut c_void;
pub type DWORD = u32;
pub type EAT = BTreeMap<isize,String>;
pub type EntryPoint = extern "system" fn (HINSTANCE, u32, *mut c_void) -> BOOL;
pub type SetHandleInformation = extern "system" fn (HANDLE, u32, u32) -> BOOL;
pub type LoadLibraryA = unsafe extern "system" fn (PSTR) -> HINSTANCE;
pub type GetLastError = unsafe extern "system" fn () -> u32;
pub type OpenProcess = unsafe extern "system" fn (u32, i32, u32) -> HANDLE;
pub type QueryFullProcessImageNameW = unsafe extern "system" fn (HANDLE, u32, *mut u16, *mut u32) -> i32;
pub type MiniDumpWriteDump = unsafe extern "system" fn (HANDLE, u32, HANDLE, u32, *mut MINIDUMP_EXCEPTION_INFORMATION,
    *mut MINIDUMP_USER_STREAM_INFORMATION, *mut MINIDUMP_CALLBACK_INFORMATION) -> i32;
pub type DeviceIoControl = unsafe extern "system" fn (HANDLE, u32, PVOID, u32, PVOID, u32, *mut u32, *mut OVERLAPPED) -> BOOL;
pub type CreateEvent = unsafe extern "system" fn (*const SECURITY_ATTRIBUTES, bool, bool, *const u16) -> HANDLE;
pub type GetOverlappedResult = unsafe extern "system" fn (HANDLE, *mut OVERLAPPED, *mut u32, bool) -> BOOL;
pub type CreateFile = unsafe extern "system" fn (*const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE) -> HANDLE;
pub type CreateTransaction = unsafe extern "system" fn (*mut SECURITY_ATTRIBUTES, *mut GUID, u32, u32, u32, u32, *mut u16) -> HANDLE;
pub type CreateFileTransactedA = unsafe extern "system" fn (*mut u8, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE,
    HANDLE, *const u32, PVOID) -> HANDLE;
pub type RollbackTransaction = unsafe extern "system" fn (HANDLE) -> BOOL;
pub type GetFileSize = unsafe extern "system" fn (HANDLE, *mut u32) -> u32;
pub type CreateFileMapping = unsafe extern "system" fn (HANDLE, *const SECURITY_ATTRIBUTES, u32, u32, u32, *mut u8) -> HANDLE;
pub type MapViewOfFile = unsafe extern "system" fn (HANDLE, u32, u32, u32, usize) -> PVOID;
pub type UnmapViewOfFile = unsafe extern "system" fn (PVOID) -> BOOL;
pub type CloseHandle = unsafe extern "system" fn (HANDLE) -> i32;
pub type CreateProcessWithLogon = unsafe extern "system" fn (*const u16, *const u16, *const u16, u32, *const u16, *mut u16, u32, *const c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION) -> BOOL;
pub type LdrGetProcedureAddress = unsafe extern "system" fn (PVOID, *mut String, u32, *mut PVOID) -> i32;
pub type NtWriteVirtualMemory = unsafe extern "system" fn (HANDLE, PVOID, PVOID, usize, *mut usize) -> i32;
pub type NtProtectVirtualMemory = unsafe extern "system" fn (HANDLE, *mut PVOID, *mut usize, u32, *mut u32) -> i32;
pub type NtAllocateVirtualMemory = unsafe extern "system" fn (HANDLE, *mut PVOID, usize, *mut usize, u32, u32) -> i32;
pub type NtQueryInformationProcess = unsafe extern "system" fn (HANDLE, u32, PVOID, u32, *mut u32) -> i32;
pub type NtQueryInformationThread = unsafe extern "system" fn (HANDLE, u32, PVOID, u32, *mut u32) -> i32;
pub type NtQuerySystemInformation = unsafe extern "system" fn (u32, PVOID, u32, *mut u32) -> i32;
pub type NtQueryInformationFile = unsafe extern "system" fn (HANDLE, *mut IO_STATUS_BLOCK, PVOID, u32, u32) -> i32;
pub type NtDuplicateObject = unsafe extern "system" fn (HANDLE, HANDLE, HANDLE, *mut HANDLE, u32, u32, u32) -> i32;
pub type NtQueryObject = unsafe extern "system" fn (HANDLE, u32, PVOID, u32, *mut u32) -> i32;
pub type NtOpenProcess = unsafe extern "system" fn (*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> i32;
pub type RtlAdjustPrivilege = unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32;
 
pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

pub const PAGE_READONLY: u32 = 0x2;
pub const PAGE_READWRITE: u32 = 0x4;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE: u32 = 0x10;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;

pub const SECTION_MEM_READ: u32 = 0x40000000;
pub const SECTION_MEM_WRITE: u32 = 0x80000000;
pub const SECTION_MEM_EXECUTE: u32 = 0x20000000;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;
pub const THREAD_ALL_ACCESS: u32 =  0x000F0000 |  0x00100000 | 0xFFFF;


#[derive(Clone)]
#[repr(C)]
pub struct PeMetadata {
    pub pe: u32,
    pub is_32_bit: bool,
    pub image_file_header: IMAGE_FILE_HEADER,
    pub opt_header_32: IMAGE_OPTIONAL_HEADER32,
    pub opt_header_64: IMAGE_OPTIONAL_HEADER64,
    pub sections: Vec<IMAGE_SECTION_HEADER> 
}

impl Default for PeMetadata {
    fn default() -> PeMetadata {
        PeMetadata {
            pe: u32::default(),
            is_32_bit: false,
            image_file_header: IMAGE_FILE_HEADER::default(),
            opt_header_32: IMAGE_OPTIONAL_HEADER32::default(),
            opt_header_64: IMAGE_OPTIONAL_HEADER64::default(),
            sections: Vec::default(),  
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetNamespace {
    pub unused: [u8;12],
    pub count: i32, // offset 0x0C
    pub entry_offset: i32, // offset 0x10
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetNamespaceEntry {
    pub unused1: [u8;4],
    pub name_offset: i32, // offset 0x04
    pub name_length: i32, // offset 0x08
    pub unused2: [u8;4],
    pub value_offset: i32, // offset 0x10
    pub value_length: i32, // offset 0x14
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetValueEntry {
    pub flags: i32, // offset 0x00
    pub name_offset: i32, // offset 0x04
    pub name_count: i32, // offset 0x08
    pub value_offset: i32, // offset 0x0C
    pub value_count: i32, // offset 0x10
}

#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_data_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Copy, Clone,Default)]
#[repr(C)] // required to keep fields order, otherwise Rust may change that order randomly
pub struct IMAGE_OPTIONAL_HEADER64 {
        pub magic: u16, 
        pub major_linker_version: u8, 
        pub minor_linker_version: u8, 
        pub size_of_code: u32, 
        pub size_of_initialized_data: u32, 
        pub size_of_unitialized_data: u32, 
        pub address_of_entry_point: u32, 
        pub base_of_code: u32, 
        pub image_base: u64, 
        pub section_alignment: u32, 
        pub file_alignment: u32, 
        pub major_operating_system_version: u16, 
        pub minor_operating_system_version: u16, 
        pub major_image_version: u16,
        pub minor_image_version: u16, 
        pub major_subsystem_version: u16,
        pub minor_subsystem_version: u16, 
        pub win32_version_value: u32, 
        pub size_of_image: u32, 
        pub size_of_headers: u32, 
        pub checksum: u32, 
        pub subsystem: u16, 
        pub dll_characteristics: u16, 
        pub size_of_stack_reserve: u64, 
        pub size_of_stack_commit: u64, 
        pub size_of_heap_reserve: u64, 
        pub size_of_heap_commit: u64, 
        pub loader_flags: u32, 
        pub number_of_rva_and_sizes: u32, 
        pub datas_directory: [IMAGE_DATA_DIRECTORY; 16], 
}

#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
#[repr(C)]
pub struct GUID
{
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub number_of_handles: u32,
    pub handles: Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO>,
}

#[repr(C)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    pub process_id: u16,
    pub creator_back_trace_index: u16,
    pub object_type_index: u8,
    pub handle_attributes: u8,
    pub handle_value: u16,
    pub object: PVOID,
    pub granted_access: u32,
}

#[repr(C)]
pub struct THREAD_BASIC_INFORMATION {
    pub exit_status: i32,
    pub teb_base_address: PVOID,
    pub client_id: CLIENT_ID,
    pub affinity_mask: usize,
    pub priority: i32,
    pub base_priority: i32,

}

#[repr(C)]
pub struct OVERLAPPED {
    pub internal: usize,
    pub internal_high: usize,
    pub anonymous: OVERLAPPED0,
    pub event_handle: HANDLE,
}

impl Default for OVERLAPPED {
    fn default() -> OVERLAPPED {
        OVERLAPPED {
            internal: 0usize,
            internal_high: 0usize,
            anonymous: OVERLAPPED0::default(),
            event_handle: HANDLE::default(),  
        }
    }
}

pub union OVERLAPPED0 {
    pub anonymous: OVERLAPPED_0_0,
    pub pointer: *mut c_void,
}

impl Default for OVERLAPPED0 {
    fn default() -> OVERLAPPED0 {
        OVERLAPPED0 {
            anonymous: OVERLAPPED_0_0::default(), 
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct OVERLAPPED_0_0 {
    pub offset: u32,
    pub offset_high: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct REQUEST_OPLOCK_INPUT_BUFFER {
    pub structure_version: u16,
    pub structure_length: u16,
    pub requested_oplock_level: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct REQUEST_OPLOCK_OUTPUT_BUFFER {
    pub structure_version: u16,
    pub structure_length: u16,
    pub original_oplock_level: u32,
    pub new_oplock_level: u32,
    pub flags: u32,
    pub access_mode: u32,
    pub share_mode: u16,
}

#[repr(C)]
pub struct FILE_PROCESS_IDS_USING_FILE_INFORMATION {
    pub number_of_process_ids_in_list: u32,
    pub process_id_list: [usize;1],
}