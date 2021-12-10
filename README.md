# Dumpy

This tool dynamically calls MiniDumpWriteDump to dump lsass memory content. This process is done without opening a new process handle to lsass and using [DInvoke_rs](https://github.com/Kudaes/DInvoke_rs) to make it harder to detect its malicious behaviour. In order to obtain a valid process handle without calling OpenProcess over lsass, all process handles in the system are analyzed using NtQuerySystemInformation, NtDuplicateObject, NtQueryObject and QueryFullProcessImageNameW.

NtOpenProcess is hooked before calling MiniDumpWriteDump to avoid the opening of a new process handle over lsass.

NTFS Transaction are used in order to xor the memory dump before storing it on disk.

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and execute it:

	cargo build
	dumpy.exe dump "your secret key"

A succesful execution will create an xor encrypted dump file with a random name in the current directory. In order to decrypt the file, execute dumpy as follows:

	dumpy.exe decrypt input_file_name output_file_name "your secret key"
