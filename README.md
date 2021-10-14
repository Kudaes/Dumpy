# Dumpy

This tool dynamically calls MiniDumpWriteDump to dump lsass memory content. This process is done without opening a new process handle to lsass and using [DInvoke_rs](https://github.com/Kudaes/DInvoke_rs) to make it harder to detect its malicious behaviour. In order to obtain a valid process handle without calling OpenProcess over lsass, all handles in the system are analyzed using NtQuerySystemInformation, NtDuplicateObject, NtQueryObject and QueryFullProcessImageNameW.

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and execute it:

	cargo build
	dumpy.exe

A succesful execution will create a dump file called foo.dmp in the current directory.
