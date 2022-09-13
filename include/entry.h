#pragma once

#if defined(NANO) && defined(PPL)

#include <windows.h>

#define UNUSED(x) (void)(x)

typedef LPWSTR*(WINAPI* CommandLineToArgvW_t) (LPCWSTR lpCmdLine, int *pNumArgs);
typedef LPWSTR(WINAPI* GetCommandLineW_t) (VOID);

#define CommandLineToArgvW_SW2_HASH 0xFF4DDE07
#define GetCommandLineW_SW2_HASH 0x6507A19C

//
// SspiCli.dll
//
__declspec(dllexport) void APIENTRY LogonUserExExW(VOID);

//
// EventAggregation.dll
//
__declspec(dllexport) void APIENTRY BriCreateBrokeredEvent(VOID);
__declspec(dllexport) void APIENTRY BriDeleteBrokeredEvent(VOID);
__declspec(dllexport) void APIENTRY EaCreateAggregatedEvent(VOID);
__declspec(dllexport) void APIENTRY EACreateAggregateEvent(VOID);
__declspec(dllexport) void APIENTRY EaQueryAggregatedEventParameters(VOID);
__declspec(dllexport) void APIENTRY EAQueryAggregateEventData(VOID);
__declspec(dllexport) void APIENTRY EaFreeAggregatedEventParameters(VOID);
__declspec(dllexport) void APIENTRY EaDeleteAggregatedEvent(VOID);
__declspec(dllexport) void APIENTRY EADeleteAggregateEvent(VOID);

#endif
