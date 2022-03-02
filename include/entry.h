#pragma once

#if defined(NANO) && defined(PPL)

#include <windows.h>

typedef LPWSTR*(WINAPI* CommandLineToArgvW_t) (LPCWSTR lpCmdLine, int *pNumArgs);
typedef LPWSTR(WINAPI* GetCommandLineW_t) ();

#define CommandLineToArgvW_SW2_HASH 0xFF4DDE07
#define GetCommandLineW_SW2_HASH 0x6507A19C

//
// SspiCli.dll
//
__declspec(dllexport) void APIENTRY LogonUserExExW();

//
// EventAggregation.dll
//
__declspec(dllexport) void APIENTRY BriCreateBrokeredEvent();
__declspec(dllexport) void APIENTRY BriDeleteBrokeredEvent();
__declspec(dllexport) void APIENTRY EaCreateAggregatedEvent();
__declspec(dllexport) void APIENTRY EACreateAggregateEvent();
__declspec(dllexport) void APIENTRY EaQueryAggregatedEventParameters();
__declspec(dllexport) void APIENTRY EAQueryAggregateEventData();
__declspec(dllexport) void APIENTRY EaFreeAggregatedEventParameters();
__declspec(dllexport) void APIENTRY EaDeleteAggregatedEvent();
__declspec(dllexport) void APIENTRY EADeleteAggregateEvent();

#endif
