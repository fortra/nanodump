#pragma once

#ifdef BOF
 #include "beacon.h"
#else
 #include <stdio.h>
#endif

#if defined(BOF)
 #define PRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#elif defined(EXE)
 #define PRINT(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }
#else
 #define PRINT(...)
#endif

#if defined(BOF)
 #define PRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#elif defined(EXE)
 #define PRINT_ERR(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }
#else
 #define PRINT_ERR(...)
#endif

#if defined(DEBUG) && defined(BOF)
 #define DPRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#elif defined(DEBUG) && defined(EXE)
 #define DPRINT(...) { \
     fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...)
#endif

#if defined(DEBUG) && defined(BOF)
 #define DPRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#elif defined(DEBUG) && defined(EXE)
 #define DPRINT_ERR(...) { \
     fprintf(stderr, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT_ERR(...)
#endif

#define syscall_failed(syscall_name, status) \
    DPRINT_ERR( \
        "Failed to call %s, status: 0x%lx", \
        syscall_name, \
        status \
    )

#define function_failed(function) \
    DPRINT_ERR( \
        "Failed to call '%s', error: %ld", \
        function, \
        GetLastError() \
    )

#define malloc_failed() function_failed("HeapAlloc")
