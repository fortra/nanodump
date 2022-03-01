
#include "delete_file.h"
#ifdef BOF
 #include "utils.c"
 #include "syscalls.c"
#endif

// this is used to delete the nanodump DLL
VOID do_delete(
    IN LPSTR file_path)
{
    if (!file_exists(file_path))
    {
        PRINT_ERR("The file does not exists");
        return;
    }
    BOOL ok = delete_file(file_path);
    if (!ok)
    {
        PRINT_ERR("Could not delete the file");
        return;
    }
    PRINT("The file has been deleted");
    return;
}

#ifdef BOF

void go(char* args, int length)
{
    datap  parser;
    LPSTR ssp_path;

    BeaconDataParse(&parser, args, length);
    ssp_path = BeaconDataExtract(&parser, NULL);

    do_delete(ssp_path);
}

#else

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("usage: %s <file path>\n", argv[0]);
        return -1;
    }

    do_delete(argv[1]);
    return 0;
}

#endif
