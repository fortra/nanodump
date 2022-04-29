#include <stdio.h>

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <input file>\n", argv[0]);
        return -1;
    }

    FILE* f = fopen(argv[1], "r+");
    if (!f)
    {
        fprintf(stderr, "Invalid input file: %s\n", argv[1]);
        return -1;
    }

    // valid signature
    unsigned char signature[] = { 0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00 };

    fseek(f, 0L, SEEK_SET);
    fwrite(signature, sizeof(signature), sizeof(unsigned char), f);

    fclose(f); f = NULL;

    printf("done, to analize the dump run:\npython3 -m pypykatz lsa minidump %s\n", argv[1]);

    return 0;
}
