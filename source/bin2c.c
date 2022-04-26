#include <stdio.h>

int main(int argc, char** argv)
{
	if (argc != 3)
	{
		fprintf(stderr, "usage: %s <input file> <array name>\n", argv[0]);
		return 0;
	}

	FILE* f = fopen(argv[1], "rb");
	if (!f)
	{
		fprintf(stderr, "Invalid input file: %s\n", argv[1]);
		return -1;
	}

	printf("#pragma once\n\nunsigned char %s[] = {", argv[2]);

	unsigned long n = 0;
	unsigned char c;
	while(!feof(f))
	{
		if (!fread(&c, 1, 1, f))
			break;
		printf("0x%.2X,", (int)c);
		n++;
	}
	fclose(f);

	printf("};\n");
	printf("unsigned int %s_len = %ld;\n", argv[2], n);

	return 0;
}
