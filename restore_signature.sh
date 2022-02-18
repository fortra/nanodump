#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <dumpfile>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "the file '$1' does not exist."
    exit 1
fi

# restore the Signature -> PMDM
printf 'MDMP' | dd of=$1 bs=1 seek=0 count=4 conv=notrunc &>/dev/null

if [ $? -ne 0  ]; then
    echo "could not write to the file '$1'"
    exit 1
fi

# restore the Version -> 42899
printf '\x93\xa7' | dd of=$1 bs=1 seek=4 count=2 conv=notrunc &>/dev/null

if [ $? -ne 0  ]; then
    echo "could not write to the file '$1'"
    exit 1
fi

# restore the ImplementationVersion -> 0
printf '\x00\x00' | dd of=$1 bs=1 seek=6 count=2 conv=notrunc &>/dev/null

if [ $? -ne 0  ]; then
    echo "could not write to the file '$1'"
    exit 1
fi

echo "done, to analize the dump run:"
echo "python3 -m pypykatz lsa minidump $1"
