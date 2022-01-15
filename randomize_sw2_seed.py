#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import glob
import random
import struct


def get_old_seed():
    with open('include/syscalls.h') as f:
        code = f.read()
    match = re.search(r'#define SW2_SEED (0x[a-fA-F0-9]{8})', code)
    assert match is not None, 'SW2_SEED not found!'
    return match.group(1)


def replace_seed(old_seed, new_seed):
    with open('include/syscalls.h') as f:
        code = f.read()
    code = code.replace(
        f'#define SW2_SEED {old_seed}',
        f'#define SW2_SEED 0x{new_seed:08X}',
        1
    )
    with open('include/syscalls.h', 'w') as f:
        f.write(code)


def get_function_hash(seed, function_name):
    function_hash = seed
    name = function_name.replace('Nt', 'Zw', 1) + '\0'
    ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

    for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
        partial_name_short = struct.unpack('<H', segment.encode())[0]
        function_hash ^= partial_name_short + ror8(function_hash)

    return function_hash


def replace_syscall_hashes(seed):
    with open('include/syscalls-asm.h') as f:
        code = f.read()
    regex = re.compile(r'__asm__\("(Nt\w+):')
    syscall_names = re.findall(regex, code)
    # every syscall is included twice (x86 and x64)
    syscall_names = syscall_names[:len(syscall_names)//2]

    for syscall_name in syscall_names:
        regex = re.compile(r'__asm__\("' + syscall_name + ': .*?mov ecx, (0x[A-Fa-f0-9]{8})', re.DOTALL)
        match = re.search(regex, code)
        assert match is not None, f'hash of syscall {syscall_name} not found!'
        old_hash = match.group(1)
        new_hash = get_function_hash(seed, syscall_name)
        code = code.replace(
            old_hash,
            f'0x{new_hash:08X}',
            2
        )

    with open('include/syscalls-asm.h', 'w') as f:
        f.write(code)


def replace_dinvoke_hashes(seed):
    for header_file in glob.glob("include/*.h"):
        with open(header_file) as f:
            code = f.read()
        regex = re.compile(r'#define (\w+)_SW2_HASH (0x[a-fA-F0-9]{8})')
        matches = re.findall(regex, code)
        for function_name, old_hash in matches:
            new_hash = get_function_hash(seed, function_name)
            code = code.replace(
                f'#define {function_name}_SW2_HASH {old_hash}',
                f'#define {function_name}_SW2_HASH 0x{new_hash:08X}',
                1
            )
        if matches:
            with open(header_file, 'w') as f:
                f.write(code)


def main():
    new_seed = random.randint(2 ** 28, 2 ** 32 - 1)
    old_seed = get_old_seed()
    replace_seed(old_seed, new_seed)
    replace_syscall_hashes(new_seed)
    replace_dinvoke_hashes(new_seed)
    print('done! recompile with: \'make\'')


if __name__ == '__main__':
    main()
