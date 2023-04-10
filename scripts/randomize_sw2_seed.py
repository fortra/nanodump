#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
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


def get_function_hash(seed, function_name, is_syscall=True):
    function_hash = seed
    function_name = function_name.replace('_', '')
    if is_syscall and function_name[:2] == 'Nt':
        function_name = 'Zw' + function_name[2:]
    name = function_name + '\0'
    ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

    for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
        partial_name_short = struct.unpack('<H', segment.encode())[0]
        function_hash ^= partial_name_short + ror8(function_hash)

    return function_hash


def replace_syscall_hashes(seed):
    with open('source/syscalls.c') as f:
        code = f.read()
    regex = re.compile(r'__declspec\(naked\) NTSTATUS (Nt[^(]+)')
    syscall_names = re.findall(regex, code)
    syscall_names = set(syscall_names)
    syscall_definitions = code.split('#elif defined(__GNUC__)')[4]

    for syscall_name in syscall_names:
        regex = re.compile('NTSTATUS ' + syscall_name + '\\(.*?"mov rcx, (0x[A-Fa-f0-9]{8})', re.DOTALL)
        match = re.search(regex, syscall_definitions)
        assert match is not None, f'hash of syscall {syscall_name} not found!'
        old_hash = match.group(1)
        new_hash = get_function_hash(seed, syscall_name)
        print(f'{syscall_name} -> {old_hash} - 0x{new_hash:08X}')
        code = code.replace(
            old_hash,
            f'0x{new_hash:08X}'
        )

    with open('source/syscalls.c', 'w') as f:
        f.write(code)

    with open('source/syscalls-asm.asm') as f:
        code = f.read()

    for syscall_name in syscall_names:
        regex = re.compile(syscall_name + ' PROC.*?mov rcx, 0([A-Fa-f0-9]{8})h', re.DOTALL)
        match = re.search(regex, code)
        assert match is not None, f'hash of syscall {syscall_name} not found!'
        old_hash = match.group(1)
        new_hash = get_function_hash(seed, syscall_name)
        code = code.replace(
            f'0{old_hash}h',
            f'0{new_hash:08X}h',
            1
        )

    with open('source/syscalls-asm.asm', 'w') as f:
        f.write(code)


def replace_dinvoke_hashes(seed):
    for header_file in glob.glob("include/**/*.h", recursive=True):
        with open(header_file) as f:
            code = f.read()
        regex = re.compile(r'#define (\w+)_SW2_HASH (0x[a-fA-F0-9]{8})')
        matches = re.findall(regex, code)
        for function_name, old_hash in matches:
            new_hash = get_function_hash(seed, function_name, is_syscall=False)
            code = code.replace(
                f'#define {function_name}_SW2_HASH {old_hash}',
                f'#define {function_name}_SW2_HASH 0x{new_hash:08X}',
                1
            )
        if matches:
            with open(header_file, 'w') as f:
                f.write(code)


def main():
    #new_seed = random.randint(2 ** 28, 2 ** 32 - 1)
    new_seed = 0x1337c0de
    fun = 'OpenSCManagerW'
    import sys
    fun = sys.argv[1]
    new_hash = get_function_hash(new_seed, fun, True)
    print(f'{fun}: 0x{new_hash:08X}')
    return

    old_seed = get_old_seed()
    replace_seed(old_seed, new_seed)
    replace_syscall_hashes(new_seed)
    replace_dinvoke_hashes(new_seed)
    if os.name == 'nt':
        print('done! recompile with:\nnmake -f Makefile.msvc')
    else:
        print('done! recompile with:\nmake -f Makefile.mingw')

if __name__ == '__main__':
    main()
