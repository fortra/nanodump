#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

if len(sys.argv) != 4:
	exit(f'usage: {sys.argv[0]} <input file> <output file> <array name>')

bin_file   = sys.argv[1]
out_file   = sys.argv[2]
array_name = sys.argv[3]

f_in  = open(out_file,'wb')
f_out = open(bin_file,'rb')

source_code  = '#pragma once\n\n'
source_code += f'unsigned char {array_name}[] = {{'
source_code += ','.join([hex(b) for b in f_out.read()])
source_code += '};\n'
source_code += f'unsigned int {array_name}_len = {os.path.getsize(bin_file)};\n'

f_in.write(source_code.encode('utf-8'))

f_out.close()
f_in.close()
