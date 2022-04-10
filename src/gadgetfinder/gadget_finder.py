#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright ©  2022-04-07 20:11 bucktoothsir <rsliu.xd@gmail.com>
#
# Distributed under terms of the MIT license.

"""
Gagedt Finder
"""

import os
import sys
import capstone as ct
import keystone as kt

sys.path.append(os.path.join(os.path.dirname(__file__)))
from gadget import gadget
from utils import get_ct_arch, get_ct_mod, get_kt_arch, get_kt_mod, page


def load(filename, file_format='elf', depth=3, arch='x86', mode='32'):
    """load file to find gadget
    Args:
        filename: str.
        file_format: str, default value: 'elf', so far only support 'elf' an 'pe'.
        depth: int, default value: 3
        arch: str, default value: 'x86'
        mode: str, default value: '32'
    Returns:
        A gadget object, containing binary code of the file.
    """
    arch = get_ct_arch(arch)
    if not arch:
        print('Unsupported architecture')
        return
    mode = get_ct_mod(mode)
    if not mode:
        print('Unsupported architecture')
        return
    print(filename)
    print(file_format)
    print(arch)
    print(mode)
    return gadget(filename, file_format=file_format, depth=depth, arch=arch, mode=mode)


def disas(start_address, arch='x86', mode='32'):
    """Disassemble bytecode"
    Args:
        start_address: str, eg: "['0x1', '0xd8', '0x59'] 40"
        arch: str, default value: 'x86'
        mode: str, default value: '32'
    """
    arch = get_ct_arch(arch)
    if arch is None:
        print('Unsupported architecture')
        return
    mode = get_ct_mod(mode)
    if mode is None:
        print('Unsupported mode')
        return
    md = ct.Cs(arch, mode)
    idx = start_address.index(']')
    l1 = start_address[:idx + 1]
    l2 = start_address[idx + 1:]
    addr = 0
    if(len(l2) > 1):
        addr = int(l2, 16) if '0x' in l2 else int(l2)
    try:
        blist = eval(l1)
    except:
        print("Corrupted binary code")
        return
    code = bytearray()
    for i in blist:
        if(len(i) > 3):
            code += bytes.fromhex(i[2:])
        else:
            code += bytes.fromhex('0' + i[2:])
    try:
        for i in md.disasm(code, addr):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    except:
        print("ERROR DISASSEMBLING")


def asm(code, arch='x86', mode='32'):
    """Assemble instructions to bytecode""
    Args:
        code: str, eg: add eax, ebx; pop ecx
        arch: str, default value: 'x86'
        mode: str, default value: '32'
    """
    arch = get_kt_arch(arch)
    if arch is None:
        print('Unsupported architecture')
        return
    mode = get_kt_mod(mode)
    if mode is None:
        print('Unsupported mode')
        return
    try:
        ks = kt.Ks(arch, mode)  # Initialize engine in X86-32bit mode
        encoding, count = ks.asm(code)
        print("%s = %s \n(number of instructions: %u)" % (code, [hex(x) for x in encoding], count))
    except:
        print("ERROR ASSEMBLING")


def search(binary, line):
    """Search for ROP gadgets, support wildcard matching ?, %'
    Args:
        binary: gadget object
        line: str, eg: pop rbp
    """
    if not line:
        print('Empty Input')
        return ''
    search_code = ""
    constraints = []
    lines = line.strip().split()
    for s in lines:
        if s[0] == "-" and len(s) > 1:  # a constraint
            constraints += [s]
        else:
            search_code += " " + s
    print(f"Searching for ROP gadget: {search_code} with constraints: {constraints}")
    output = ""
    for result in binary.asm_search(search_code, [set(constraints), set([])]):
        if len(result) > 1:
            (code, offset) = result
            # just list out unique code for 3 times
            output += hex(offset) + ": " + code + "\n"
    keywords = search_code.replace("?", "").replace("%", "").replace("[", "").replace("]", "").strip()
    keywords = keywords.split()
    page(output, keywords)


def dump(binary):
    """Display the disassembled instructions
    Args:
        binary: gadget object
    """
    binary.dump()


def info(binary):
    """Print the basic info of the binary file
    Args:
        binary: gadget object
    """
    binary.printinfo()
