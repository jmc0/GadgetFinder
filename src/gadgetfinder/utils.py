#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright ©  2022-04-08 00:20 bucktoothsir <rsliu.xd@gmail.com>
#
# Distributed under terms of the MIT license.

"""

"""
import capstone as ct
import keystone as kt

ARCH_DIC = {'x86':[ct.CS_ARCH_X86, kt.KS_ARCH_X86],
            'arm':[ct.CS_ARCH_ARM, kt.KS_ARCH_ARM],
            'arm64':[ct.CS_ARCH_ARM64, kt.KS_ARCH_ARM64],
            'mips':[ct.CS_ARCH_MIPS, kt.KS_ARCH_MIPS]
            }
MOD_DIC = {'16':[ct.CS_MODE_16, kt.KS_MODE_16],
           '32':[ct.CS_MODE_32, kt.KS_MODE_32],
           '64':[ct.CS_MODE_64, kt.KS_MODE_64],
           'arm':[ct.CS_MODE_ARM, kt.KS_MODE_ARM],
           'bigendian':[ct.CS_MODE_BIG_ENDIAN, kt.KS_MODE_BIG_ENDIAN],
           'littleendian':[ct.CS_MODE_LITTLE_ENDIAN, kt.KS_MODE_LITTLE_ENDIAN]
           }


def get_ct_arch(arch_str):
    arch = ARCH_DIC.get(arch_str, None)
    if arch:
        return arch[0]
    else:
        return None


def get_ct_mod(mod_str):
    mod = MOD_DIC.get(mod_str, None)
    if mod:
        return mod[0]
    else:
        return None


def get_kt_arch(arch_str):
    arch = ARCH_DIC.get(arch_str, None)
    if arch:
        return arch[1]
    else:
        return None


def get_kt_mod(mod_str):
    mod = MOD_DIC.get(mod_str, None)
    if mod:
        return mod[1]
    else:
        return None
   

def page(str, keywords=[], lines=25):
    for k in keywords:
        str = str.replace(k, highlight(k))
    text = str.split('\n')
    length = len(text)
    for linenum in range(length):
        print(text[linenum])
        if linenum % lines == 0 and linenum >= lines:
            key = input('--More-- (%d/%d)' % (linenum-1, length))
            if key == 'q': 
                break

# linux ansicolor highlighting
def highlight(word, color='green'):
    output = ""
    suffix = "\033[0m"
    if color == "green":
       prefix = "\033[1;32m"
    output = prefix + word + suffix
    return output