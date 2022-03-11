import cmd
import os
import sys
import gadget
from keystone import *
from capstone import *

class ropshell(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = "\033[33mgadgetfinder> \033[0m"
        self.intro = "Simple ROP shell to find gadgets"
        self.asmed = None
        self.ruler = '-'
        self.binary = None

    def do_load(self, line):
        if line == "":
            self.help_load()
            return ''

        line = line.split()
        filename = line[0]

        try:
            open(filename, 'r')
        except:
            print("Error reading " + filename)
            return ''

        self.binary = gadget.gadget(filename)
        print("Done.")
    
    def do_disas(self, line):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        idx = line.index(']')
        l1 = line[:idx + 1]
        l2 = line[idx + 1:]
        addr = 0
        if(len(l2) > 1):
            addr = int(l2)
        blist = eval(l1)
        code = bytearray()
        for i in blist:
            if(len(i) > 3):
                code += bytes.fromhex(i[2:])
            else:
                code += bytes.fromhex('0' + i[2:])
        for i in md.disasm(code, addr):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    def do_asm(self, line):
        try:
            # Initialize engine in X86-32bit mode
            code = line
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
            encoding, count = ks.asm(code)
            self.asmed = ('').join([chr(x) for x in encoding]).encode()
            print("%s = %s \n(number of instructions: %u)" %(code,
                [hex(x) for x in encoding], count))
        except:
            print("ERROR ASSEMBLING")
            
    def do_info(self, line):
        if not self.binary:
            print('No file loaded')
        self.binary.printinfo()

    def do_dump(self, line):
        if not self.binary:
            print('No file loaded')
        self.binary.dump()

    def help_load(self):
        print("Load Binary File")
        print("Usage: load filename fileformat")
        print("Supported format: ELF")

    def help_info(self):
        print("Print the basic info of the binary file")

    def help_dump(self):
        print("Display the disassembled instructions")

    def help_asm(self):
        print("Assemble instructions to bytecode")
        print("Usage: asm instructions")
        print("Example: asm add eax, ebx; pop ecx")

    def help_disas(self):
        print("Disassemble bytecode")
        print("Usage: asm bytecode (start address)")
        print("Example: disas ['0x1', '0xd8', '0x59'] 40")

    def do_exit(self, line):
        return True


if __name__ == '__main__':
    ropshell().cmdloop()