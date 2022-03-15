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
        try:
            format = str(line[1])
        except:
            format = 'ELF'

        try:
            depth = int(line[2])
        except:
            depth = 3

        self.binary = gadget.gadget(filename, format=format, depth=depth)
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

    def do_search(self, line):
        if line == "":
            self.help_search()
            return ''
        
        search_code = ""    
        constraints = []
        lines = line.strip().split()
        for s in lines:
            if s[0] == "-" and len(s) > 1: # a constraint
                constraints += [s]
            else:
                search_code += " " + s
            
        print(f"Searching for ROP gadget: {search_code} with constraints: {constraints}")
        
        output = ""
        for result in self.binary.asm_search(search_code, [set(constraints), set([])]):
            if len(result) > 1:
                (code, offset) = result
                # just list out unique code for 3 times
                output += hex(offset) + ": " + code + "\n"
        keywords = search_code.replace("?", "").replace("%", "").replace("[", "").replace("]", "").strip()
        keywords = keywords.split()
        self.__page(output, keywords)
        
        return ''
        
    def help_search(self):
        print('\n'.join([ 'Search for ROP gadgets, support wildcard matching ?, %',
                            'Usage: search gadget [-exclude_instruction]',
                            'Example: search mov eax ? # search for all gadgets contains "mov eax"',
                            'Example: search add [ eax % ] % # search for all gadgets starting with "add [eax"', 
                            'Example: search pop eax % -leave # search for all gadgets starting with "pop eax" and not contain "leave"',
                       ]))

    def help_load(self):
        print("Load Binary File")
        print("Usage: load filename file_format backword_depth")
        print("Supported format: ELF 4")

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

    # simple paging
    def __page(self, str, keywords=[], lines=25):
        for k in keywords:
            str = str.replace(k, self.__highlight(k))
        text = str.split('\n')
        length = len(text)
        for linenum in range(length):
            print(text[linenum])
            if linenum % lines == 0 and linenum >= lines:
                key = input('--More-- (%d/%d)' % (linenum-1, length))
                if key == 'q': 
                    break

    # linux ansicolor highlighting
    def __highlight(self, word, color = "green"):
        output = ""
        suffix = "\033[0m"
        if color == "green":
            prefix = "\033[1;32m"
        
        output = prefix + word + suffix
        return output


if __name__ == '__main__':
    ropshell().cmdloop()