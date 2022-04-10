from platform import architecture
from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
import pefile
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__)))
import trie

RET_CODE = {"ret" : b"\xc3"} # return opcode
# useless instructions, we will not put these to gadgets
BAD_INSTS = ["DB", "CALL 0x", "JMP 0x", "JN", "JE", "JZ", "JB", "JA", "JAE", "JO", "IN", "HLT", "LES", "FLD"]

class gadget():
    def __init__(self, filename, file_format = 'ELF', depth=3, arch = CS_ARCH_X86, mode = CS_MODE_32):
        self.file_format = file_format
        self.arch = arch
        self.mode = mode
        self.filename = filename
        self.bin_sections = []
        self.__asmgadget = trie.Trie()
        self.__asmgadget.set_case_sensitive(False)
        self.__backward_depth = depth # default number of insts for backward processing
        self.__max_duplicate = 3 # default number duplicate gadgets, keep somes for enough offset alternatives
        self.load(filename, file_format, self.__backward_depth)

    def load(self, filename, file_format, backward_depth=3):
        f = open(filename, "rb")
        if(file_format.casefold() == 'elf'):
            elffile = ELFFile(f)

            for i in range(elffile.num_sections()):
                section = elffile.get_section(i)
                if section['sh_type'] != "SHT_PROGBITS":
                    continue
                if not (section['sh_flags'] & 0x04):
                    continue
                self.bin_sections.append({
                                'name': section.name,
                                'addr': section['sh_addr'],
                                'data': section.data()
                            })
            
        elif(file_format.casefold() == 'pe'):
            pe = pefile.PE(filename)
            for section in pe.sections:
                self.bin_sections.append({
                                    'name': section.Name.decode('utf-8').strip('\x00'),
                                    'addr': section.VirtualAddress,
                                    'data': section.get_data()
                                })
        
        self.generate(backward_depth=backward_depth)

    def printinfo(self):
        print('The file has following sections:')
        for section in self.bin_sections:
            print('Name: ' + section['name'],
                'Addr: ' + hex(section['addr']),
                'Length: ' + str(len(section['data'])))

    def dump(self):
        md = Cs(self.arch, self.mode)
        for chunk in self.bin_sections:
            if chunk['name'] != '.text':
                continue
            for i in md.disasm(chunk['data'], chunk['addr']):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    def set_backward_depth(self, depth):
        self.__backward_depth = depth

    #
    # generate the gadgets from binary file, can be called multiple times
    #
    def generate(self, backward_depth = 3):
        md = Cs(self.arch, self.mode)
        for chunk in self.bin_sections:
            self.set_backward_depth(backward_depth)
            base_addr = chunk['addr']
            print(f"Generating gadgets with backward depth={str(backward_depth)}")

            disassembly = list(md.disasm(chunk['data'], chunk['addr']))
            bincode = b"" # keep track of hex code
            for i in disassembly:
                offset = i.address - chunk['addr']
                size = i.size
                instruction = i.mnemonic + ' ' + i.op_str
                hexbyte = i.bytes
                bincode += hexbyte
                l = len(hexbyte)
                i = hexbyte.find(RET_CODE["ret"]) # find RET in opcode

                if i != -1: # RET found
                    # get back (__backward_depth * 8)
                    hexbyte = bincode[-((l-i) + (self.__backward_depth * 8)) : -(l-i)]
                    self.__process_backward(hexbyte, base_addr + offset + i - 1)

        print(f"Generated {str(self.__asmgadget.get_size())} gadgets")

    #
    # backward process for code from RET
    #
    def __process_backward(self, hexbyte, end_offset):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        RET = RET_CODE["ret"]
        l = len(hexbyte)
        for i in range(l):
            code = (hexbyte[(l-i-1) : l])
            code = code + RET
            disassembly = list(md.disasm(code, end_offset - i))
            if len(disassembly) <= self.__backward_depth + 1 and len(disassembly) > 0: # max backward depth not reach
                if disassembly[-1].bytes.lower() != RET: # invalid sequence
                    continue
                asmcode = []
                for dis in disassembly[:-1]:
                    instruction = (dis.mnemonic + ' ' + dis.op_str).upper()
                    asmcode += ("".join(instruction).replace(",", " ")).split() + [";"]

                # skip bad instructions
                s = " ".join(asmcode)
                if "CALL 0x" in s or "JMP 0x" in s:
                    continue
                if set(asmcode) & set(BAD_INSTS) != set([]):
                    continue

                #asmcode += [RET_CODE.keys()[1] + " "]
                value = (" ".join(asmcode).lower() + ";", end_offset - i)
                self.__insert_asmcode(asmcode, value)

    #
    # insert asmcode to asmgadget trie
    # special case: [eax + 0xdeadbeef], eax + 0xdeadbeef, [eax + esi * n],
    #
    def __insert_asmcode(self, instruction, value):
        result = []
        code = "@".join(instruction).replace("@;", "").replace(" ", "").lower()
        code = code.replace("[", "[@")
        code = code.replace("]", "@]")
        code = code.replace("+", "@+@")
        code = code.replace("-", "@-@")
        code = code.replace("*", "@*@")
        code = code.split("@")
        result = self.__asmgadget.retrieve(code)
        if len(result) < self.__max_duplicate: # still need offset for this gadget
            self.__asmgadget.insert(code, value)

    #
    # search for asm code in text file_format
    #
    def asm_search(self, asmcode, constraints = [set([]), set(["-00"])], depth = 1):
        # e.g mov eax,ebx
        result = []
        search_code = asmcode.upper().replace(",", " ").split()
        if depth == 2:
            search_code = search_code + ["*"]
        if depth == 3:
            search_code = ["*"] + search_code + ["*"]

        result = self.__asmgadget.retrieve(search_code)

        # filter bad instructions & bad addresses
        if result != []:
            result = self.__filter_instruction(result, constraints[0])
            result = self.__filter_address(result, constraints[1])

        # filter duplicate gadgets, just need to display few
        return result

    #
    # filter for denied inst or register in asm code
    # filter file_format: ["-esp", "-sub"]
    #
    def __filter_instruction(self, retcode, constraints = set([])):
        result = []
        if constraints == set([]): return retcode
        for code in retcode:
            found = 0
            for filter in constraints:
                if code[0].lower().find(filter[1:].lower()) != -1:
                    found = 1
                    break
            if found == 0:
                result.append(code)

        return result

    #
    # filter for denied chars in offset address
    # filter file_format: ["-00", "-0a"]
    #
    def __filter_address(self, retcode, constraints = set([])):
        result = []
        if constraints == set([]): return retcode
        for code in retcode:
            for filter in constraints:
                if hex(code[1])[2:-1].rjust(8, "0").find(filter[1:]) %2 != 0:
                    result.append(code)

        return result


if __name__ == '__main__':
    filename = input('input filename:')
    file_format = input('input file_format:')
    bin_chunks = []

    if file_format == 'ELF' or file_format == 'elf':
        f = open(filename, "rb")
        elffile = ELFFile(f)
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        for i in range(elffile.num_sections()):
            section = elffile.get_section(i)
            if section['sh_type'] != "SHT_PROGBITS":
                continue
            if not (section['sh_flags'] & 0x04):
                continue

            bin_chunks.append({
                            'name': section.name,
                            'addr': section['sh_addr'],
                            'data': section.data()
                        })

        print(bin_chunks)

        for chunk in bin_chunks:
            if chunk['name'] != '.text':
                continue
            for i in md.disasm(chunk['data'], chunk['addr']+1):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    
    elif file_format == 'PE' or file_format == 'pe':
        
        pe = pefile.PE(filename)
        for section in pe.sections:
            print(section.Name.decode('utf-8'))
            print("\tVirtual Address: " + hex(section.VirtualAddress))
            print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
            print("\tRaw Size: " + hex(section.SizeOfRawData))
            bin_chunks.append({
                                'name': section.Name.decode('utf-8'),
                                'addr': section.VirtualAddress,
                                'data': section.get_data()
                            })
        
        print(bin_chunks)

    else:
        print('Unsupported file_format')
