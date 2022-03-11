from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
#import pefile

class gadget():
    def __init__(self, filename, format = 'ELF'):
        self.format = format
        self.filename = filename
        self.bin_sections = []
        self.load(filename, format)

    def load(self, filename, format):
        f = open(filename, "rb")
        if(format == 'ELF'):
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
        elif(format == 'PE'):
            # pe = pefile.PE(filename)
            pass

    def printinfo(self):
        print('The file has following sections:')
        for section in self.bin_sections:
            print('Name: ' + section['name'],
                'Addr: ' + hex(section['addr']),
                'Length: ' + str(len(section['data'])))

    def dump(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for chunk in self.bin_sections:
            if chunk['name'] != '.text':
                continue
            for i in md.disasm(chunk['data'], chunk['addr']):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


if __name__ == '__main__':
    filename = input('input filename')
    f = open(filename, "rb")
    elffile = ELFFile(f)
    bin_chunks = []
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

    # pe = pefile.PE('')

    # for section in pe.sections:
    #     print(section.Name.decode('utf-8'))
    #     print("\tVirtual Address: " + hex(section.VirtualAddress))
    #     print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
    #     print("\tRaw Size: " + hex(section.SizeOfRawData))
