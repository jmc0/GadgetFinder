import cmd
import os
import sys
import gadget


class ropshell(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = "\033[33mgadgetfinder> \033[0m"
        self.intro = "Simple ROP shell to find gadgets"
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

    def do_exit(self, line):
        return True


if __name__ == '__main__':
    ropshell().cmdloop()