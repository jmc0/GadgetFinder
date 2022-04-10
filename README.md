# GadgetFinder
A tool with interactive shell for finding gadgets in executable files. 
Support ELF and PE file format, multiple architectures and modes: x86, ARM, 32bit, 64 bit.
Can also assemble and disassemble instructions.


## Requirements
+ capstone
+ keystone
+ pyelftools
+ pefile

## Getting started
create a virtualenv:
```bash
virtualenv env            
source env/bin/activate   # activate the Python virtualenv 
```

Install development dependencies:
```bash
pip install -r requirements.txt
```

Run the interactive shell:
```bash
cd src
python3 shell.py
```

## Build your own package
You can edit configuration in setup.config.\
To build:
```bash
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade build
python3 -m build
```

## Package usage
```python
import gadgetfinder
binary = gadgetfinder.load('path/data/prog.file', 'elf', 4,'x86','32')
gadgetfinder.info(binary)
gadgetfinder.dump(binary)
gadgetfinder.disas("['0x1', '0xd8', '0x59'] 40", 'x86', '32')
gadgetfinder.asm('add eax, ebx; pop ecx', 'x86', '32')
gadgetfinder.search(binary, 'pop rbp')
```
