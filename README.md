# GadgetFinder
A tool with interactive shell for finding gadgets in executable files. 
Support ELF and PE file format, multiple architectures and modes: x86, ARM, 32bit, 64 bit.
Can also assemble and disassemble instructions.


## Requirements
+ capstone
+ keystone
+ elftools
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
cd gadgetfinder
python ropshell.py
```
