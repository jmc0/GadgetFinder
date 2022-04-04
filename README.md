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
