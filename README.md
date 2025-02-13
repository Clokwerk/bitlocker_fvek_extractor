
# BitLocker FVEK Extractor

This is a small Python script for extracting BitLocker Full Volume Encryption Keys (FVEK) from RAM dumps. It is meant to be used by digital forensics professionals.


## Features

- Looks for FVEK by scanning the memory around identified Widnows Memory Pool tags.
- Determines Windows OS version and build by fingerprinting LSASS (Local Security Authority Subsystem Service).
- Currently only tested on "Windows 10/11 x64 WIN_10_1809+".


## Acknowledgements
Inspired by MemProcFS and Pypykatz
 - [MemProcFS](https://github.com/ufrisk/MemProcFS)
 - [Pypykatz](https://github.com/skelsec/pypykatz/tree/main)


## Usage/Examples

```bash
python3 bitlocker_extractor.py -f /path/to/memdump
```


## Installation

Just clone the repo, give permissions and you're good to go!

```bash
  git clone https://github.com/Clokwerk/bitlocker_fvek_extractor.git
  chmod +x bitlocker_extractor.py
```
    
