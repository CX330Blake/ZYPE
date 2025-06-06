# ZYPE: Your Payload Encryptor

<p align="center">
  <img alt="GitHub License" src="https://img.shields.io/github/license/CX330Blake/zype">
  <img alt="GitHub top language" src="https://img.shields.io/github/languages/top/cx330blake/zype">
  <img alt="GitHub Downloads (all assets, all releases)" src="https://img.shields.io/github/downloads/cx330blake/zype/total">
  <img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/cx330blake/zype">
  <img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/CX330Blake">

</p>

<p align="center">
  <a href="#whats-zyra">What's ZYRA?</a> •
  <a href="#showcase">Showcase</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#workflow-under-the-hood">Workflow under the hood</a> •
  <a href="#packed-binary-structure">Packed binary structure</a> •
  <a href="#to-do">To Do</a> •
  <a href="#contribution">Contribution</a> •
  <a href="#star-history">Star history</a>
</p>

<p height="300" align="center">
  <img src="./assets/ZYRA.png">
</p>

## What's ZYRA?

ZYPE: Zig Yield Payload Encryptor - Transform your shellcode into undetectable, obfuscated payloads that bypass modern security solutions.

- ⚡ Lightning Fast: Written in Zig for optimal performance and memory safety
- 🎯 Multi-Method Obfuscation: Support for AES, RC4, XOR encryption plus MAC/IPv4/IPv6/UUID address obfuscation
- 🌐 Cross-Platform Compatible: Generated decoder templates work on Windows, Linux, and macOS without API dependencies
- 🛠️ Developer Friendly: Interactive mode for easy setup, plus command-line interface for automation
- 🔒 Advanced Evasion: Multiple encoding layers make static analysis nearly impossible
- 📦 Complete Solution: Generates both obfuscated payload data and ready-to-compile decoder templates
- 🚀 Zero Dependencies: Self-contained tool with no external requirements

## Showcase

## Installation

ZYPE is now currently support Linux only, but the Windows version will be released soon.

You can simply copy and paste the following one-liner to install ZYPE.

```bash
bash <(curl -sSL https://raw.githubusercontent.com/CX330Blake/ZYPE/main/install.sh)
```

> [!WARNING]  
> Never execute any untrusted script on your machine. Read the script first.

On the other hand, you can clone this repo and use the following command to build your own ZYRA biary.

```bash
git clone https://github.com/CX330Blake/ZYPE
cd ZYPE
# You can change the build flag on your own
zig build --release=fast
```

## Usage

```
 ___  _   _ ___  ____
   /   \_/  |__] |___
  /__   |   |    |___

ZYPE shellcode encryptor v0.1.0
Copyright (C) 2025 @CX330Blake.
All rights reserved.

ZYPE v0.1.0 - Shellcode encryptor and obfuscator

Usage: zype [options]

Options:
  -h, --help              Show this help message
  -v, --version           Show version information
  -i, --interactive       Interactive mode (guided setup)
  -m, --method <type>     Encryption/obfuscation method
  -f, --file <path>       Input shellcode file path

Supported Methods:
  mac                     MAC address obfuscation
  ipv4                    IPv4 address obfuscation
  ipv6                    IPv6 address obfuscation
  uuid                    UUID obfuscation
  aes                     AES encryption (CTR mode)
  rc4                     RC4 encryption
  xor                     XOR encryption

Examples:
  zype -i                                         # Interactive mode
  zype -m aes -f shellcode.bin > shellcode.zig    # AES encrypt shellcode.bin
  zype -m mac -f shellcode.bin                    # MAC address obfuscation
  zype --method rc4 --file sc.bin                 # RC4 encryption

Notes:
  - Interactive mode provides guided setup for all options
  - Output includes both obfuscated data and decoder template
  - Generated code is cross-platform compatible (no Windows APIs)
```

## Contribution

This project is maintained by [@CX330Blake](https://github.com/CX330Blake/). PRs are welcome if you also want to contribute to this project.

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=CX330Blake/ZYPE&type=Date)](https://www.star-history.com/#CX330Blake/ZYPE&Date)
