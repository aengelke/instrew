# Instrew — LLVM-based Dynamic Binary Instrumentation

[![Build Status](https://github.com/aengelke/instrew/workflows/CI/badge.svg)](https://github.com/aengelke/instrew/actions?query=workflow%3ACI)

Instrew is a performance-targeted transparent dynamic binary rewriter/translator/instrumenter based on LLVM targeting. Currently supported source/guest architectures are x86-64 and RISC-V64 (rv64imafdc); supported host architectures are x86-64 and AArch64. The original code is lifted to LLVM-IR using [Rellume](https://github.com/aengelke/rellume), where it can be modified and from which new machine code is generated using LLVM's MCJIT compiler.

### Architecture

Instrew implements a two-process client/server architecture: the light-weight client contains the guest address space as well as the code cache and controls execution, querying rewritten objects as necessary from the server. The server performs lifting (requesting instruction bytes from the client when required), instrumentation, and code generation and sends back an ELF object file. When receiving a new object file, the client resolves missing symbols and applies relocations.

### Publications

- Alexis Engelke, Dominik Okwieka, and Martin Schulz. 2021. Efficient LLVM-Based Dynamic Binary Translation. In 17th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (VEE ’21), April 16, 2020. *Accepted, Link will follow*
- Alexis Engelke and Martin Schulz. 2020. Instrew: Leveraging LLVM for High Performance Dynamic Binary Instrumentation. In 16th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (VEE ’20), March 17, 2020, Lausanne, Switzerland. [Paper](https://home.in.tum.de/~engelke/pubs/2003-vee.pdf) -- Please cite this paper when referring to Instrew in general.

### License
Instrew is licensed under LGPLv2.1+.
