# Instrew — LLVM-based Dynamic Binary Translation

[![builds.sr.ht status](https://builds.sr.ht/~aengelke/instrew/commits/master.svg)](https://builds.sr.ht/~aengelke/instrew/commits/master?)

Instrew is a performance-targeted transparent dynamic binary translator(/instrumenter) based on LLVM. Currently supported source/guest architectures are x86-64, AArch64, and RISC-V64 (rv64imafdc); supported host architectures are x86-64 and AArch64. The original code is lifted to LLVM-IR using [Rellume](https://github.com/aengelke/rellume), where it can be modified and from which new machine code is generated using LLVM's JIT compiler.

### Using Instrew

After cloning and checking out submodules, compile Instrew as follows:

```
mkdir build
meson build -Dbuildtype=release
ninja -C build
# optionally, run tests
ninja -C build test
```

Afterwards, you can run an application with Instrew. Statically linked applications often have a significantly lower translation time. New glibc versions often tend to use recent syscalls that are not yet supported, therefore warnings about missing system calls can sometimes be ignored.

```
./build/server/instrew /bin/ls -l
```

You can also use some options to customize the translation:

- `-profile`: print information about the time used for translation.
- `-callret`: enable call–return optimization. Often gives higher run-time performance at higher translation-time.
- `-targetopt=n`: set LLVM optimization level, 0-3. Default is 3, use 0 for FastISel.
- `-fastcc=0`: use C calling convention instead of architecture-specific optimized calling convention; primarily useful for debugging.
- `-perf=n`: enable perf support. 1=generate memory map, 2=generate JITDUMP
- `-dumpir={lift,cc,opt,codegen}`: print IR after the specified stage. Generates lots of output.
- `-dumpobj`: dump compiled code into object files in the current working directory.
- `-help`/`-help-hidden` shows more options.

Example:

```
./build/server/instrew -profile -targetopt=0 /bin/ls -l
```

### Architecture

Instrew implements a two-process client/server architecture: the light-weight client contains the guest address space as well as the code cache and controls execution, querying rewritten objects as necessary from the server. The server performs lifting (requesting instruction bytes from the client when required), instrumentation, and code generation and sends back an ELF object file. When receiving a new object file, the client resolves missing symbols and applies relocations.

### Publications

- Alexis Engelke. Optimizing Performance Using Dynamic Code Generation. Dissertation. Technical University of Munich, Munich, 2021. ([Thesis](https://mediatum.ub.tum.de/doc/1614897/1614897.pdf))
- Alexis Engelke, Dominik Okwieka, and Martin Schulz. Efficient LLVM-Based Dynamic Binary Translation. In 17th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (VEE ’21), April 16, 2021. [Paper](https://home.in.tum.de/~engelke/pubs/2104-vee.pdf)
- Alexis Engelke and Martin Schulz. Instrew: Leveraging LLVM for High Performance Dynamic Binary Instrumentation. In 16th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (VEE ’20), March 17, 2020, Lausanne, Switzerland. [Paper](https://home.in.tum.de/~engelke/pubs/2003-vee.pdf) -- Please cite this paper when referring to Instrew in general.

### License
Instrew is licensed under LGPLv2.1+.
