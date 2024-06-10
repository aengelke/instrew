# build this docker image for a clean environemnt to build instrew
FROM ubuntu:24.04

# install dependencies
RUN apt update \
    && apt install -y gnupg wget meson cmake pkg-config libssl-dev clang

# install LLVM
RUN wget --no-check-certificate -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -\
    && echo 'deb http://apt.llvm.org/bookworm/   llvm-toolchain-bookworm-17  main' >> /etc/apt/sources.list \
    && apt update \
    && apt install -y llvm-17 \
    && update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-17 17

# create mount point for project
RUN mkdir /instrew/

# build and test project
WORKDIR /instrew/
CMD /instrew/build.sh