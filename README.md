# Symstress

Symstress is a tool to attempt to recover symbols in a binary given a set of source files
that the binary is suspected to be compiled from.

For example, the Realworld CTF 2022 competition had a challenge called "FLAG", where
players were given a stripped compiled binary but were told it used LWIP, RTOS, and some
other open source projects.

The motivating example is the inclusion of LWIP in the binary, a full TCP/IP stack that
is readily available and whose version number was easy to find with a small amount of
static analysis (in Binary Ninja).

Instead of some similar tools which attempt to do this using a second binary that is
compiled with symbols to populate symbols in the target binary, this is done using the
tree sitter parsing library's Python bindings.

## Installation

```sh

git clone https://github.com/novafacing/symstress.git
cd symstress
git submodule init
git submodule update
poetry install
poetry shell
python3 /path/to/binaryninja/scripts/install_api.py -v
python3 -c 'import binaryninja'
```

## Usage

Something like:
