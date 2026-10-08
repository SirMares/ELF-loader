# ELF Loader

Un loader minimal de executabile ELF 64-bit scris în C, realizat ca temă la facultate (Sisteme de Operare).

Programul mapează în memorie un fișier ELF, îi validează header-ul, încarcă segmentele `PT_LOAD` și îi transferă execuția.

## Cerințe
- Linux x86_64
- `gcc`, `make`

## Build
```bash
make
```

## Rulare
```bash
./elf-loader <executabil_elf> [argumente...]
```

## Curățare
```bash
make clean
```

## Structură
- `elf-loader.c` – implementarea loader-ului
- `Makefile` – build (`-static-pie`)

## Licență
Codul sursă conține header-ul `SPDX-License-Identifier: BSD-3-Clause`.
