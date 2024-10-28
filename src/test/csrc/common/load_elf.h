/***************************************************************************************
* Copyright (c) 2020-2023 Institute of Computing Technology, Chinese Academy of Sciences
* Copyright (c) 2020-2021 Peng Cheng Laboratory
*
* DiffTest is licensed under Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*          http://license.coscl.org.cn/MulanPSL2
*
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
* EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
* MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
*
* See the Mulan PSL v2 for more details.
***************************************************************************************/

#ifndef LOAD_ELF_H
#define LOAD_ELF_H

#include "common.h"
#include <map>
#include <sys/stat.h>
#include <vector>

// elf functions
// Modified from: https://github.com/riscv-software-src/riscv-isa-sim

static inline uint8_t swap(uint8_t n) {
  return n;
}
static inline uint16_t swap(uint16_t n) {
  return (n >> 8) | (n << 8);
}
static inline uint32_t swap(uint32_t n) {
  return (swap(uint16_t(n)) << 16) | swap(uint16_t(n >> 16));
}
static inline uint64_t swap(uint64_t n) {
  return ((uint64_t)(swap(uint32_t(n))) << 32) | swap(uint32_t(n >> 32));
}
static inline int8_t swap(int8_t n) {
  return n;
}
static inline int16_t swap(int16_t n) {
  return int16_t(swap(uint16_t(n)));
}
static inline int32_t swap(int32_t n) {
  return int32_t(swap(uint32_t(n)));
}
static inline int64_t swap(int64_t n) {
  return int64_t(swap(uint64_t(n)));
}

#ifdef HAVE_INT128
typedef __uint128_t uint128_t;
typedef unsigned __int128 uint128_t;
static inline uint128_t swap(uint128_t n) {
  return (uint128_t(swap(uint64_t(n))) << 64) | swap(uint64_t(n >> 64));
}
typedef int128_t = swap(int128_t n) {
  return int128_t(swap(uint128_t(n)));
}
#endif

#ifdef WORDS_BIGENDIAN
template <typename T> static inline T from_be(T n) {
  return n;
}
template <typename T> static inline T to_be(T n) {
  return n;
}
template <typename T> static inline T from_le(T n) {
  return swap(n);
}
template <typename T> static inline T to_le(T n) {
  return swap(n);
}
#else
template <typename T> static inline T from_be(T n) {
  return swap(n);
}
template <typename T> static inline T to_be(T n) {
  return swap(n);
}
template <typename T> static inline T from_le(T n) {
  return n;
}
template <typename T> static inline T to_le(T n) {
  return n;
}
#endif

#define ET_EXEC    2
#define EM_RISCV   243
#define EM_NONE    0
#define EV_CURRENT 1

#define IS_ELF(hdr) \
  ((hdr).e_ident[0] == 0x7F && (hdr).e_ident[1] == 'E' && (hdr).e_ident[2] == 'L' && (hdr).e_ident[3] == 'F')

#define ELF_SWAP(hdr, val) (IS_ELFLE(hdr) ? from_le((val)) : from_be((val)))

#define IS_ELF32(hdr)        (IS_ELF(hdr) && (hdr).e_ident[4] == 1)
#define IS_ELF64(hdr)        (IS_ELF(hdr) && (hdr).e_ident[4] == 2)
#define IS_ELFLE(hdr)        (IS_ELF(hdr) && (hdr).e_ident[5] == 1)
#define IS_ELFBE(hdr)        (IS_ELF(hdr) && (hdr).e_ident[5] == 2)
#define IS_ELF_EXE(hdr)      (IS_ELF(hdr) && ELF_SWAP(hdr, (hdr).e_type) == ET_EXEC)
#define IS_ELF_RISCV(hdr)    (IS_ELF(hdr) && ELF_SWAP(hdr, (hdr).e_machine) == EM_RISCV)
#define IS_ELF_EM_NONE(hdr)  (IS_ELF(hdr) && ELF_SWAP(hdr, (hdr).e_machine) == EM_NONE)
#define IS_ELF_VCURRENT(hdr) (IS_ELF(hdr) && ELF_SWAP(hdr, (hdr).e_version) == EV_CURRENT)

#define PT_LOAD 1

#define SHT_NOBITS 8

typedef uint64_t paddr_t;

typedef struct {
  uint8_t e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint32_t e_entry;
  uint32_t e_phoff;
  uint32_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} Elf32_Ehdr;

typedef struct {
  uint32_t sh_name;
  uint32_t sh_type;
  uint32_t sh_flags;
  uint32_t sh_addr;
  uint32_t sh_offset;
  uint32_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint32_t sh_addralign;
  uint32_t sh_entsize;
} Elf32_Shdr;

typedef struct {
  uint32_t p_type;
  uint32_t p_offset;
  uint32_t p_vaddr;
  uint32_t p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;
} Elf32_Phdr;

typedef struct {
  uint32_t st_name;
  uint32_t st_value;
  uint32_t st_size;
  uint8_t st_info;
  uint8_t st_other;
  uint16_t st_shndx;
} Elf32_Sym;

typedef struct {
  uint8_t e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} Elf64_Phdr;

typedef struct {
  uint32_t st_name;
  uint8_t st_info;
  uint8_t st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
} Elf64_Sym;

int isElfFile(const char *fn);
uint64_t load_elf(uint64_t *ram, const char *fn);

#endif
