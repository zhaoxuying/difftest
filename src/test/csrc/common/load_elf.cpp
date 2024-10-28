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

#include "load_elf.h"
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>

// Return whether the file is an elf file
int isElfFile(const char *fn) {
  int fd = open(fn, O_RDONLY);
  struct stat s;
  if (fd == -1)
    throw std::invalid_argument(std::string("Specified ELF can't be opened: ") + strerror(errno));
  if (fstat(fd, &s) < 0)
    abort();
  size_t size = s.st_size;

  char *buf = (char *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (buf == MAP_FAILED)
    throw std::invalid_argument(std::string("Specified ELF can't be mapped: ") + strerror(errno));
  close(fd);

  if (size < sizeof(Elf64_Ehdr)) {
    munmap(buf, size);
    return 0;
  }
  const Elf64_Ehdr *eh64 = (const Elf64_Ehdr *)buf;
  if (!(IS_ELF32(*eh64) || IS_ELF64(*eh64))) {
    munmap(buf, size);
    return 0;
  }
  if (!(IS_ELFLE(*eh64) || IS_ELFBE(*eh64))) {
    munmap(buf, size);
    return 0;
  }
  if (!(IS_ELF_EXE(*eh64))) {
    munmap(buf, size);
    return 0;
  }
  if (!(IS_ELF_RISCV(*eh64) || IS_ELF_EM_NONE(*eh64))) {
    munmap(buf, size);
    return 0;
  }
  if (!(IS_ELF_VCURRENT(*eh64))) {
    munmap(buf, size);
    return 0;
  }
  munmap(buf, size);
  return 1;
}

uint64_t load_elf(uint64_t *ram, const char *fn) {
  int fd = open(fn, O_RDONLY);
  struct stat s;
  uint64_t elf_img_size = 0;
  if (fd == -1)
    throw std::invalid_argument(std::string("Specified ELF can't be opened: ") + strerror(errno));
  if (fstat(fd, &s) < 0)
    abort();
  size_t size = s.st_size;

  char *buf = (char *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (buf == MAP_FAILED)
    throw std::invalid_argument(std::string("Specified ELF can't be mapped: ") + strerror(errno));
  close(fd);

  assert(size >= sizeof(Elf64_Ehdr));
  const Elf64_Ehdr *eh64 = (const Elf64_Ehdr *)buf;
  assert(IS_ELF32(*eh64) || IS_ELF64(*eh64));
  assert(IS_ELFLE(*eh64) || IS_ELFBE(*eh64));
  assert(IS_ELF_EXE(*eh64));
  assert(IS_ELF_RISCV(*eh64) || IS_ELF_EM_NONE(*eh64));
  assert(IS_ELF_VCURRENT(*eh64));

  std::vector<uint8_t> zeros;

#define LOAD_ELF2RAM(ehdr_t, phdr_t, shdr_t, sym_t, bswap)                                           \
  do {                                                                                               \
    ehdr_t *eh = (ehdr_t *)buf;                                                                      \
    phdr_t *ph = (phdr_t *)(buf + bswap(eh->e_phoff));                                               \
    assert(size >= bswap(eh->e_phoff) + bswap(eh->e_phnum) * sizeof(*ph));                           \
    for (unsigned i = 0; i < bswap(eh->e_phnum); i++) {                                              \
      if (bswap(ph[i].p_type) == PT_LOAD && bswap(ph[i].p_memsz)) {                                  \
        if (bswap(ph[i].p_filesz)) {                                                                 \
          assert(size >= bswap(ph[i].p_offset) + bswap(ph[i].p_filesz));                             \
          memcpy(ram + elf_img_size, (uint8_t *)buf + bswap(ph[i].p_offset), bswap(ph[i].p_filesz)); \
        }                                                                                            \
        if (size_t pad = bswap(ph[i].p_memsz) - bswap(ph[i].p_filesz)) {                             \
          zeros.resize(pad);                                                                         \
          memcpy(ram + elf_img_size + bswap(ph[i].p_filesz), zeros.data(), pad);                     \
        }                                                                                            \
      }                                                                                              \
      elf_img_size += bswap(ph[i].p_memsz);                                                          \
    }                                                                                                \
  } while (0)

  if (IS_ELFLE(*eh64)) {
    if (IS_ELF32(*eh64))
      LOAD_ELF2RAM(Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Sym, from_le);
    else
      LOAD_ELF2RAM(Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Sym, from_le);
  } else {
    throw std::invalid_argument(
        "Specified ELF is big endian, but system uses a little-endian memory system. Not support big endian yet!");
  }

  munmap(buf, size);
  return elf_img_size;
}
