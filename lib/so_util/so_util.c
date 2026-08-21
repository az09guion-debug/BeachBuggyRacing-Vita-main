/* so_util.c -- utils to load and hook .so modules
 *
 * Copyright (C) 2021 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.	See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#include "utils/dialog.h"
#include "so_util.h"

#ifndef ALIGN_MEM
#define ALIGN_MEM(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#endif

typedef int SceUID;

#define sceClibPrintf printf
#define sceClibMemcpy memcpy
#define kuKernelCpuUnrestrictedMemcpy(dst, src, sz) memcpy(dst, src, sz)
#define kuKernelFlushCaches(addr, sz) __builtin___clear_cache((char *)(addr), (char *)(addr) + (sz))

typedef struct b_enc {
    union {
        struct __attribute__((__packed__)) {
            int imm24: 24;
            unsigned int l: 1; // Branch with Link flag
            unsigned int enc: 3; // 0b101
            unsigned int cond: 4; // 0b1110
        } bits;
        uint32_t raw;
    };
} b_enc;

typedef struct ldst_enc {
    union {
        struct __attribute__((__packed__)) {
            int imm12: 12;
            unsigned int rt: 4; // Source/Destination register
            unsigned int rn: 4; // Base register
            unsigned int bit20_1: 1; // 0: store to memory, 1: load from memory
            unsigned int w: 1; // 0: no write-back, 1: write address into base
            unsigned int b: 1; // 0: word, 1: byte
            unsigned int u: 1; // 0: subtract offset from base, 1: add to base
            unsigned int p: 1; // 0: post indexing, 1: pre indexing
            unsigned int enc: 3;
            unsigned int cond: 4;
        } bits;
        uint32_t raw;
    };
} ldst_enc;

#define B_RANGE ((1 << 24) - 1)
#define B_OFFSET(x) (x + 8) // branch jumps into addr - 8, so range is biased forward
#define B(PC, DEST) ((b_enc){.bits = {.cond = 0b1110, .enc = 0b101, .l = 0, .imm24 = (((intptr_t)DEST-(intptr_t)PC) / 4) - 2}})
#define LDR_OFFS(RT, RN, IMM) ((ldst_enc){.bits = {.cond = 0b1110, .enc = 0b010, .p = 1, .u = (IMM >= 0), .b = 0, .w = 0, .bit20_1 = 1, .rn = RN, .rt = RT, .imm12 = (IMM >= 0) ? IMM : -IMM}})

#define PATCH_SZ 0x10000 //64 KB-ish arenas
static so_module *head = NULL, *tail = NULL;

so_hook hook_thumb(uintptr_t addr, uintptr_t dst) {
    so_hook h;
    printf("THUMB HOOK\n");
    if (addr == 0)
        return h;
    h.thumb_addr = addr;
    addr &= ~1;
    if (addr & 2) {
        uint16_t nop = 0xbf00;
        memcpy((void *)addr, &nop, sizeof(nop));
        addr += 2;
        printf("THUMB UNALIGNED\n");
    }

    h.addr = addr;
    h.patch_instr[0] = 0xf000f8df; // LDR PC, [PC]
    h.patch_instr[1] = dst;
    memcpy(&h.orig_instr, (void *)addr, sizeof(h.orig_instr));
    memcpy((void *)addr, h.patch_instr, sizeof(h.patch_instr));

    return h;
}

so_hook hook_arm(uintptr_t addr, uintptr_t dst) {
    so_hook h;
    printf("ARM HOOK\n");
    if (addr == 0)
        return h;
    h.thumb_addr = 0;
    h.addr = addr;
    h.patch_instr[0] = 0xe51ff004; // LDR PC, [PC, #-0x4]
    h.patch_instr[1] = dst;
    memcpy(&h.orig_instr, (void *)addr, sizeof(h.orig_instr));
    memcpy((void *)addr, h.patch_instr, sizeof(h.patch_instr));

    return h;
}

so_hook hook_addr(uintptr_t addr, uintptr_t dst) {
    if (addr == 0) {
        so_hook h;
        return h;
    }

    if (addr & 1)
        return hook_thumb(addr, dst);
    else
        return hook_arm(addr, dst);
}

void so_flush_caches(so_module *mod) {
    __builtin___clear_cache((char *)mod->text_base, (char *)(mod->text_base + mod->text_size));
}

int _so_load(so_module *mod, SceUID so_blockid, void *so_data, uintptr_t load_addr) {
    int res = 0;
    uintptr_t data_addr = 0;

    if (memcmp(so_data, ELFMAG, SELFMAG) != 0) {
        res = -1;
        goto err_free_so;
    }

    mod->ehdr = (Elf32_Ehdr *)so_data;
    mod->phdr = (Elf32_Phdr *)((uintptr_t)so_data + mod->ehdr->e_phoff);
    mod->shdr = (Elf32_Shdr *)((uintptr_t)so_data + mod->ehdr->e_shoff);

    mod->shstr = (char *)((uintptr_t)so_data + mod->shdr[mod->ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < mod->ehdr->e_phnum; i++) {
        if (mod->phdr[i].p_type == PT_LOAD) {
            void *prog_data = NULL;
            size_t prog_size = 0;

            if ((mod->phdr[i].p_flags & PF_X) == PF_X) {
                mod->patch_size = ALIGN_MEM(PATCH_SZ, mod->phdr[i].p_align);
                
                void *patch_ptr = mmap(NULL, mod->patch_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                if (patch_ptr == MAP_FAILED)
                    goto err_free_so;

                mod->patch_base = (uintptr_t)patch_ptr;
                mod->patch_head = mod->patch_base;

                prog_size = ALIGN_MEM(mod->phdr[i].p_memsz, mod->phdr[i].p_align);
                
                void *text_ptr = mmap(NULL, prog_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                if (text_ptr == MAP_FAILED)
                    goto err_free_so;

                prog_data = text_ptr;
                mod->phdr[i].p_vaddr += (Elf32_Addr)prog_data;

                mod->text_base = mod->phdr[i].p_vaddr;
                mod->text_size = mod->phdr[i].p_memsz;

                mod->cave_size = ALIGN_MEM(prog_size - mod->phdr[i].p_memsz, 0x4);
                mod->cave_base = mod->cave_head = (uintptr_t) prog_data + mod->phdr[i].p_memsz;
                mod->cave_base = ALIGN_MEM(mod->cave_base, 0x4);
                mod->cave_head = mod->cave_base;
                printf("code cave: %zu bytes (@0x%08X).\n", mod->cave_size, (unsigned int)mod->cave_base);

                data_addr = (uintptr_t)prog_data + prog_size;
            } else {
                if (data_addr == 0)
                    goto err_free_so;

                if (mod->n_data >= MAX_DATA_SEG)
                    goto err_free_data;

                prog_size = ALIGN_MEM(mod->phdr[i].p_memsz + mod->phdr[i].p_vaddr - (data_addr - mod->text_base), mod->phdr[i].p_align);

                void *data_ptr = mmap(NULL, prog_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                if (data_ptr == MAP_FAILED)
                    goto err_free_text;

                prog_data = data_ptr;
                data_addr = (uintptr_t)prog_data + prog_size;

                mod->phdr[i].p_vaddr += (Elf32_Addr)mod->text_base;

                mod->data_base[mod->n_data] = mod->phdr[i].p_vaddr;
                mod->data_size[mod->n_data] = mod->phdr[i].p_memsz;
                mod->n_data++;
            }

            char *zero = calloc(1, prog_size - mod->phdr[i].p_filesz);
            if (zero) {
                memcpy((void *)((uintptr_t)prog_data + mod->phdr[i].p_filesz), zero, prog_size - mod->phdr[i].p_filesz);
                free(zero);
            }

            memcpy((void *)mod->phdr[i].p_vaddr, (void *)((uintptr_t)so_data + mod->phdr[i].p_offset), mod->phdr[i].p_filesz);
        }
    }

    for (int i = 0; i < mod->ehdr->e_shnum; i++) {
        char *sh_name = mod->shstr + mod->shdr[i].sh_name;
        uintptr_t sh_addr = mod->text_base + mod->shdr[i].sh_addr;
        size_t sh_size = mod->shdr[i].sh_size;
        if (strcmp(sh_name, ".dynamic") == 0) {
            mod->dynamic = (Elf32_Dyn *)sh_addr;
            mod->num_dynamic = sh_size / sizeof(Elf32_Dyn);
        } else if (strcmp(sh_name, ".dynstr") == 0) {
            mod->dynstr = (char *)sh_addr;
        } else if (strcmp(sh_name, ".dynsym") == 0) {
            mod->dynsym = (Elf32_Sym *)sh_addr;
            mod->num_dynsym = sh_size / sizeof(Elf32_Sym);
        } else if (strcmp(sh_name, ".rel.dyn") == 0) {
            mod->reldyn = (Elf32_Rel *)sh_addr;
            mod->num_reldyn = sh_size / sizeof(Elf32_Rel);
        } else if (strcmp(sh_name, ".rel.plt") == 0) {
            mod->relplt = (Elf32_Rel *)sh_addr;
            mod->num_relplt = sh_size / sizeof(Elf32_Rel);
        } else if (strcmp(sh_name, ".init_array") == 0) {
            mod->init_array = (void *)sh_addr;
            mod->num_init_array = sh_size / sizeof(void *);
        } else if (strcmp(sh_name, ".hash") == 0) {
            mod->hash = (void *)sh_addr;
        }
    }

    if (mod->dynamic == NULL ||
        mod->dynstr == NULL ||
        mod->dynsym == NULL ||
        mod->reldyn == NULL ||
        mod->relplt == NULL) {
        res = -2;
        goto err_free_data;
    }

    for (int i = 0; i < mod->num_dynamic; i++) {
        switch (mod->dynamic[i].d_tag) {
            case DT_SONAME:
                mod->soname = mod->dynstr + mod->dynamic[i].d_un.d_ptr;
                break;
            default:
                break;
        }
    }

    if (!head && !tail) {
        head = mod;
        tail = mod;
    } else {
        tail->next = mod;
        tail = mod;
    }

    return 0;

err_free_data:
    for (int i = 0; i < mod->n_data; i++) {
        if (mod->data_base[i])
            munmap((void *)mod->data_base[i], mod->data_size[i]);
    }
err_free_text:
    if (mod->text_base)
        munmap((void *)mod->text_base, mod->text_size);
err_free_so:
    return res;
}

int so_mem_load(so_module *mod, void *buffer, size_t so_size, uintptr_t load_addr) {
    memset(mod, 0, sizeof(so_module));
    return _so_load(mod, 0, buffer, load_addr);
}

int so_file_load(so_module *mod, const char *filename, uintptr_t load_addr) {
    memset(mod, 0, sizeof(so_module));

    FILE *fd = fopen(filename, "rb");
    if (!fd)
        return -1;

    fseek(fd, 0, SEEK_END);
    size_t so_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    void *so_data = malloc(so_size);
    if (!so_data) {
        fclose(fd);
        return -1;
    }

    if (fread(so_data, 1, so_size, fd) != so_size) {
        fclose(fd);
        free(so_data);
        return -1;
    }
    fclose(fd);

    int res = _so_load(mod, 0, so_data, load_addr);
    free(so_data);
    return res;
}

int so_relocate(so_module *mod) {
    uintptr_t val;
    for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
        Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
        Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)];
        uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

        int type = ELF32_R_TYPE(rel->r_info);
        switch (type) {
            case R_ARM_ABS32:
                if (sym->st_shndx != SHN_UNDEF) {
                    val = *ptr + mod->text_base + sym->st_value;
                    memcpy(ptr, &val, sizeof(uintptr_t));
                }
                break;
            case R_ARM_RELATIVE:
                val = *ptr + mod->text_base;
                memcpy(ptr, &val, sizeof(uintptr_t));
                break;
            case R_ARM_GLOB_DAT:
            case R_ARM_JUMP_SLOT:
            {
                if (sym->st_shndx != SHN_UNDEF) {
                    val = mod->text_base + sym->st_value;
                    memcpy(ptr, &val, sizeof(uintptr_t));
                }
                break;
            }
            default:
                fatal_error("Error unknown relocation type %x\n", type);
                break;
        }
    }

    return 0;
}

uintptr_t so_resolve_link(so_module *mod, const char *symbol) {
    for (int i = 0; i < mod->num_dynamic; i++) {
        switch (mod->dynamic[i].d_tag) {
            case DT_NEEDED:
            {
                so_module *curr = head;
                while (curr) {
                    if (curr != mod && strcmp(curr->soname, mod->dynstr + mod->dynamic[i].d_un.d_ptr) == 0) {
                        uintptr_t link = so_symbol(curr, symbol);
                        if (link)
                            return link;
                    }
                    curr = curr->next;
                }

                break;
            }
            default:
                break;
        }
    }

    return 0;
}

void reloc_err(uintptr_t got0)
{
    int found = 0;
    so_module *curr = head;
    while (curr && !found) {
        for (int i = 0; i < curr->n_data; i++)
            if ((got0 >= curr->data_base[i]) && (got0 <= (uintptr_t)(curr->data_base[i] + curr->data_size[i])))
                found = 1;

        if (!found)
            curr = curr->next;
    }

    if (curr) {
        for (int i = 0; i < curr->num_reldyn + curr->num_relplt; i++) {
            Elf32_Rel *rel = i < curr->num_reldyn ? &curr->reldyn[i] : &curr->relplt[i - curr->num_reldyn];
            Elf32_Sym *sym = &curr->dynsym[ELF32_R_SYM(rel->r_info)];
            uintptr_t *ptr = (uintptr_t *)(curr->text_base + rel->r_offset);

            int type = ELF32_R_TYPE(rel->r_info);
            switch (type) {
                case R_ARM_JUMP_SLOT:
                {
                    if (got0 == (uintptr_t)ptr) {
                        fatal_error("Unknown symbol \"%s\" (%p).\n", curr->dynstr + sym->st_name, (void*)got0);
                    }
                    break;
                }
            }
        }
    }

    fatal_error("Unknown symbol \"???\" (%p).\n", (void*)got0);
}

__attribute__((naked)) void plt0_stub()
{
    register uintptr_t got0 asm("r12");
    reloc_err(got0);
}

int so_resolve(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only) {
    uintptr_t val;
    for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
        Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
        Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)];
        uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

        int type = ELF32_R_TYPE(rel->r_info);
        switch (type) {
            case R_ARM_ABS32:
            case R_ARM_GLOB_DAT:
            case R_ARM_JUMP_SLOT:
            {
                if (sym->st_shndx == SHN_UNDEF) {
                    int resolved = 0;
                    if (!default_dynlib_only) {
                        uintptr_t link = so_resolve_link(mod, mod->dynstr + sym->st_name);
                        if (link) {
                            printf("Resolved from dependencies: %s\n", mod->dynstr + sym->st_name);
                            if (type == R_ARM_ABS32) {
                                val = *ptr + link;
                                memcpy(ptr, &val, sizeof(uintptr_t));
                            } else {
                                val = link;
                                memcpy(ptr, &val, sizeof(uintptr_t));
                            }
                            resolved = 1;
                        }
                    }

                    for (int j = 0; j < size_default_dynlib / sizeof(so_default_dynlib); j++) {
                        if (strcmp(mod->dynstr + sym->st_name, default_dynlib[j].symbol) == 0) {
                            val = default_dynlib[j].func;
                            memcpy(ptr, &val, sizeof(uintptr_t));
                            resolved = 1;
                            break;
                        }
                    }

                    if (!resolved) {
                        if (type == R_ARM_JUMP_SLOT) {
                            printf("Unresolved import: %s\n", mod->dynstr + sym->st_name);
                            *ptr = (uintptr_t)&plt0_stub;
                        }
                        else {
                            printf("Unresolved import: %s\n", mod->dynstr + sym->st_name);
                        }
                    }
                }

                break;
            }
            default:
                break;
        }
    }

    return 0;
}

int __ret0() {
    return 0;
}

int so_resolve_with_dummy(so_module *mod, so_default_dynlib *default_dynlib, int size_default_dynlib, int default_dynlib_only) {
    for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
        Elf32_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
        Elf32_Sym *sym = &mod->dynsym[ELF32_R_SYM(rel->r_info)];
        uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

        int type = ELF32_R_TYPE(rel->r_info);
        switch (type) {
            case R_ARM_ABS32:
            case R_ARM_GLOB_DAT:
            case R_ARM_JUMP_SLOT:
            {
                if (sym->st_shndx == SHN_UNDEF) {
                    for (int j = 0; j < size_default_dynlib / sizeof(so_default_dynlib); j++) {
                        if (strcmp(mod->dynstr + sym->st_name, default_dynlib[j].symbol) == 0) {
                            *ptr = (uintptr_t) &__ret0;
                            break;
                        }
                    }
                }

                break;
            }
            default:
                break;
        }
    }

    return 0;
}

void so_initialize(so_module *mod) {
    for (int i = 0; i < mod->num_init_array; i++) {
        if (mod->init_array[i] && (int)mod->init_array[i] != -1)
            mod->init_array[i]();
    }
}

uint32_t so_hash(const uint8_t *name) {
    uint64_t h = 0, g;
    while (*name) {
        h = (h << 4) + *name++;
        if ((g = (h & 0xf0000000)) != 0)
            h ^= g >> 24;
        h &= 0x0fffffff;
    }
    return h;
}

static int so_symbol_index(so_module *mod, const char *symbol)
{
    if (mod->hash) {
        uint32_t hash = so_hash((const uint8_t *)symbol);
        uint32_t nbucket = mod->hash[0];
        uint32_t *bucket = &mod->hash[2];
        uint32_t *chain = &bucket[nbucket];
        for (int i = bucket[hash % nbucket]; i; i = chain[i]) {
            if (mod->dynsym[i].st_shndx == SHN_UNDEF)
                continue;
            if (mod->dynsym[i].st_info != SHN_UNDEF && strcmp(mod->dynstr + mod->dynsym[i].st_name, symbol) == 0)
                return i;
        }
    }

    for (int i = 0; i < mod->num_dynsym; i++) {
        if (mod->dynsym[i].st_shndx == SHN_UNDEF)
            continue;
        if (mod->dynsym[i].st_info != SHN_UNDEF && strcmp(mod->dynstr + mod->dynsym[i].st_name, symbol) == 0)
            return i;
    }

    return -1;
}

uintptr_t so_alloc_arena(so_module *so, uintptr_t range, uintptr_t dst, size_t sz) {
#define inrange(lsr, gtr, range) \
        (((uintptr_t)(range) == (uintptr_t)NULL) || ((uintptr_t)(range) >= ((uintptr_t)(gtr) - (uintptr_t)(lsr))))
#define blkavail(type) (so->type##_size - (so->type##_head - so->type##_base))

    sz = ALIGN_MEM(sz, 4);

    if (sz <= (blkavail(patch)) && inrange(so->patch_base, dst, range)) {
        so->patch_head += sz;
        return (so->patch_head - sz);
    } else if (sz <= (blkavail(cave)) && inrange(dst, so->cave_base, range)) {
        so->cave_head += sz;
        return (so->cave_head - sz);
    }

    return (uintptr_t)NULL;
}

static void trampoline_ldm(so_module *mod, uint32_t *dst) {
    uint32_t trampoline[1];
    uint32_t funct[20] = {0xFAFAFAFA};
    uint32_t *ptr = funct;

    int cur = 0;
    int baseReg = ((*dst) >> 16) & 0xF;
    int bitMask = (*dst) & 0xFFFF;

    uint32_t stored = (uint32_t) NULL;
    for (int i = 0; i < 16; i++) {
        if (bitMask & (1 << i)) {
            if (baseReg == i)
                stored = LDR_OFFS(i, baseReg, cur).raw;
            else
                *ptr++ = LDR_OFFS(i, baseReg, cur).raw;
            cur += 4;
        }
    }

    if (stored) {
        *ptr++ = stored;
    }

    *ptr++ = (uint32_t) 0xe51ff004; // LDR PC, [PC, -0x4] ; jmp to [dst+0x4]
    *ptr++ = (uint32_t) dst+1; // .dword <...>	; [dst+0x4]

    size_t trampoline_sz = ((uintptr_t)ptr - (uintptr_t)&funct[0]);
    uintptr_t patch_addr = so_alloc_arena(mod, B_RANGE, (uintptr_t) B_OFFSET(dst), trampoline_sz);

    if (!patch_addr) {
        fatal_error("Failed to patch LDMIA at 0x%08X, unable to allocate space.\n", (unsigned int)(uintptr_t)dst);
    }

    trampoline[0] = B(dst, patch_addr).raw;

    memcpy((void*)patch_addr, funct, trampoline_sz);
    memcpy(dst, trampoline, sizeof(trampoline));
}

uintptr_t so_symbol(so_module *mod, const char *symbol) {
    int index = so_symbol_index(mod, symbol);
    if (index == -1)
        return (uintptr_t) NULL;

    return mod->text_base + mod->dynsym[index].st_value;
}

void so_symbol_fix_ldmia(so_module *mod, const char *symbol) {
    int idx = so_symbol_index(mod, symbol);
    if (idx == -1)
        return;

    uintptr_t st_addr = mod->text_base + mod->dynsym[idx].st_value;
    for (uintptr_t addr = st_addr; addr < st_addr + mod->dynsym[idx].st_size; addr+=4) {
        uint32_t inst = *(uint32_t*)(addr);

        if (((inst & 0xFFF00000) == 0xE8900000) && (((inst >> 16) & 0xF) < 13) ) {
            printf("Found possibly misaligned LDMIA on 0x%08X, trying to fix it... (instr: 0x%08X, to 0x%08X)\n", (unsigned int)addr, *(uint32_t*)addr, (unsigned int)mod->patch_head);
            trampoline_ldm(mod, (uint32_t *) addr);
        }
    }
}
