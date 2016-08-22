# pragma once

#include <stddef.h>
#include <stdint.h>

extern bool is_indirect_branch(void* content, size_t size);
extern void print_inst(void* content, size_t size, uint64_t address);
extern size_t get_inst_size(void* content, size_t size);