# pragma once

#include <stdint.h>

extern std::map<uint64_t, std::set<uint64_t> > indirect_call_set;

void output_indirect(uint64_t src_addr, uint64_t des_addr);