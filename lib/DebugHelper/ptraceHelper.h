# pragma once

#include <string>

#include <unistd.h>

pid_t create_debugger_by_ptrace(std::string binary, uint64_t addr);
size_t get_mem(uint64_t address, void* buf, size_t size);
size_t get_reg(std::string reg_name, void* buf, size_t size);
pid_t get_pid();