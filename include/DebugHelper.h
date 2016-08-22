# pragma once

#include <string>

pid_t create_debugger(std::string binary, uint64_t addr);
uint64_t get_base(std::string module_name);
std::pair<std::string, uint64_t> get_file_offset(std::string func_name);  // 从装载地址获取所属模块和文件中偏移
std::pair<std::string, uint64_t> get_file_offset(unsigned long addr);  // 从装载地址获取所属模块和文件中偏移
std::pair<std::string, uint64_t> get_func_end_file_offset(std::string func_name);  // 从函数名获取函数的所属模块和文件中终止偏移

size_t get_mem(uint64_t address, void* buf, size_t size);
size_t get_reg(std::string reg_name, void* buf, size_t size);

unsigned long get_func_addr(std::string name);           // 从函数名获取函数的装载地址
bool is_addr_in_plt(uint64_t addr); // 判断装载地址是否在.plt
std::string get_func_name(uint64_t addr);    // 从.plt中的虚拟地址获取目标函数名