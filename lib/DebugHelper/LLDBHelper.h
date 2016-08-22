# pragma once

#include "common.h"

#include <string>
#include <map>

void create_debugger_by_lldb(std::string binary);   // 在create_debugger_by_ptrace中调用
unsigned long get_base(std::string module_name);    // 获取模块的装载基址
unsigned long get_base(unsigned long addr);         // 从模块中的虚拟地址获取模块的装载基址
// std::string get_func_name_in_plt(uint64_t addr);    // 从.plt中的虚拟地址获取目标函数名
unsigned long get_func_addr(std::string name);           // 从函数名获取函数的装载地址
std::string get_func_name(unsigned long addr);      // 从函数中的虚拟地址获取函数名
std::pair<std::string, uint64_t> get_file_offset(unsigned long addr);  // 从装载地址获取所属模块和文件中偏移
std::pair<std::string, uint64_t> get_file_offset(std::string func_name);   // 从函数名获取函数的所属模块和文件中偏移
// unsigned long get_load_addr(unsigned long addr, std::string obj_name, std::string sec_name);  // 从文件中偏移获取装载地址
std::string get_mangled_name(std::string name);     // 获取函数名的mangled名
unsigned long get_section_load_addr(std::string obj_name, std::string sec_name);  // 获取节的装载地址
unsigned long get_sym_end_file_offset(unsigned long unload_addr, std::string obj_name, std::string sec_name);  // 获取符号的文件中偏移
unsigned long get_func_end_load_addr(std::string func_name);  // 获取符号的终止装载地址
std::pair<std::string, uint64_t> get_func_end_file_offset(std::string func_name);  // 从函数名获取函数的所属模块和文件中终止偏移

void add_modules(std::map<addr_t, std::string> link_modules); // 装载模块，DebugHelper.cpp中的create_debugger中调用


bool is_addr_in_plt(uint64_t addr); // 判断装载地址是否在.plt