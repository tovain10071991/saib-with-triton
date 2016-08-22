# pragma once

#include <string>

extern uint64_t get_got_plt_addr(std::string obj_name);

// extern size_t get_text_sec_start_off(std::string binary);
// extern size_t get_text_sec_end_off(std::string binary);
// extern size_t get_text_sec_start_addr(std::string binary);
extern size_t get_content(std::string binary, size_t offset, void* buf, size_t size);
extern uint64_t get_entry(std::string binary);