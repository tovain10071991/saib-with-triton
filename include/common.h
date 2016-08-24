# pragma once

#include <string>
#include <fstream>

typedef unsigned long addr_t;

std::string get_absolute(std::string name);
std::string omit_case(std::string name);

extern std::ofstream fout;
extern std::string control_flow;