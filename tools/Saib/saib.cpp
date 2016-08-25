#include "ELFHelper.h"
#include "DebugHelper.h"
#include "SymExecutor.h"
#include "DisHelper.h"
#include "MapsHelper.h"
#include "common.h"

#include <string>
#include <iostream>
#include <set>
#include <map>
#include <vector>
#include <fstream>

#include <stdlib.h>
#include <err.h>
#include <unistd.h>

using namespace std;

static set<uint64_t> updated_mem_set;

ofstream fout;
string control_flow;

int main(int argc, char** argv) {
  assert(argc >= 4);
  
  fout.open(string("out.")+to_string(getpid()));
  
  string executable = argv[1];
  uint64_t start_addr = stoull(argv[2], 0, 16);
  uint64_t end_addr = stoull(argv[3], 0, 16);
  
  if(argc == 5)
    control_flow = argv[4];
  
  pid_t pid = create_debugger(executable, start_addr);
  SymExecutor* sym_executor = SymExecutor::create(SymExecutor::impl::TRITON);
    
  auto file_off_piar = get_file_offset(start_addr);
  string file_name = file_off_piar.first;
  uint64_t off = file_off_piar.second;
  
  auto file_endOff_pair = get_file_offset(end_addr);// get_func_end_file_offset("main");
  string end_file_name = file_endOff_pair.first;
  uint64_t end_off = file_endOff_pair.second;
  
  void* content = malloc(20);
  
  // 更新寄存器
  vector<string> reg_name_set = sym_executor->get_all_parent_regs();
  void* reg_buf = malloc(80);
  size_t size;
  for(auto reg_name = reg_name_set.begin(); reg_name != reg_name_set.end(); ++reg_name) {
    if(!reg_name->compare("fs"))
      size = get_reg("fs_base", reg_buf, 80);
    else if(!reg_name->compare("gs"))
      size = get_reg("gs_base", reg_buf, 80);
    else
      size = get_reg(*reg_name, reg_buf, 80);
    if(size == 0) {
      warnx("can't get reg in main: %s", reg_name->c_str());
    }
    if(size != 0) {
      sym_executor->update_reg(*reg_name, reg_buf, size);
    }
  }
  free(reg_buf);

  // 更新内存
#define MAX_SIZE 0xfffffff
  void* mem_buf = malloc(MAX_SIZE);
  assert(mem_buf);
  std::vector<map_t> data_segments = get_data_segments(pid);
  for(auto iter = data_segments.begin(); iter != data_segments.end(); ++iter) {
    fout << hex << iter->filename << ": " << iter->addr << " ~ " << iter->endaddr << endl;
    size_t size = iter->endaddr - iter->addr;
    assert(size <= MAX_SIZE);
    get_mem(iter->addr, mem_buf, size);
    sym_executor->update_mem(iter->addr, mem_buf, size);
  }
  free(mem_buf);

  uint64_t addr = start_addr;// get_func_addr("main");
  while(1) {
    assert(get_content(file_name, off, content, 20) == 20);
  
    size_t inst_size = get_inst_size(content, 20);

    ExecutionState* state = sym_executor->execute(content, inst_size, addr);

    if(addr == end_addr)// if(!file_name.compare(end_file_name) && off + inst_size == end_off)
      break;
    
    addr = state->get_next_addr();
    
    // if(is_addr_in_plt(addr))
      // addr = get_func_addr(get_func_name(addr));
    
    file_off_piar = get_file_offset(addr);
    file_name = file_off_piar.first;
    off = file_off_piar.second;
    
    delete state;
  }
  
  delete sym_executor;
  fout << "done! control flow: " << control_flow << endl;
  
  ofstream control_output("control_output");
  control_output << control_flow << endl;
}