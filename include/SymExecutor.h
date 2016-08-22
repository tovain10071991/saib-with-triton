# pragma once

#include <string>
#include <vector>
#include <assert.h>
#include <stdint.h>

class ExecutionState {
public:
  virtual bool is_control_flow() {assert(0 && "unimplemented");}
  virtual bool is_indirect_branch() {assert(0 && "unimplemented");}
  virtual bool is_syscall() {assert(0 && "unimplemented");}
  virtual bool is_cond_branch() {assert(0 && "unimplemented");}
  virtual uint64_t get_next_addr() {assert(0 && "unimplemented");}
  virtual uint64_t get_target_addr() {assert(0 && "unimplemented");}
  virtual std::string disassemble() {assert(0 && "unimplemented");}
  virtual void print_exprs() {assert(0 && "unimplemented");}
};

class SymExecutor {
public:
  virtual ~SymExecutor() {}
  virtual ExecutionState* execute(void* inst_content, size_t size, uint64_t addr) {assert(0 && "unimplemented");}
  
  virtual std::vector<std::string> get_all_parent_regs() {assert(0 && "unimplemented");}
  virtual void update_mem(uint64_t addr, void* buf, size_t size) {assert(0 && "unimplemented");}
  virtual void update_reg(std::string reg_name, void* buf, size_t size) {assert(0 && "unimplemented");}
  
  enum class impl {
    TRITON
  };
  
  static SymExecutor* create(impl impl_kind);
};