# pragma once

#include "SymExecutor.h"

#include "triton/instruction.hpp"

#include <string>

class TritonState : public ExecutionState {
public:
  TritonState(void* inst_content, size_t size, uint64_t addr);
  virtual bool is_control_flow();
  virtual bool is_syscall();
  virtual uint64_t get_target_addr();
  virtual uint64_t get_next_addr();
  virtual std::string disassemble();
  virtual void print_exprs();
private:
  triton::arch::Instruction inst;
  void handle_syscall();
  void check_mem_access();
};