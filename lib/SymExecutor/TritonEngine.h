# pragma once

#include "SymExecutor.h"

class TritonEngine : public SymExecutor {
public:
  TritonEngine();
  virtual ~TritonEngine();
  virtual ExecutionState* execute(void* inst_content, size_t size, uint64_t addr);
  virtual std::vector<std::string> get_all_parent_regs();
  virtual void update_reg(std::string reg_name, void* buf, size_t size);
  virtual void update_mem(uint64_t addr, void* buf, size_t size);
};