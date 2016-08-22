#include "TritonEngine.h"
#include "TritonState.h"
#include "DummyMemoryManager.h"

#include "triton/api.hpp"
#include "triton/x86Specifications.hpp"
#include "triton/registerOperand.hpp"

#include <iostream>
#include <map>

using namespace triton;
using namespace std;

static map<string, uint32> reg_name_id_set;

TritonEngine::TritonEngine() {
  api.setArchitecture(arch::ARCH_X86_64);
  
  auto parent_regs = api.getParentRegisters();
  for(auto reg = parent_regs.begin(); reg != parent_regs.end(); ++reg)
    reg_name_id_set[(*reg)->getName()] = (*reg)->getId();
}

TritonEngine::~TritonEngine() {
  auto sym_vars = api.getSymbolicVariables();
  cout << "====sym var====" << endl;
  for(auto sym_var = sym_vars.begin(); sym_var != sym_vars.end(); ++sym_var) {
    cout << sym_var->first << ": " << sym_var->second << endl;
    cout << api.getFullAst(api.getAstVariableNode(sym_var->second->getName())) << endl;  
  }
  cout << "====end of sym var====" << endl;
}

ExecutionState* TritonEngine::execute(void* inst_content, size_t size, uint64_t addr) {
  TritonState* state = new TritonState(inst_content, size, addr);
  return state;
}

vector<string> TritonEngine::get_all_parent_regs() {
  auto parent_regs = api.getParentRegisters();
  vector<string> reg_name_set;
  for(auto reg = parent_regs.begin(); reg != parent_regs.end(); ++reg)
    reg_name_set.push_back((*reg)->getName());
  return reg_name_set;
}

void TritonEngine::update_reg(std::string reg_name, void* buf, size_t size) {
  assert(reg_name_id_set.find(reg_name) != reg_name_id_set.end());
  switch(size*8) {
    case 8: {
      uint8 val = *(uint8_t*)buf;
      api.setConcreteRegisterValue(arch::RegisterOperand(reg_name_id_set[reg_name], val));
      break;
    }
    case 16: {
      uint16 val = *(uint16_t*)buf;
      api.setConcreteRegisterValue(arch::RegisterOperand(reg_name_id_set[reg_name], val));
      break;
    }
    case 32: {
      uint32 val = *(uint32_t*)buf;
      api.setConcreteRegisterValue(arch::RegisterOperand(reg_name_id_set[reg_name], val));
      break;
    }
    case 64: {
      uint64 val = *(uint64_t*)buf;
      api.setConcreteRegisterValue(arch::RegisterOperand(reg_name_id_set[reg_name], val));
      break;
    }
    case 128: {
      uint128 val(to_string((*(uint64_t*)buf+1)) + to_string(*(uint64_t*)buf));
      api.setConcreteRegisterValue(arch::RegisterOperand(reg_name_id_set[reg_name], val));
      break;
    }
    case 256: {
      uint256 val(to_string((*(uint64_t*)buf+3)) + to_string((*(uint64_t*)buf+2)) + to_string((*(uint64_t*)buf+1)) + to_string(*(uint64_t*)buf));
      api.setConcreteRegisterValue(arch::RegisterOperand(reg_name_id_set[reg_name], val));
    }
      break;
    case 512: {
      uint512 val(to_string((*(uint64_t*)buf+7)) + to_string((*(uint64_t*)buf+6)) + to_string((*(uint64_t*)buf+5)) + to_string((*(uint64_t*)buf+4)) + to_string((*(uint64_t*)buf+3)) + to_string((*(uint64_t*)buf+2)) + to_string((*(uint64_t*)buf+1)) + to_string(*(uint64_t*)buf));
      api.setConcreteRegisterValue(arch::RegisterOperand(reg_name_id_set[reg_name], val));
      break;
    }
    default:
      assert(0);
  }
}

map<uint64_t, uint64_t> updated_mem_set;

void TritonEngine::update_mem(uint64_t addr, void* buf, size_t size) {
  updated_mem_set.insert({addr, addr+size});
  api.setConcreteMemoryAreaValue(addr, (uint8*)buf, size);
}