#include "TritonState.h"
#include "DummyMemoryManager.h"

#include "triton/api.hpp"
#include "triton/operandWrapper.hpp"
#include "triton/x86Specifications.hpp"
#include "triton/ast.hpp"

#include <string>
#include <iostream>
#include <err.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

using namespace triton;
using namespace std;

TritonState::TritonState(void* inst_content, size_t size, uint64_t addr) {
  inst.setOpcodes((triton::uint8*)inst_content, size);
  inst.setAddress(addr);
  api.processing(inst);
  
  cout << inst << endl;
  cout << hex;
/*  
  cout << "====================" << endl;
  print_exprs();
  cout << "====================" << endl;
*/  
  if(inst.isMemoryRead()) {
    cout << "load memory:" << endl;
    for(auto iter = inst.getLoadAccess().begin(); iter != inst.getLoadAccess().end(); ++iter) {
      auto seg_reg = iter->first.getConstSegmentRegister();
      if(seg_reg.isValid()) {
        cout << "\tseg reg: " << seg_reg.getName() << endl;
        cout << "\t\tconcrete value from api: " << api.getConcreteRegisterValue(seg_reg).convert_to<uint64_t>() << endl;
      }
      auto base_reg = iter->first.getConstBaseRegister();
      if(base_reg.isValid()) {
        cout << "\tbase reg: " << base_reg.getName() << endl;
        cout << "\t\tconcrete value from api: " << api.getConcreteRegisterValue(base_reg).convert_to<uint64_t>() << endl;
      }
      auto idx_reg = iter->first.getConstIndexRegister();
      if(idx_reg.isValid()) {
        cout << "\tindex reg: " << idx_reg.getName() << endl;
        cout << "\t\tconcrete value from api: " << api.getConcreteRegisterValue(idx_reg).convert_to<uint64_t>() << endl;
      }
      auto scale = iter->first.getConstScale();
      cout << "\tsacle: " << scale.getValue() << endl;
      auto displacement = iter->first.getConstDisplacement();
      cout << "\tdisplacement: " << displacement.getValue() << endl;
      cout << "\taddress: " << iter->first.getAddress() << endl;
      cout << "\tsize: " << iter->first.getSize() << endl;
      
      uint64_t mem_addr = iter->first.getAddress();
      uint64_t mem_end = iter->first.getAddress() + iter->first.getSize();
      for(; mem_addr < mem_end; ++mem_addr) {
        cout << "\t" << mem_addr << ": " << (unsigned)api.getConcreteMemoryValue(mem_addr) << endl;

        auto mem_expr_set = api.getSymbolicMemory();
        if(mem_expr_set.find(mem_addr) != mem_expr_set.end()) {
          cout << "\texpression:" << endl;
          cout << "\t\t" << mem_expr_set[mem_addr] << endl;
        
          if(mem_expr_set[mem_addr]->getAst()->isSymbolized())
            cout << "\t\t\tsymbolized" << endl;
        }
      }
    }
  }

  if(!inst.getReadRegisters().empty()) {
    cout << "read register:" << endl;
    for(auto iter = inst.getReadRegisters().begin(); iter != inst.getReadRegisters().end(); ++iter) {
      assert(iter->first.isValid());
      cout << "\t" << iter->first.getName() << "(" << iter->first.getSize() << ")" << ": " << api.getConcreteRegisterValue(iter->first).convert_to<uint64_t>() << endl;

      auto reg_expr_set = api.getSymbolicRegisters();      
      if(reg_expr_set.find(iter->first.getParent()) != reg_expr_set.end()) {
        cout << "\texpression:" << endl;
        cout << "\t\t" << reg_expr_set[iter->first.getParent()] << endl;
      
        if(reg_expr_set[iter->first.getParent()]->getAst()->isSymbolized())
          cout << "\t\t\tsymbolized" << endl;
      }
    }
  }

  if(inst.isMemoryWrite()) {
    cout << "stroe memory:" << endl;
    for(auto iter = inst.getStoreAccess().begin(); iter != inst.getStoreAccess().end(); ++iter) {
      auto seg_reg = iter->first.getConstSegmentRegister();
      if(seg_reg.isValid()) {
        cout << "\tseg reg: " << seg_reg.getName() << endl;
        cout << "\t\tconcrete value from api: " << api.getConcreteRegisterValue(seg_reg).convert_to<uint64_t>() << endl;
      }
      auto base_reg = iter->first.getConstBaseRegister();
      if(base_reg.isValid()) {
        cout << "\tbase reg: " << base_reg.getName() << endl;
        cout << "\t\tconcrete value from api: " << api.getConcreteRegisterValue(base_reg).convert_to<uint64_t>() << endl;
      }
      auto idx_reg = iter->first.getConstIndexRegister();
      if(idx_reg.isValid()) {
        cout << "\tindex reg: " << idx_reg.getName() << endl;
        cout << "\t\tconcrete value from api: " << api.getConcreteRegisterValue(idx_reg).convert_to<uint64_t>() << endl;
      }
      auto scale = iter->first.getConstScale();
      cout << "\tsacle: " << scale.getValue() << endl;
      auto displacement = iter->first.getConstDisplacement();
      cout << "\tdisplacement: " << displacement.getValue() << endl;
      cout << "\taddress: " << iter->first.getAddress() << endl;
      cout << "\tsize: " << iter->first.getSize() << endl;
      
      uint64_t mem_addr = iter->first.getAddress();
      uint64_t mem_end = iter->first.getAddress() + iter->first.getSize();
      for(; mem_addr < mem_end; ++mem_addr) {
        cout << "\t" << mem_addr << ": " << (unsigned)api.getConcreteMemoryValue(mem_addr) << endl;
        cout << "\texpression:" << endl;
        auto mem_expr_set = api.getSymbolicMemory();
        assert(mem_expr_set.find(mem_addr) != mem_expr_set.end());
        cout << "\t\t" << mem_expr_set[mem_addr] << endl;
        
        if(mem_expr_set[mem_addr]->getAst()->isSymbolized())
          cout << "\t\t\tsymbolized" << endl;
      }
    }
  }
  
  if(!inst.getWrittenRegisters().empty()) {
    cout << "write register:" << endl;
    for(auto iter = inst.getWrittenRegisters().begin(); iter != inst.getWrittenRegisters().end(); ++iter) {
      assert(iter->first.isValid());
      cout << "\t" << iter->first.getName() << "(" << iter->first.getSize() << ")" << ": " << api.getConcreteRegisterValue(iter->first).convert_to<uint64_t>() << endl;
      
      cout << "\texpression:" << endl;
      auto reg_expr_set = api.getSymbolicRegisters();
      assert(reg_expr_set.find(iter->first.getParent()) != reg_expr_set.end());
      cout << "\t\t" << reg_expr_set[iter->first.getParent()] << endl;
      
      if(reg_expr_set[iter->first.getParent()]->getAst()->isSymbolized())
        cout << "\t\t\tsymbolized" << endl;
      
    }
  }
  
  if(inst.isMemoryRead() || inst.isMemoryWrite()) {
    check_mem_access();
  }
  
  if(is_syscall())
    handle_syscall();
    
  cout << "====after handling====" << endl;
  auto sym_var_set = api.getSymbolicVariables();
  for(auto iter = sym_var_set.begin(); iter != sym_var_set.end(); ++iter) {
    cout << iter->first << ": " << iter->second << endl;
  }
}

bool TritonState::is_control_flow() {
  return inst.isControlFlow();
}


uint64_t TritonState::get_target_addr() {
  uint64_t rip_val =  api.getConcreteRegisterValue(arch::x86::x86_reg_rip).convert_to<uint64_t>();
  return rip_val;
/*  if(inst.isBranch()) {
    assert(0);
  } else if(inst.getType == arch::ID_INS_RET) {
    
  } else {
    arch::OperandWrapper target_opr = inst.operands[0];
    assert(target_opr.getBitSize() == 64);
    // switch(target_opr.getType()) {
      // case arch::OP_IMM: {
        // return 
      // }
    // }
    return target_opr.getConcreteValue().convert_to<uint64_t>();
  }*/
}

string TritonState::disassemble() {
  return inst.getDisassembly();
}

void TritonState::print_exprs() {
  cout << "====sym expr====" << endl;
  for(auto expr = inst.symbolicExpressions.begin(); expr != inst.symbolicExpressions.end(); ++expr) {
    cout << *expr << endl;
    if((*expr)->getAst()->isSymbolized())
      cout << "\tsymbolized" << endl;
  }
  cout << "====end of sym expr====" << endl;
  cout << "====sym reg====" << endl;
  auto sym_regs = api.getSymbolicRegisters();
  for(auto sym_reg = sym_regs.begin(); sym_reg != sym_regs.end(); ++sym_reg) {
    cout << sym_reg->first << endl << "\t" << sym_reg->second << endl;
    cout << sym_reg->first << " = 0x" << hex << api.getConcreteRegisterValue(sym_reg->first) << endl;
    if(sym_reg->second->getAst()->isSymbolized())
      cout << "\tsymbolized" << endl;
  }
  cout << "====end of sym reg====" << endl;
  
    auto sym_mems = api.getSymbolicMemory();
  cout << "====sym mem====" << endl;
  for(auto sym_mem = sym_mems.begin(); sym_mem != sym_mems.end(); ++sym_mem) {
    cout << hex << "0x" << sym_mem->first << endl << "\t" << sym_mem->second << endl;
    cout << sym_mem->first << " = 0x" << hex << (unsigned)api.getConcreteMemoryValue(sym_mem->first) << endl;
    if(sym_mem->second->getAst()->isSymbolized())
      cout << "\tsymbolized" << endl;
  }
  cout << "====end of sym mem====" << endl;
}

uint64_t TritonState::get_next_addr() {
  auto reg_expr_set = api.getSymbolicRegisters();
  assert(reg_expr_set.find(arch::x86::x86_reg_rip) != reg_expr_set.end());
  auto rip_expr = reg_expr_set[arch::x86::x86_reg_rip];
  if(!rip_expr->getAst()->isSymbolized()) {
    uint64_t rip_val =  api.getConcreteRegisterValue(arch::x86::x86_reg_rip).convert_to<uint64_t>();
    return rip_val;
  }
  auto id_expr_set = api.getSymbolicExpressions();
  usize id = 0;
  auto id_expr = id_expr_set.begin();
  for(; id_expr != id_expr_set.end(); ++id_expr) {
    if(id_expr->second == rip_expr) {
      id = id_expr->first;
      break;
    }
  }
  assert(id_expr != id_expr_set.end());
  if(inst.isBranch()) {
    cout << "fork here" << endl;
    cerr << "fork here" << endl;
    pid_t pid = fork();
    if(pid < 0) {
      err(errno, "fork failed");
    }
    if(pid) {
      wait(NULL);
      cout << "in parent process: " << getpid() << endl;
      cerr << "in parent process: " << getpid() << endl;
      uint64 addr = inst.getNextAddress();
      ast::BvNode* addr_node = new ast::BvNode(addr, 64);
      ast::EqualNode* equal_node = new ast::EqualNode(api.getAstFromId(id), addr_node);
      auto constraint = api.newSymbolicExpression(equal_node, "cond not taken");
      api.addPathConstraint(inst, constraint);
      return addr;
    }
    else {
      cout << "in child process: " << getpid() << endl;
      cerr << "in child process: " << getpid() << endl;
      uint64 addr = inst.operands[0].getImmediate().getValue();
      ast::BvNode* addr_node = new ast::BvNode(addr, 64);
      ast::EqualNode* equal_node = new ast::EqualNode(api.getAstFromId(id), addr_node);
      auto constraint = api.newSymbolicExpression(equal_node, "cond taken");
      api.addPathConstraint(inst, constraint);
      return addr;
    }
  }
}

bool TritonState::is_syscall() {
  return inst.getType() == arch::x86::ID_INS_SYSCALL;
}

void TritonState::handle_syscall() {
  uint32_t eax_val =  api.getConcreteRegisterValue(arch::x86::x86_reg_eax).convert_to<uint32_t>();
  switch(eax_val) {
    case SYS_getpid: {
      api.convertRegisterToSymbolicVariable(arch::x86::x86_reg_rax, "return from getpid()");
      break;
    }
    case SYS_mmap: {
      uint64_t rsi_val =  api.getConcreteRegisterValue(arch::x86::x86_reg_rsi).convert_to<uint64_t>();
      uint64_t mem_size = rsi_val;
/*      if(rsi_val % 64)
        mem_size = ((rsi_val + 64) / 64) * 64;
      assert(mem_size >= rsi_val);
*/      uint64_t dummy_mem = mem_manager.malloc(mem_size);
      arch::x86::x86_reg_rax.setConcreteValue(dummy_mem);
      api.setConcreteRegisterValue(arch::x86::x86_reg_rax);
      api.convertRegisterToSymbolicVariable(arch::x86::x86_reg_rax, "return from mmap()");
      
/*      for(uint64_t i = 0; i < mem_size; i+=64) {
        arch::MemoryOperand mem_opr(dummy_mem + i, 64);
        api.convertMemoryToSymbolicVariable(mem_opr, "sym mem");
      }
*/      
      break;
    }
    case SYS_open: {
      api.convertRegisterToSymbolicVariable(arch::x86::x86_reg_rax, "return from openat()");
      break;
    }
    case SYS_lseek: {
      api.convertRegisterToSymbolicVariable(arch::x86::x86_reg_rax, "return from lseek()");
      break;
    }
    case SYS_fstat: {
      uint64_t rsi_val =  api.getConcreteRegisterValue(arch::x86::x86_reg_rsi).convert_to<uint64_t>();
      uint64_t mem_size = sizeof(struct stat);
      uint64_t num64 = (mem_size/64)*64;
      uint64_t i = 0;
      for(; i < num64; i+=64) {
        cerr << hex << "set sym mem: " << rsi_val + i << endl;
        arch::MemoryOperand mem_opr(rsi_val + i, 64);
        api.convertMemoryToSymbolicVariable(mem_opr, "sym mem from fstat()");
      }
      for(; i < mem_size; ++i) {
        cerr << hex << "set sym mem: " << rsi_val + i << endl;
        arch::MemoryOperand mem_opr(rsi_val + i, 1);
        api.convertMemoryToSymbolicVariable(mem_opr, "sym mem from fstat()");
      }
      api.setConcreteRegisterValue(arch::x86::x86_reg_rax);
      api.convertRegisterToSymbolicVariable(arch::x86::x86_reg_rax, "return from fstat()");
      break;
    }
    default: {
      errx(-1, "unknown syscall num: %u", eax_val);
      break;
    }
  }
}

static set<uint64_t> updated_mem_set; //每1字节为一个单位

void TritonState::check_mem_access() {
  // assert(!(inst.isMemoryRead() && inst.isMemoryWrite()));
  auto mem_access = inst.getLoadAccess();
  for(auto mem_access_iter = mem_access.begin(); mem_access_iter != mem_access.end(); ++mem_access_iter) {
    assert(mem_access_iter->first.getAddress() + mem_access_iter->first.getSize() > mem_access_iter->first.getAddress());
    cout << "access(load) mem: " << hex << mem_access_iter->first.getAddress() << "~" << mem_access_iter->first.getAddress() + mem_access_iter->first.getSize() << endl;
    
    assert(!(mem_access_iter->first.getAddress()<mem_manager.low_mem && mem_access_iter->first.getAddress() + mem_access_iter->first.getSize() > mem_manager.low_mem));
    assert(mem_access_iter->first.getAddress() + mem_access_iter->first.getSize() < mem_manager.high_mem);
    // assert(!(mem_access_iter->first.getAddress()<mem_manager.low_tls && mem_access_iter->first.getSize() > mem_manager.low_tls));
    // assert(!(mem_access_iter->first.getAddress()<mem_manager.high_tls && mem_access_iter->first.getSize() > mem_manager.high_tls));
    
    if(mem_access_iter->first.getAddress() >= mem_manager.low_mem) {
      uint64_t mem_addr = mem_access_iter->first.getAddress();
      uint64_t mem_end = mem_access_iter->first.getAddress() + mem_access_iter->first.getSize();
      for(uint64_t i = mem_addr; i < mem_end; i+=64) {
        if(updated_mem_set.find(i) == updated_mem_set.end()) {
          arch::MemoryOperand mem_opr(i, 1);
          api.convertMemoryToSymbolicVariable(mem_opr, "sym mem");
          updated_mem_set.insert(i);
        }
      }
    }
  }
  
  mem_access = inst.getStoreAccess();
  for(auto mem_access_iter = mem_access.begin(); mem_access_iter != mem_access.end(); ++mem_access_iter) {
    cout << "access(write) mem: " << hex << mem_access_iter->first.getAddress() << "~" << mem_access_iter->first.getAddress() + mem_access_iter->first.getSize() << endl;
    
    assert(!(mem_access_iter->first.getAddress()<mem_manager.low_mem && mem_access_iter->first.getAddress() + mem_access_iter->first.getSize() > mem_manager.low_mem));
    assert(!(mem_access_iter->first.getAddress()<mem_manager.high_mem && mem_access_iter->first.getAddress() + mem_access_iter->first.getSize() > mem_manager.high_mem));
    
    if(mem_access_iter->first.getAddress() >= mem_manager.low_mem) {
      uint64_t mem_addr = mem_access_iter->first.getAddress();
      uint64_t mem_end = mem_access_iter->first.getAddress() + mem_access_iter->first.getSize();
      for(uint64_t i = mem_addr; i < mem_end; i+=64) {
        updated_mem_set.insert(i);
      }
    }
  }
}