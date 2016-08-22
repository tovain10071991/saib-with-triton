
#include "ptraceHelper.h"
#include "DebugHelper.h"
#include "ELFHelper.h"
#include "common.h"

#include "lldb/API/SBDebugger.h"
#include "lldb/API/SBTarget.h"
#include "lldb/API/SBProcess.h"
#include "lldb/API/SBModule.h"
#include "lldb/API/SBModuleSpec.h"
#include "lldb/API/SBBreakpoint.h"
#include "lldb/API/SBThread.h"
#include "lldb/API/SBFrame.h"
#include "lldb/API/SBValueList.h"
#include "lldb/API/SBValue.h"
#include "lldb/API/SBStream.h"
#include "lldb/API/SBEvent.h"
#include "lldb/API/SBBroadcaster.h"
#include "lldb/API/SBListener.h"
#include "lldb/API/SBModuleSpec.h"

#include <link.h>
#include <err.h>
#include <unistd.h>
#include <locale>
#include <cctype>

#include <iostream>
#include <string>
#include <algorithm>
#include <map>
#include <stdio.h>
#include <string.h>

using namespace std;
using namespace lldb;

#define EXECUTABLE_BASE 0x400000
#define CONVERT(base) (base?base:EXECUTABLE_BASE) 

static SBDebugger debugger;
static SBTarget target;

class LLDBInited {
public:
  LLDBInited()
  {
    SBDebugger::Initialize();
    debugger = SBDebugger::Create();
    debugger.SetAsync(false);
  }
};

static LLDBInited inited;

void create_debugger_by_lldb(string binary) {
  target = debugger.CreateTarget(binary.c_str());
  target.SetModuleLoadAddress(target.FindModule(target.GetExecutable()), 0);
}

// 装载模块，DebugHelper.cpp中的create_debugger中调用
void add_modules(map<addr_t, string> link_modules) {
  for(auto modules_iter = link_modules.begin(); modules_iter != link_modules.end(); ++ modules_iter) {
    if(!modules_iter->second.size())
      continue;
    SBFileSpec file_spec(get_absolute(modules_iter->second).c_str());
    SBModuleSpec module_spec;
    module_spec.SetFileSpec(file_spec);
    if(target.FindModule(file_spec).IsValid())
      continue;
    SBModule module = target.AddModule(module_spec);
    target.SetModuleLoadAddress(module, modules_iter->first);
  }
}

static string get_absolute(SBFileSpec file_spec) {
  return get_absolute(string(file_spec.GetFilename()));
}

// 从模块中的虚拟地址获取模块的装载基址
unsigned long get_base(unsigned long addr) {
  SBAddress load_addr = target.ResolveLoadAddress(addr);
  assert(load_addr.IsValid());
  SBModule module = load_addr.GetModule();
  assert(module.IsValid());
  SBFileSpec file_spec = module.GetFileSpec();
  string module_name = string(file_spec.GetDirectory())+"/"+file_spec.GetFilename();
  unsigned long base = get_base(module_name);  
  return base;
}

// 从函数名获取函数的装载地址
unsigned long get_func_addr(string name) {
  SBSymbolContextList symbolContextList = target.FindFunctions(name.c_str());
  assert(symbolContextList.IsValid());
  for(uint32_t i = 0; i < symbolContextList.GetSize(); ++i) {
    SBSymbolContext symbolContext = symbolContextList.GetContextAtIndex(i);
    SBFunction function = symbolContext.GetFunction();
    SBSymbol func_sym = symbolContext.GetSymbol();
    if(function.IsValid()) {
      cerr << "judge func: " << (function.GetName()==NULL?"noname":function.GetName()) << " / " << (function.GetMangledName()==NULL?"noname":function.GetMangledName()) << endl;
      if(!name.compare(function.GetName()) || !name.compare(function.GetMangledName()))
      {
        SBAddress addr = function.GetStartAddress();
        assert(addr.IsValid());
        return addr.GetLoadAddress(target);
      }
    }
    else if(func_sym.IsValid()) {
      cerr << "judge sym: " << (func_sym.GetName()==NULL?"noname":func_sym.GetName()) << " / " << (func_sym.GetMangledName()==NULL?"noname":func_sym.GetMangledName()) << endl;
      SBStream description;
      func_sym.GetDescription(description);
      cout << description.GetData() << endl;
      if(!name.compare(func_sym.GetName()) || !name.compare(func_sym.GetMangledName()))
      {
        SBAddress addr = func_sym.GetStartAddress();
        assert(addr.IsValid());
        if(!string(".text").compare(addr.GetSection().GetName()))
          return addr.GetLoadAddress(target);
      }
    }
  }
  warnx("can't find func: %s", name.c_str());
  return 0;
}

// 从装载地址获取所属模块和文件中偏移
std::pair<std::string, uint64_t> get_file_offset(uint64_t addr) {
  SBAddress load_addr = target.ResolveLoadAddress(addr);
  assert(load_addr.IsValid());
  string file_from_addr(load_addr.GetModule().GetFileSpec().GetDirectory());
  file_from_addr = file_from_addr + "/" + load_addr.GetModule().GetFileSpec().GetFilename();
  uint64_t file_offset = load_addr.GetSection().GetFileOffset() + load_addr.GetOffset();
  return {file_from_addr, file_offset};
}

std::pair<std::string, uint64_t> get_file_offset(string func_name) {
  uint64_t func_addr = get_func_addr(func_name);
  return get_file_offset(func_addr);
}

// 获取函数名的mangled名
string get_mangled_name(string name) {
  SBSymbolContextList symbolContextList = target.FindFunctions(name.c_str());
  assert(symbolContextList.IsValid());
  for(uint32_t i = 0; i < symbolContextList.GetSize(); ++i)
  {
    SBSymbolContext symbolContext = symbolContextList.GetContextAtIndex(i);
    SBFunction function = symbolContext.GetFunction();
    SBSymbol func_sym = symbolContext.GetSymbol();
    if(function.IsValid())
    {
      cerr << "judge func: " << (function.GetName()==NULL?"noname":function.GetName()) << " / " << (function.GetMangledName()==NULL?"noname":function.GetMangledName()) << endl;
      if(!name.compare(function.GetName()) || !name.compare(function.GetMangledName()))
        return function.GetMangledName();
    }
    else if(func_sym.IsValid())
    {
      cerr << "judge sym: " << (func_sym.GetName()==NULL?"noname":func_sym.GetName()) << " / " << (func_sym.GetMangledName()==NULL?"noname":func_sym.GetMangledName()) << endl;
      if(!name.compare(func_sym.GetName()) || !name.compare(func_sym.GetMangledName()))
      {
        SBAddress addr = func_sym.GetStartAddress();
        assert(addr.IsValid());
        if(!string(".text").compare(addr.GetSection().GetName()))
          return func_sym.GetMangledName()?func_sym.GetMangledName():func_sym.GetName();
      }
    }
  }
  errx(-1, "can't find func: %s", name.c_str());
}

SBSection get_section(string obj_name, string sec_name)
{
  SBFileSpec obj_file(obj_name.c_str(), false);
  SBFileSpec obj_file_with_resolved(obj_name.c_str(), true);
  // SBFileSpec exec_file = target.GetExecutable();
  // if(!string(exec_file.GetDirectory()).compare(obj_file.GetDirectory()) && !string(exec_file.GetFilename()).compare(obj_file.GetFilename()))
    // return 0;
  SBModule obj_mdl = target.FindModule(obj_file);
  if(!obj_mdl.IsValid())
  {
    obj_mdl = target.FindModule(obj_file_with_resolved);
    assert(obj_mdl.IsValid());
  }
  SBSection section = obj_mdl.FindSection(sec_name.c_str());
  assert(section.IsValid());
  return section;
}

unsigned long get_section_load_addr(string obj_name, string sec_name)
{
  SBSection section = get_section(obj_name, sec_name);
  return section.GetLoadAddress(target);
}
/*
unsigned long get_load_addr(unsigned long addr, string obj_name, string sec_name) {
  SBSection section = get_section(obj_name, sec_name);
  unsigned long sec_load_base = section.GetLoadAddress(target);
  unsigned long sec_unload_base = section.GetFileAddress();
  return sec_load_base - sec_unload_base + addr;
}
*/
/*
SBSymbol get_func_sym_in_plt(uint64_t addr) {  
  for(unsigned i = 0, num = target.GetNumModules(); i < num; ++i)
  {
    SBModule module = target.GetModuleAtIndex(i);
    SBFileSpec file_spec = module.GetFileSpec();
    if(get_absolute(file_spec).compare(get_absolute(main_obj->getFileName().str())))
      continue;
    SBSection section = module.FindSection(".plt");
    assert(section.IsValid());
    addr_t plt_addr = section.GetFileAddress();
    addr_t plt_size = section.GetByteSize();
    assert(addr>=plt_addr && addr<plt_addr+plt_size);
    SBAddress func_addr = module.ResolveFileAddress(addr);
    SBSymbol func_sym = func_addr.GetSymbol();
    assert(func_sym.GetStartAddress().GetOffset() == func_addr.GetOffset());
    cerr << "found plt func: " << func_sym.GetName() << endl;
    return func_sym;
  }
  errx(-1, "can't find in get_func_name_in_plt");
}
*/

SBSymbol get_func_sym(unsigned long addr) {
  SBAddress load_addr = target.ResolveLoadAddress(addr);
  assert(load_addr.IsValid());
  SBStream description;
  load_addr.GetDescription(description);
  cout << description.GetData() << endl;
  assert(!string(".plt").compare(load_addr.GetSection().GetName()) || !string(".text").compare(load_addr.GetSection().GetName()));
  SBSymbol func_sym = load_addr.GetSymbol();
  assert(func_sym.IsValid());
  return func_sym;
}
/*
string get_func_name_in_plt(uint64_t addr) {
  SBSymbol func_sym = get_func_sym_in_plt(addr);
  return func_sym.GetName();
}
*/
string get_func_name(unsigned long addr) {
  SBSymbol func_sym = get_func_sym(addr);
  string func_name(func_sym.GetName());
  if(!func_name.compare("???"))
    return string();
  else
    return func_name;
}

unsigned long get_func_end_load_addr(string func_name) {
  SBSymbol func_sym = get_func_sym(get_func_addr(func_name));
  return func_sym.GetEndAddress().GetLoadAddress(target);
}

std::pair<std::string, uint64_t> get_func_end_file_offset(string func_name) {
  uint64_t end_addr = get_func_end_load_addr(func_name);
  return get_file_offset(end_addr);
}
/*
unsigned long get_sym_unload_endaddr(unsigned long unload_addr, string obj_name, string sec_name) {
  SBSymbol func_sym = get_func_sym(get_load_addr(unload_addr, obj_name, sec_name));
  return get_unload_addr(func_sym.GetEndAddress().GetLoadAddress(target));
}
*/

bool is_addr_in_plt(uint64_t addr) {
  SBAddress load_addr(addr, target);
  SBSection section = load_addr.GetSection();
  assert(section.IsValid());
  if(!string(section.GetName()).compare(".plt"))
    return true;
  else
    return false;
}