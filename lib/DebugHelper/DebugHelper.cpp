#include "ptraceHelper.h"
#include "LLDBHelper.h"
#include "ELFHelper.h"
#include "common.h"

#include <string>
#include <map>
#include <iostream>

#include <unistd.h>
#include <link.h>
#include <err.h>
#include <assert.h>

using namespace std;

static string main_binary;

map<addr_t, string> get_link_modules(string binary)
{
  map<addr_t, string> link_modules;
  return link_modules;
  //从主模块获取链接信息
  struct link_map* lm_ptr;
  get_mem(get_got_plt_addr(binary)+8, &lm_ptr, 8);
  while(lm_ptr!=NULL)
  {
    struct link_map lm;
    get_mem((uint64_t)lm_ptr, &lm, sizeof(struct link_map));
    char name[200];
    get_mem((addr_t)lm.l_name, name, 200);
    assert(string(name).size()<200);
    link_modules[lm.l_addr] = name;
    lm_ptr=lm.l_next;
  }
  return link_modules;
}

pid_t create_debugger(string binary, uint64_t addr) {
  main_binary = binary;
  pid_t pid = create_debugger_by_ptrace(binary, addr);
  map<addr_t, string> link_modules = get_link_modules(binary);
  add_modules(link_modules);
  return pid;
}

unsigned long get_base(string module_name)
{
  if(!get_absolute(module_name).compare(get_absolute(main_binary)))
    return 0;
  //从主模块获取链接信息
  struct link_map* lm_ptr;
  get_mem(get_got_plt_addr(main_binary)+8, &lm_ptr, 8);
  while(lm_ptr!=NULL)
  {
    struct link_map lm;
    get_mem((uint64_t)lm_ptr, &lm, sizeof(struct link_map));
    char name[200] = "";
    get_mem((addr_t)lm.l_name, name, 200);
    assert(string(name).size()<200);
    cerr << "in get_base: " << name << endl;
    if(string(name).size() && !get_absolute(module_name).compare(get_absolute(name)))
    {
      return lm.l_addr;
    }
    lm_ptr=lm.l_next;
  }
  errx(-1, "can't find module in get_base(name): %s", module_name.c_str());
}