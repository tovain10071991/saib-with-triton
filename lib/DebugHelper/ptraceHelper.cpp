#include "common.h"
#include "LLDBHelper.h"
#include "ELFHelper.h"

#include <string>
#include <map>
#include <vector>

#include <link.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <err.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>

using namespace std;

static pid_t pid;

long ptrace_assert(enum __ptrace_request req, int pid, void* addr, void* data, string msg="") {
	errno = 0;
	long ret;
	if((ret = ptrace(req, pid, addr, data))==-1&&errno!=0)
		err(errno, "%s", msg.c_str());
	return ret;
}

bool wait_assert(string msg="") {
	int status;
	if(waitpid(pid, &status, 0)==-1)
		err(errno, "fail in wait(%s)", msg.c_str());
	if(WIFEXITED(status))
	{
		warnx("normally exit(%s): %d", msg.c_str(), WEXITSTATUS(status));
		return false;
	}
	if(WIFSTOPPED(status)&&WSTOPSIG(status)!=SIGTRAP)
		errx(-1, "don't handler this STOPSIG(%s): %d\n", msg.c_str(), WSTOPSIG(status));
	if(WIFSIGNALED(status))
		errx(-1, "don't handler this TERMSIG(%s): %d\n", msg.c_str(), WTERMSIG(status));
	return true;
}

pid_t create_child(string binary) {
  pid = fork();
  if(pid==0)
  {
    ptrace_assert(PTRACE_TRACEME, 0, 0, 0, "PTRACE_TRACEME in create_child");
    if(execl(binary.c_str(), binary.c_str(), NULL)==-1)
      err(errno, "execv in create_child");
  }
  else if(pid<0)
    err(errno, "fork in create_child");
  wait_assert();
  return pid;
}

addr_t get_start_addr(string binary) {
  addr_t start_addr = get_func_addr("main");
  if(!start_addr)
    start_addr = get_entry(binary);
  return start_addr;
}

size_t get_reg(std::string reg_name, void* buf, size_t buf_size) {
  struct user_regs_struct regs;
  ptrace_assert(PTRACE_GETREGS, pid, 0, &regs);
  map<string, long> name_reg_map = {
    {"r15", regs.r15},
    {"r14", regs.r14},
    {"r13", regs.r13},
    {"r12", regs.r12},
    {"rbp", regs.rbp},
    {"rbx", regs.rbx},
    {"r11", regs.r11},
    {"r10", regs.r10},
    {"r9", regs.r9},
    {"r8", regs.r8},
    {"rax", regs.rax},
    {"rcx", regs.rcx},
    {"rdx", regs.rdx},
    {"rsi", regs.rsi},
    {"rdi", regs.rdi},
    {"orig_rax", regs.orig_rax},
    {"rip", regs.rip},
    {"cs", regs.cs},
    {"eflags", regs.eflags},
    {"rsp", regs.rsp},
    {"ss", regs.ss},
    {"fs_base", regs.fs_base},
    {"gs_base", regs.gs_base},
    {"ds", regs.ds},
    {"es", regs.es},
    {"fs", regs.fs},
    {"gs", regs.gs},
  };
  map<string, long> name_flag_map = {
    {"cf", 1 & (regs.eflags >> 0)},
    {"pf", 1 & (regs.eflags >> 2)},
    {"af", 1 & (regs.eflags >> 4)},
    {"zf", 1 & (regs.eflags >> 6)},
    {"sf", 1 & (regs.eflags >> 7)},
    {"tf", 1 & (regs.eflags >> 8)},
    {"if", 1 & (regs.eflags >> 9)},
    {"df", 1 & (regs.eflags >> 10)},
    {"of", 1 & (regs.eflags >> 11)},
    {"nt", 1 & (regs.eflags >> 14)},
    {"rf", 1 & (regs.eflags >> 16)},
  };
  vector<long> name_xmm_space_vector = {
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[0]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[2]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[4]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[6]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[8]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[10]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[12]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[14]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[16]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[18]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[20]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[22]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[24]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[26]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[28]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[30]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[32]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[34]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[36]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[38]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[40]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[42]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[44]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[46]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[48]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[50]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[52]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[54]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[56]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[58]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[60]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.xmm_space[62]), 0),
  };
  vector<long> name_st_space_vector = {
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[0]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[2]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[4]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[6]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[8]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[10]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[12]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[14]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[16]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[18]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[20]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[22]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[24]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[26]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[28]), 0),
    ptrace_assert(PTRACE_PEEKUSER, pid, (void*)offsetof(struct user, i387.st_space[30]), 0),
  };

  if(name_reg_map.find(omit_case(reg_name))!=name_reg_map.end())
  {
    *(long*)buf = name_reg_map[omit_case(reg_name)];
    size_t val_size = sizeof(long);
    warnx("get reg successfully: %s = 0x%lx", reg_name.c_str(), *(long*)buf);
    return val_size;
  }
  else if(name_flag_map.find(omit_case(reg_name))!=name_flag_map.end())
  {
    *(long*)buf = name_flag_map[omit_case(reg_name)];
    size_t val_size = 1;
    warnx("get flag successfully: %s = 0x%lx", reg_name.c_str(), *(long*)buf);
    return val_size;
  }
  else if(!omit_case(reg_name).substr(0, 3).compare("xmm"))
  {
    int idx = stoi(reg_name.substr(3));
    if(idx>=16)
    {
      warnx("can't find reg: %s", reg_name.c_str());
      return 0;
    }
    *((long*)buf + 0) = name_xmm_space_vector[idx*2];
    warnx("get xmm_space successfully: %s:%d = 0x%lx", reg_name.c_str(), 0, *((long*)buf + 0));
    *((long*)buf + 1) = name_xmm_space_vector[idx*2+1];
    warnx("get xmm_space successfully: %s:%d = 0x%lx", reg_name.c_str(), 1, *((long*)buf + 1));
    size_t val_size = 64;
    return val_size;
  }
  else if(!omit_case(reg_name).substr(0, 2).compare("st"))
  {
    int idx = stoi(reg_name.substr(2));
    assert(idx<8);
    *((long*)buf + 0) = name_st_space_vector[idx*2];
    warnx("get st_space successfully: %s:%d = 0x%lx", reg_name.c_str(), 0, *((long*)buf + 0));
    *((long*)buf + 1) = name_st_space_vector[idx*2+1];
    warnx("get st_space successfully: %s:%d = 0x%lx", reg_name.c_str(), 1, *((long*)buf + 1));
    size_t val_size = 10;
    return val_size;
  }
  else
  {
    warnx("can't find reg: %s", reg_name.c_str());
    return 0;
  }
}

size_t get_mem(addr_t addr, void* buf, size_t size) {
  size_t ts = size/sizeof(long);
  if(size%sizeof(long))
    ++ts;
  long* tmp = (long*)malloc(ts*sizeof(long));
  if(tmp==NULL)
    errx(-1, "malloc: fail to allocate tmp in readata()\n");
  for(size_t i=0;i<ts;i++)
    *(tmp+i) = ptrace_assert(PTRACE_PEEKDATA, pid, (void*)(addr+sizeof(long)*i), 0, "read to tmp in get_mem");
  memcpy(buf, tmp, size);
  free(tmp);
  return size;
}

static long breakpoint_bytes;

void set_breakpoint(addr_t addr) {
	//设置断点
	//将addr的头一个字节(第一个字的低字节)换成0xCC
  get_mem(addr, &breakpoint_bytes, sizeof(long));
  long temp = (breakpoint_bytes & 0xFFFFFFFFFFFFFF00) | 0xCC;
  ptrace_assert(PTRACE_POKETEXT, pid, (void*)addr, (void*)temp);
}

void remove_breakpoint(addr_t addr) {
  //恢复断点
  struct user_regs_struct regs;
  ptrace_assert(PTRACE_GETREGS, pid, NULL, &regs);
  //软件断点会在断点的下一个字节停住,所以还要将RIP向前恢复一个字节
  regs.rip-=1;
  assert(addr == regs.rip);
  // printf("0x%llx\n", regs.rip);
  ptrace_assert(PTRACE_SETREGS, pid, NULL, &regs);
  ptrace_assert(PTRACE_POKETEXT, pid, (void*)regs.rip, (void*)breakpoint_bytes);
}

void set_syscall_intercept() {
  ptrace_assert(PTRACE_SYSCALL, pid, NULL, NULL);
}

void continue_process() {
  //执行子进程
  ptrace_assert(PTRACE_CONT, pid, 0, 0);
  wait_assert();
}

bool is_reach_syscall() {
  unsigned long long pc;
  assert(get_reg("rip", &pc, sizeof(pc))==sizeof(pc));
  uint8_t inst_bytes[2];
  get_mem(pc-2, inst_bytes, 2);
  if(inst_bytes[0] != 0xf || inst_bytes[1] != 5)
    return false;
  else
    return true;
}

bool is_arch_prctl() {
  if(!is_reach_syscall())
    return false;
  unsigned long long sys_num;
  assert(get_reg("orig_rax", &sys_num, sizeof(sys_num))==sizeof(sys_num));
  if(sys_num == SYS_arch_prctl)
    return true;
  return false;
}

bool is_reach_start() {
  unsigned long long pc;
  assert(get_reg("rip", &pc, sizeof(pc))==sizeof(pc));
  uint8_t inst_bytes[1];
  get_mem(pc-1, inst_bytes, 1);
  if(inst_bytes[0] != 0xcc)
    return false;
  else
    return true;
}

static bool tls_use_fs;
static addr_t tls_base;

void start_child_set_tls(string binary, uint64_t addr) {
  // launch child to main or entry and intercept arch_prctl by the way
  // get main's addr, if can't, get entry
  addr_t start_addr = addr;// get_start_addr(binary);
  set_breakpoint(start_addr);
  unsigned meet_arch_prctl = 0;
  while(1) {
    set_syscall_intercept();
    wait_assert();
    if(is_arch_prctl())
      ++meet_arch_prctl;
    if(is_arch_prctl() && meet_arch_prctl==1) {
      unsigned long long prctl_code;
      assert(get_reg("rdi", &prctl_code, sizeof(prctl_code))==sizeof(prctl_code));
      assert((unsigned long long)((int)prctl_code) == prctl_code);
      if(prctl_code == ARCH_SET_FS || prctl_code == ARCH_SET_GS) {
        if(prctl_code == ARCH_SET_FS)
          tls_use_fs = true;
        else if(prctl_code == ARCH_SET_GS)
          tls_use_fs = false;
        assert(get_reg("rsi", &tls_base, sizeof(tls_base))==sizeof(tls_base));
      }
    }
    assert(!is_arch_prctl() || meet_arch_prctl == 1 || meet_arch_prctl == 2);
    if(is_reach_start()) {
      unsigned long long pc;
      assert(get_reg("rip", &pc, sizeof(pc))==sizeof(pc));
      remove_breakpoint(pc-1);
      if(!tls_base) {
        if(tls_use_fs) {
          addr_t temp;
          assert(get_reg("fs_base", &temp, sizeof(temp))==sizeof(temp));
          assert(temp==tls_base);
        }
        else {
          addr_t temp;
          assert(get_reg("gs_base", &temp, sizeof(temp))==sizeof(temp));
          assert(temp==tls_base);
        }
      }
      return;
    }
  }
}

pid_t create_debugger_by_ptrace(string binary, uint64_t addr)
{
  pid = create_child(binary);
  create_debugger_by_lldb(binary);
  start_child_set_tls(binary, addr);
  return pid;
}

pid_t get_pid()
{
  return pid;
}