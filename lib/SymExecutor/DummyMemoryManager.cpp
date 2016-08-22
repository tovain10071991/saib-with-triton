#include "DummyMemoryManager.h"

#define HIGH_MEM 0xffffffffff000000
#define LOW_MEM 0x800000000000

#define HIGH_TLS 0x400000
#define LOW_TLS 0x0

#include <map>
#include <assert.h>

using namespace std;

DummyMemoryManager::DummyMemoryManager() : low_mem(LOW_MEM), high_mem(HIGH_MEM), low_tls(LOW_TLS), high_tls(HIGH_TLS) {}

uint64_t DummyMemoryManager::malloc(size_t size) {
  uint64_t min_addr = LOW_MEM;
  auto allocated_iter = allocated_mem_set.begin();
  for(; allocated_iter != allocated_mem_set.end(); ++allocated_iter) {
    if(allocated_iter->first > min_addr && min_addr + size <= allocated_iter->second)
      break;
    min_addr = allocated_iter->second;
  }
  uint64_t high_bound = (allocated_iter==allocated_mem_set.end()) ? HIGH_MEM : allocated_iter->second;
  assert(min_addr + size <= high_bound);
  allocated_mem_set.insert({min_addr, min_addr+ size});
  return min_addr;
}

void DummyMemoryManager::free(uint64_t pointer) {
  auto allocated_iter = allocated_mem_set.find(pointer);
  assert(allocated_iter != allocated_mem_set.end());
  allocated_mem_set.erase(allocated_iter);
}

bool DummyMemoryManager::is_allocated(uint64_t addr, size_t size) {
  if(addr < LOW_MEM)
    return false;
  auto allocated_iter = allocated_mem_set.lower_bound(addr);
  if(allocated_iter == allocated_mem_set.end()) {
    assert(0 && "unsafe");
    return false;
  }
  if(addr + size <= allocated_iter->second)
    return true;
  else {
    assert(0 && "unsafe");
    return false;
  }
}

DummyMemoryManager mem_manager;