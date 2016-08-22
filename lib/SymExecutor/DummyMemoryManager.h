# pragma once

#include <map>

class DummyMemoryManager {
public:
  DummyMemoryManager();
  uint64_t malloc(size_t size);
  void free(uint64_t pointer);
  bool is_allocated(uint64_t addr, size_t size);
  uint64_t low_mem;
  uint64_t high_mem;
  uint64_t low_tls;
  uint64_t high_tls;
private:
  std::map<uint64_t, uint64_t> allocated_mem_set;
};

extern DummyMemoryManager mem_manager;