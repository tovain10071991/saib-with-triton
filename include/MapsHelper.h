# pragma once

#include <vector>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

typedef struct {
  uint64_t addr;
  uint64_t endaddr;
  const char *permissions;
  size_t permissions_len;
  uint64_t offset;
  const char *device;
  size_t device_len;
  uint64_t inode;
  const char *filename;
} map_t;

void get_stack_range(uint64_t* stack_addr, uint64_t* stack_endaddr, pid_t pid);
std::vector<map_t> get_data_segments(pid_t pid);