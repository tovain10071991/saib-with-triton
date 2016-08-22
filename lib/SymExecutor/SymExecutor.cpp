#include "SymExecutor.h"
#include "TritonEngine.h"

#include <string>
#include <err.h>

using namespace std;

SymExecutor* SymExecutor::create(impl impl_kind) {
  switch(impl_kind) {
    case impl::TRITON: {
      SymExecutor* sym_impl = new TritonEngine();
      return sym_impl;
      break;
    }
    default: {
      errx(-1, "elf unimplemented: %d", impl_kind);
    }
  }
}