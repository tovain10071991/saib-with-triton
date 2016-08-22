#include <udis86.h>

#include <iostream>

#include <err.h>
#include <assert.h>

using namespace std;

static ud_t ud_obj;

class UDis86Inited {
public:
  UDis86Inited() {
    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, 64);
    ud_set_vendor(&ud_obj, UD_VENDOR_AMD);
    ud_set_syntax(&ud_obj, UD_SYN_ATT);
  }
  ~UDis86Inited() {}
};
static UDis86Inited inited;

static void disassemble_inst(void* content, size_t size, uint64_t address = 0) {
  ud_set_input_buffer(&ud_obj, (unsigned char*)content, 15);
  ud_set_pc(&ud_obj, address);  
  assert(ud_disassemble(&ud_obj));
}

bool is_indirect_branch(void* content, size_t size) {
  disassemble_inst(content, size);
  ud_mnemonic_code mne = ud_insn_mnemonic(&ud_obj);
  if(mne == UD_Icall || mne == UD_Ijmp || mne == UD_Iret || mne == UD_Iiretw || mne == UD_Iiretd || mne == UD_Iiretq)
  {
    int i = 0;
    while(const ud_operand_t* ud_opr = ud_insn_opr(&ud_obj, i))
    {
      if(ud_opr->type == UD_OP_REG || ud_opr->type == UD_OP_MEM)
        return true;
    }
  }
  return false;
}

void print_inst(void* content, size_t size, uint64_t address) {
  disassemble_inst(content, size, address);
  cerr << ud_insn_asm(&ud_obj) << endl;
}

size_t get_inst_size(void* content, size_t size) {
  disassemble_inst(content, size);
  return ud_insn_len(&ud_obj);
}