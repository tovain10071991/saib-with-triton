#include "IndirectInfo.pb.h"

#include <iostream>
#include <fstream>
#include <map>
#include <set>

using namespace std;
using namespace saib;

std::map<uint64_t, std::set<uint64_t> > indirect_call_set;

IndirectBrTargetSet indirect_br_target_set;

void init_indirect_call_set() {
  if(indirect_call_set.empty()) {
    ifstream indirect_input("indirect.output");
    indirect_br_target_set.ParseFromIstream(&indirect_input);
    
     int info_size = indirect_br_target_set.indirect_info_size();
     for(int i = 0; i < info_size; ++i) {
       IndirectBrTarget* indirect_br_target = indirect_br_target_set.mutable_indirect_info(i);
       uint64_t src_inst_addr = indirect_br_target->inst_addr();
       int target_size = indirect_br_target->inst_target_size();
       for(int j = 0; j < target_size; ++j) {
         indirect_call_set[src_inst_addr].insert(indirect_br_target->inst_target(j));
       }
     }
  }
}

void output_indirect(uint64_t src_addr, uint64_t des_addr)
{
  init_indirect_call_set();
  
  indirect_call_set[src_addr].insert(des_addr);
  
  IndirectBrTargetSet output_indirect_br_target_set;
  
  for(auto iter = indirect_call_set.begin(); iter != indirect_call_set.end(); ++iter)
  {
    IndirectBrTarget* indirect_br_target = output_indirect_br_target_set.add_indirect_info();
    indirect_br_target->set_inst_addr(iter->first);
      
    for(auto target_iter = iter->second.begin(); target_iter != iter->second.end(); ++target_iter)
    {
      indirect_br_target->add_inst_target(*target_iter);
    }
    assert(indirect_br_target->IsInitialized());
  }
  assert(output_indirect_br_target_set.IsInitialized());
  ofstream indirect_output("indirect.output");
  assert(output_indirect_br_target_set.SerializeToOstream(&indirect_output));
}