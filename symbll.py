#!/usr/bin/env python

from z3 import *
from llvm import *
from llvm.core import *
from collections import defaultdict
import enum
import sys
import plog_reader
import i386 
from i386_flat import *

offset_to_slot = {}
for slot in X86CPU_flat.keys():
    offset = X86CPU_flat[slot]
    offset_to_slot[offset] = slot

class LLVMType(Enum):
    FUNC_CODE_DECLAREBLOCKS    =  1  # DECLAREBLOCKS: [n]
    FUNC_CODE_INST_BINOP       =  2  # BINOP:      [opcode, ty, opval, opval]
    FUNC_CODE_INST_CAST        =  3  # CAST:       [opcode, ty, opty, opval]
    FUNC_CODE_INST_GEP         =  4  # GEP:        [n x operands]
    FUNC_CODE_INST_SELECT      =  5  # SELECT:     [ty, opval, opval, opval]
    FUNC_CODE_INST_EXTRACTELT  =  6  # EXTRACTELT: [opty, opval, opval]
    FUNC_CODE_INST_INSERTELT   =  7  # INSERTELT:  [ty, opval, opval, opval]
    FUNC_CODE_INST_SHUFFLEVEC  =  8  # SHUFFLEVEC: [ty, opval, opval, opval]
    FUNC_CODE_INST_CMP         =  9  # CMP:        [opty, opval, opval, pred]
    FUNC_CODE_INST_RET         = 10  # RET:        [opty,opval<both optional>]
    FUNC_CODE_INST_BR          = 11  # BR:         [bb#, bb#, cond] or [bb#]
    FUNC_CODE_INST_SWITCH      = 12  # SWITCH:     [opty, op0, op1, ...]
    FUNC_CODE_INST_INVOKE      = 13  # INVOKE:     [attr, fnty, op0,op1, ...]
    # 14 is unused.
    FUNC_CODE_INST_UNREACHABLE = 15  # UNREACHABLE
    FUNC_CODE_INST_PHI         = 16  # PHI:        [ty, val0,bb0, ...]
    # 17 is unused.
    # 18 is unused.
    FUNC_CODE_INST_ALLOCA      = 19  # ALLOCA:     [instty, op, align]
    FUNC_CODE_INST_LOAD        = 20  # LOAD:       [opty, op, align, vol]
    # 21 is unused.
    # 22 is unused.
    FUNC_CODE_INST_VAARG       = 23  # VAARG:      [valistty, valist, instty]
    # This store code encodes the pointer type  rather than the value type
    # this is so information only available in the pointer type (e.g. address
    # spaces) is retained.
    FUNC_CODE_INST_STORE       = 24  # STORE:      [ptrty,ptr,val, align, vol]
    # 25 is unused.
    FUNC_CODE_INST_EXTRACTVAL  = 26  # EXTRACTVAL: [n x operands]
    FUNC_CODE_INST_INSERTVAL   = 27  # INSERTVAL:  [n x operands]
    # fcmp/icmp returning Int1TY or vector of Int1Ty. Same as CMP  exists to
    # support legacy vicmp/vfcmp instructions.
    FUNC_CODE_INST_CMP2        = 28  # CMP2:       [opty, opval, opval, pred]
    FUNC_CODE_INST_VSELECT     = 29  # VSELECT:    [ty,opval,opval,predty,pred]
    FUNC_CODE_INST_INBOUNDS_GEP= 30  # INBOUNDS_GEP: [n x operands]
    FUNC_CODE_INST_INDIRECTBR  = 31  # INDIRECTBR: [opty, op0, op1, ...]
    # 32 is unused.
    FUNC_CODE_DEBUG_LOC_AGAIN  = 33  # DEBUG_LOC_AGAIN
    FUNC_CODE_INST_CALL        = 34  # CALL:       [attr, fnty, fnid, args...]
    FUNC_CODE_DEBUG_LOC        = 35  # DEBUG_LOC:  [Line,Col,ScopeVal, IAVal]
    FUNC_CODE_INST_FENCE       = 36  # FENCE: [ordering, synchscope]
    FUNC_CODE_INST_CMPXCHG     = 37  # CMPXCHG: [ptrty,ptr,cmp,new, align, vol,
                                     #           ordering  synchscope]
    FUNC_CODE_INST_ATOMICRMW   = 38  # ATOMICRMW: [ptrty,ptr,val, operation,
                                     #             align  vol,
                                     #             ordering  synchscope]
    FUNC_CODE_INST_RESUME      = 39  # RESUME:     [opval]
    FUNC_CODE_INST_LANDINGPAD  = 40  # LANDINGPAD: [ty,val,val,num,id0,val0...]
    FUNC_CODE_INST_LOADATOMIC  = 41  # LOAD: [opty, op, align, vol,
                                     #        ordering  synchscope]
    FUNC_CODE_INST_STOREATOMIC = 42  # STORE: [ptrty,ptr,val, align, vol
                                     #         ordering  synchscope]
    BB = 43 
    LLVM_FN = 44 
    LLVM_EXCEPTION = 45

guest_ram = {}

def unhandled_ram():
    return 0xdeadbeefdeadbeef
host_ram = defaultdict(unhandled_ram)

symbolic_cpu = {}

def lookup_operand(operand, symbolic_locals):
    if isinstance(operand, Instruction):
        return symbolic_locals[operand]
    elif isinstance(operand, ConstantInt):
        return operand.s_ext_value
    else:
        raise NotImplementedError('Unknown operand type')

def lookup_cpu(slotname, numbits, symbolic_cpu):
    if not(slotname in symbolic_cpu):
        symbolic_cpu[slotname] = BitVec(slotname, numbits)
    return symbolic_cpu[slotname]

env = BitVec('env', 64)

def get_cpu_slot(addr):
    try:
        offs = simplify(substitute(addr, (env, BitVecVal(i386.cpu_types['X86CPU'][1]['env'][0], 64)))).as_signed_long()
        if (offs in offset_to_slot):
            return (offs, offset_to_slot[offsy])
        else:
            print addr
            raise ValueError("How can addr simplify to a number and not be a slot?")
    except:
        return None
    

def exec_bb(mod, plog, bb, symbolic_locals):
    assert(plog.next().llvmEntry.type == LLVMType.BB)
    for insn in bb.instructions:
        print "\n\ninstr : " + str(insn)
        if insn.opcode == OPCODE_CALL:
            if insn.called_function.name.startswith('record'):
                pass
            else:
                raise ValueError("unknown function %s encountered" % insn.called_function.name)
        elif insn.opcode == OPCODE_ALLOCA:
            pass
        elif insn.opcode == OPCODE_PTRTOINT:
            if insn.operands[0] == symbolic_locals['env_ptr']:
                symbolic_locals[insn] = env 
            else:
                symbolic_locals[insn] = lookup_operand(insn.operands[0], symbolic_locals)
        elif (insn.opcode == OPCODE_INTTOPTR or
              insn.opcode == OPCODE_BITCAST):
            symbolic_locals[insn] = lookup_operand(insn.operands[0], symbolic_locals)
        elif insn.opcode == OPCODE_LOAD:
            entry = plog.next().llvmEntry
            assert entry.type == LLVMType.FUNC_CODE_INST_LOAD
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate':
                pass
            else:
                addr = lookup_operand(insn.operands[0], symbolic_locals)
                cpu_slot = get_cpu_slot(addr)
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    symbolic_locals[insn] = lookup_cpu(slot_name, 64, symbolic_cpu)
                else:
#                    assert entry.address % 8 == 0
                    symbolic_locals[insn] = host_ram[entry.address]
#
#                print insn
 #               raise NotImplementedError("Load froma addr outside of cpu?")
        elif insn.opcode == OPCODE_ADD:
            x = lookup_operand(insn.operands[0], symbolic_locals) 
            y = lookup_operand(insn.operands[1], symbolic_locals)
            symbolic_locals[insn] = (x+y)                
        elif insn.opcode == OPCODE_STORE:
            entry = plog.next().llvmEntry
            assert entry.type == LLVMType.FUNC_CODE_INST_STORE
            assert entry.address % 8 == 0
            host_ram[entry.address] = lookup_operand(insn.operands[0], symbolic_locals) 
        elif insn.opcode == OPCODE_ICMP:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals)
            if insn.predicate == ICMP_NE:
                symbolic_locals[insn] = (o1 != o2)
            elif insn.predicate == ICMP_EQ:
                symbolic_locals[insn] = (o1 == o2)
            else:
                raise NotImplemented("There are more predicates dum-dum")
        elif insn.opcode == OPCODE_BR:
            cond = lookup_operand(insn.operands[0], symbolic_locals)
            s = Solver()
            s.add(cond == True)
            if (s.check()) == sat:
                successor = insn.operands[1]
            else:
                successor = insn.operands[2]
        else:
            print insn
            raise NotImplementedError("Pls implement this instr")

    print "At end of BB.  locals:"
    for k in symbolic_locals.keys():
        print (str(k)) + " : " + str(symbolic_locals[k])

    return successor

def exec_function(mod, plog, func):
    symbolic_locals = {}
    bb = f.entry_basic_block 
    symbolic_locals['env_ptr'] = func.args[0]
    while True:
        successor = exec_bb(mod, plog, bb, symbolic_locals)
        if not bb: break

mod = Module.from_bitcode(file(sys.argv[1]))
plog = plog_reader.read(sys.argv[2])
plog.next()

s = Solver()

while True:
    try:
        entry = plog.next()
    except StopIteration:
        break
    assert (entry.llvmEntry.type == LLVMType.LLVM_FN)
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    exec_function(mod, plog, f)
