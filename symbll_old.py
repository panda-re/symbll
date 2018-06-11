#!/usr/bin/env python

#import IPython
from z3 import *
from llvm import *
from llvm.core import *
from collections import defaultdict
import enum
import sys
import plog_reader
#import i386 
#from i386_flat import *
import arm
from arm_flat import *

offset_to_slot = {}
for slot in ARMCPU_flat.keys():
    offset = ARMCPU_flat[slot]
    offset_to_slot[offset] = slot
from plog_enum import LLVMType

guest_ram = {}

def unhandled_ram():
    print "WARNING: returning nonsense for unhandled RAM read"
    return 0xdeadbeefdeadbeef
host_ram = defaultdict(unhandled_ram)

symbolic_cpu = {}

path_condition = []

def check(entry, expected):
    if entry.type != expected.value:
        print "ERROR: misaligned log. Have",LLVMType(entry.type),"expected",expected
        print "Log entry:"
        print entry
        raise AssertionError("entry.type != expected.value")
    else:
        print "DEBUG:",LLVMType(entry.type),"==",expected

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
        offs = simplify(substitute(addr, (env, BitVecVal(arm.cpu_types['ARMCPU'][1]['env'][0], 64)))).as_signed_long()
        print "DEBUG: that simplify thing returned", offs
        if (offs in offset_to_slot):
            return (offs, offset_to_slot[offs])
        else:
            print addr
            raise ValueError("How can addr simplify to a number and not be a slot?")
    except:
        raise

def exec_bb(mod, plog, bb, symbolic_locals):
    print "====== DEBUG: BB dump ======"
    print bb
    entry = plog.next().llvmEntry
    check(entry, LLVMType.BB)
    for insn in bb.instructions:
        print "instr : " + str(insn)
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
            check(entry, LLVMType.FUNC_CODE_INST_LOAD)
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate':
                print "DEBUG: ignoring instruction tagged as rrupdate"
                pass
            else:
                addr = lookup_operand(insn.operands[0], symbolic_locals)
                cpu_slot = get_cpu_slot(addr)
                print cpu_slot
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    print "DEBUG: Found entry in CPU slot: %s" % slot_name
                    symbolic_locals[insn] = lookup_cpu(slot_name, 64, symbolic_cpu)
                else:
                    print "DEBUG: Didn't find %#x in the CPU, retrieving from host RAM" % entry.address
                    symbolic_locals[insn] = host_ram[entry.address]
        elif insn.opcode == OPCODE_ADD:
            x = lookup_operand(insn.operands[0], symbolic_locals) 
            y = lookup_operand(insn.operands[1], symbolic_locals)
            symbolic_locals[insn] = (x+y)                
        elif insn.opcode == OPCODE_STORE:
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_STORE)
            assert entry.address % 8 == 0
            host_ram[entry.address] = lookup_operand(insn.operands[0], symbolic_locals) 
        elif insn.opcode == OPCODE_ICMP:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals)
            if insn.predicate == ICMP_NE:
                res = (o1 != o2)
            elif insn.predicate == ICMP_EQ:
                res = (o1 == o2)
            else:
                raise NotImplemented("There are more predicates dum-dum")
            symbolic_locals[insn] = If(res,BitVecVal(1,1),BitVecVal(0,1))
        elif insn.opcode == OPCODE_ZEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            symbolic_locals[insn] = ZeroExt(insn.type.width, o1)
        elif insn.opcode == OPCODE_BR:
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_BR)
            successor = insn.operands[1 + entry.condition]
            path_condition.append(lookup_operand(insn.operands[0], symbolic_locals))
            #cond = lookup_operand(insn.operands[0], symbolic_locals)
            #s = Solver()
            #s.add(cond == True)
            #if (s.check()) == sat:
            #    successor = insn.operands[1]
            #else:
            #    successor = insn.operands[2]
            #IPython.embed()
        elif insn.opcode == OPCODE_RET:
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_RET)
            successor = None
        else:
            print insn
            raise NotImplementedError("Pls implement this instr")

    #print "At end of BB.  locals:"
    #for k in symbolic_locals.keys():
    #    print (str(k)) + " :\t" + str(symbolic_locals[k])

    return successor

def exec_function(mod, plog, func):
    symbolic_locals = {}
    bb = func.entry_basic_block 
    symbolic_locals['env_ptr'] = func.args[0]
    while True:
        bb = exec_bb(mod, plog, bb, symbolic_locals)
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
    check(entry.llvmEntry, LLVMType.LLVM_FN)
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    exec_function(mod, plog, f)
