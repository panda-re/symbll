#!/usr/bin/env python

USAGE="""
symbll.py [args] panda-llvm-trace

STOP! W're no running PANDA for you. 
We're not generating replays nor will we translate them to LLVM. That's your job!

Symbll runs progressive symbolic execution on PANDA traces
to generate promising new inputs for further tests.
This technique is also known as Concolic Testing, Whitebox Fuzzing, or Dynamic Symbolic Execution.


Advanced USAGE:
    --xx does ... 
    --?? does ... 
"""

from z3 import *
from llvm import *
from llvm.core import *
from collections import defaultdict
import enum
import sys
import plog_reader
#import i386 
#from i386_flat import *

#import os
#import shlex
#import shutil
#import subprocess as sp
import argparse

def EXIT_USAGE():
    print(USAGE)
sys.exit(1)


#class LLVMType(Enum):
    ### Function codes as of symbll.py
    ### added later 
    ### will probably be exported

def get_function(plog, module):
    try:
        entry = plog.next()
    except StopIteration:
        print "x"
    #assert (entry.llvmEntry.type == LLVMType.LLVM_FN)
    #return module.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    #exec_function(mod, plog, f)

def get_bb(f):
    return f.entry_basic_block

def get_instruction(i):
    return bb.instructions

def analyze(insn):
############################### Common Instructions ###############################
# handle basic instructions liek ADD
    if insn.opcode == OPCODE_ADD:
        x = lookup_operand(insn.operands[0], symbolic_store) 
        y = lookup_operand(insn.operands[1], symbolic_store)
        symbolic_store[insn] = (x+y)    
############################### Memory Access ###############################
# handle memory allocations
# do nothing
    elif insn.opcode == OPCODE_ALLOCA:
        pass    

# handle LOAD
# pass if host operand = "rrupdate"
# ELSE write to symbolic_vars
    elif insn.opcode == OPCODE_LOAD:
        entry = plog.next().llvmEntry
        assert entry.type == LLVMType.FUNC_CODE_INST_LOAD
        m = insn.get_metadata('host')
        if m and m.getOperand(0).getName() == 'rrupdate':
            pass
        else:
            addr = lookup_operand(insn.operands[0], symbolic_store)
            cpu_slot = get_cpu_slot(addr)
            if cpu_slot:
                (offs, slot_name) = cpu_slot
                symbolic_store[insn] = lookup_cpu(slot_name, 64, symbolic_cpu)
            else:
                symbolic_store[insn] = host_ram[entry.address]
# handle STORE
# write to symbolic vars
    elif insn.opcode == OPCODE_STORE:
        entry = plog.next().llvmEntry
        assert entry.type == LLVMType.FUNC_CODE_INST_STORE
        assert entry.address % 8 == 0
        host_ram[entry.address] = lookup_operand(insn.operands[0], symbolic_store) 


############################### Environment Interaction ###############################
# handle Sys Calls
# pass if syscall was recorded else raise error
    if insn.opcode == OPCODE_CALL:
        if insn.called_function.name.startswith('record'):
            pass
        else:
            raise ValueError("unknown function %s encountered" % insn.called_function.name)

# handle ptr to integers    
    elif insn.opcode == OPCODE_PTRTOINT:
        if insn.operands[0] == symbolic_store['env_ptr']:
            symbolic_store[insn] = env 
        else:
                symbolic_store[insn] = lookup_operand(insn.operands[0], symbolic_store)
# handlte integers to pointers
    elif (insn.opcode == OPCODE_INTTOPTR or
              insn.opcode == OPCODE_BITCAST):
            symbolic_store[insn] = lookup_operand(insn.operands[0], symbolic_store)

############################### Branches ###############################
# handle COMPAREs
# write predicate to symbolic_vars
    elif insn.opcode == OPCODE_ICMP:
        o1 = lookup_operand(insn.operands[0], symbolic_store)
        o2 = lookup_operand(insn.operands[1], symbolic_store)
        if insn.predicate == ICMP_NE:
             path_constraints[insn] = (o1 != o2)
        elif insn.predicate == ICMP_EQ:
            path_constraints[insn] = (o1 == o2)
        else:
            raise NotImplemented("There are more predicates dum-dum")
    
# handle BRANCH
# set a target address (successor)
# add it to our SMT solver
    elif insn.opcode == OPCODE_BR:
        cond = lookup_operand(insn.operands[0], symbolic_store)
        s = Solver()
        s.add(cond == True)
        if (s.check()) == sat:
            successor = insn.operands[1]
            # we don't need this; BR always follows ICMP path_constraints[insn] = (o1 == o2)
        else:
            successor = insn.operands[2]
            # we don't need this; BR always follows ICMP path_constraints[insn] = (o1 == o2)#
# print default case
    else:
        print insn
        raise NotImplementedError("Pls implement this instr")
    return successor

def lookup_operand(operand, symbolic_store):
    if isinstance(operand, Instruction):
        return symbolic_store[operand]
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
    #return 1
    except:
        return None


def symbolic_exec():
    parser = argparse.ArgumbentParser(usage=USAGE)

    parser.add_argument("--xx", action='store_true')
    parser.add_argument("--yy", action='store', default="y")

    args, guest_cmd = parser.parse_known_args()
    if args.cmd:
       guest_cmd = shlex.split(args.cmd)

    if len(sys.argv) < 2:
        EXIT_USAGE()

    trace = guest_cmd[0]
    statement = {} #holds NEXT statement to evaluate; can be assignment, BR, JMP, CALL or LOOP
    symbolic_store = {}     #assigns program variables to either concrete or symbolic vars
    path_constraints = {} #holds assumptions for each symbolic var in symbolic_store

    llvm_module = Module.from_bitcode(file(sys.argv[1]))
    plog = plog_reader.read(sys.argv[2])
    plog.next()

    while 1:
        func = get_function(plog, module)
        #while 1: # CROSS OUT  actually follows the path rather than iteration over bbs
        bb = get_bb(func) #can be optimized by inlining, but I fell this is more readable
        while 1:
           insts = get_instructions(bb)
           for inst in insts:### add successor
                bb = analyze(inst, symbolic_store, path_constraints)
            #for loop naturally ends after last instruction, which is a bb; can we assert that?
            #gets next bbs instructions and starts for loop over
            #infinite. has to be stopped
                #print all new symbolics found in this basic block and return the next Block to analyze (successor)
                print "At end of BB!"
                print "Symbolic Store:"
                for k in symbolic_store.keys():
                    print (str(k)) + " : " + str(symbolic_store[k])
                    print "Path Constraints:"
                for k in path_constraints.keys():
                    print (str(k)) + " : " + str(path_constraints[k])
                    if (bb == RETURN_FUNCTION):
                        break
                        #print "break"
    #return None

if __name__ == "__main__":
    symbolic_exec()
