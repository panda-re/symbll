#!/usr/bin/env python

import IPython
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

def handleCTLZS(operand):
    o1 = lookup_operand(operand, symbolic_locals)
    for i in o1.size():
        if operand[:i] == 0: 
            return BitvecVal(i, o1.size()) 

def handleCTTZS(operand):
    o1 = lookup_operand(operand, symbolic_locals)
    for i in o1.size():
        if operand[:i] == 0: 
            return BitvecVal(i, o1.size()) 

def handleUADD(operandA, operandB):
    return (operandA + operandB)

def handleBSWAP(operand):
    o1 = lookup_operand(operand, symbolic_locals)

    
    return operand


def unhandled_ram():
    print ("WARNING: returning nonsense for unhandled RAM read")
    return 0xdeadbeefdeadbeef
host_ram = defaultdict(unhandled_ram)

symbolic_cpu = {}
sorted_cpu = sorted(arm.cpu_types['CPUARMState'][1].items(), key=lambda item: item[1][0]) #unflattened ARM CPU but sorted so we can access via index as in GetElementPointer

bb_counter = 0
previous_bb = 0 
path_condition = []

def check(entry, expected):
    print  entry.type
    print expected.value
    if entry.type != expected.value:
        print ("ERROR: misaligned log. Have",LLVMType(entry.type),"expected",expected)
        print ("Log entry:")
        print (entry)
        print (plog.next().llvmEntry)
        print (plog.next().llvmEntry)
        raise AssertionError("entry.type != expected.value")
    else:
        print ("DEBUG:",LLVMType(entry.type),"==",expected)

def lookup_operand(operand, symbolic_locals):
    if isinstance(operand, Instruction):
        return symbolic_locals[operand]
    elif isinstance(operand, Argument):
        return symbolic_locals[operand]     
    elif isinstance(operand, ConstantInt):
        return operand.s_ext_value
    elif isinstance(operand, ConstantPointerNull):
        return None
    else:
        print ("DEBUG: Operand couldnt be found:")
        print ("THE OPERAND:")
        print (operand)
        print ("", operand)
        print ("ITS TYPE")
        print (operand.type)
        print ("CURRENT SYMBOLIC LOCALS")
        print (symbolic_locals)
        raise NotImplementedError('Unknown operand type')

def lookup_cpu(slotname, numbits, symbolic_cpu):
    if not(slotname in symbolic_cpu):
        symbolic_cpu[slotname] = BitVec(slotname, numbits)
    return symbolic_cpu[slotname]

env = BitVec('env', 64)

def get_cpu_slot(addr):
    try:
        offs = simplify(substitute(addr, (env, BitVecVal(arm.cpu_types['ARMCPU'][1]['env'][0], 64)))).as_signed_long()
        print ("DEBUG: that simplify thing returned", offs) #e.g. offs = 33420
        if (offs in offset_to_slot):# 
            return (offs, offset_to_slot[offs]) #return e.g. (33420, registername)
        else:
            print (addr, offs)
            raise ValueError("How can addr simplify to a number and not be a slot?")
    except:
        raise

def get_cpu_slot2(addr):
    try:
        offs = simplify(substitute(addr, (env, BitVecVal(arm.cpu_types['ARMCPU'][1]['env'][0], 64)))).as_signed_long()
        print ("DEBUG: that simplify thing returned", offs) #e.g. offs = 33420
        if (offs in offset_to_slot):# 
            return (offs, offset_to_slot[offs]) #return e.g. (33420, registername)
        else:
            return # for STORE instructions offs always simplifies to a number -> the address
            #actually, we can cut out the whole simplify thing and just lookup the address...
            #raise ValueError("How can addr simplify to a number and not be a slot?")
    except:
        raise

def exec_bb(mod, plog, bb, symbolic_locals):
    global bb_counter 
    global previous_bb
    print (bb_counter)
    bb_counter = bb_counter + 1
    print ("====== DEBUG: BB dump ======")
    print (bb)
    entry = plog.next().llvmEntry
    check(entry, LLVMType.BB)
    for insn in bb.instructions:
        print ("instr : " + str(insn))
        if insn.opcode == OPCODE_CALL:
            if insn.called_function.name.startswith('record'):
                pass
            
            elif insn.called_function.name.startswith('helper_le_ld'):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_LOAD)
                assert entry.addr_type == 2
                asd = BitVecVal(entry.addr_type, 32)## should be VALUE of course, once its generated
                host_ram[entry.address] = asd #asentry.addr_type #should be value of course but value is not implemented yet
                symbolic_locals[insn] = asd #entry.addr_type
            
            elif insn.called_function.name.startswith('helper_le_st'):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_STORE)
                assert entry.addr_type == 2
                val = BitVecVal(entry.value, 32)
                host_ram[entry.address] = val
                symbolic_locals[insn] = val

            elif insn.called_function.name.startswith('helper_cpsr_read_llvm') or insn.called_function.name.startswith('helper_cpsr_write_llvm') or insn.called_function.name.startswith('cpsr_read') or insn.called_function.name.startswith('cpsr_write') or insn.called_function.name.startswith('helper_cpsr_write_eret_llvm') or insn.called_function.name.startswith('switch_mode') or insn.called_function.name.startswith('helper_le_ldul_mmu_panda') or insn.called_function.name.startswith('helper_ret_ldub_mmu_panda'):
                symbolic_locals_preserved = symbolic_locals
                subfunction = insn.called_function
                parameters = [] # chose to use list over dict, as its sorted
                print ("####################DEBUG###############:")
                print ("CURRENT SYMBOLIC LOCALS")
                print (symbolic_locals)
                i = 0
                for operand in insn.operands:
                    if (i == insn.operand_count-1): #the last operand is the called function itself
                        continue
                    if (i == 0): #assuming that the first param always is the env ptr
                        parameters.append(env)
                    elif i > 0:
                        parameters.append(lookup_operand(operand, symbolic_locals))
                    print("####################DEBUG###############:")
                    print("Parameter ", i,":", parameters[i])
                    print (type(parameters[i]))
                    i = i + 1
                retVal = exec_function(mod, plog, subfunction, *parameters)
                symbolic_locals = symbolic_locals_preserved
                try:
                    symbolic_locals[insn] = BitVecVal(retVal, insn.type.width)
                except AttributeError: #return may have type VOID
                    pass
                entry = plog.next().llvmEntry # fucntion call is recorded AFTER execution
            elif insn.called_function.name.startswith('llvm'):
                symbolic_locals[insn] = BitVec('x', insn.type.width)
                print ("yalalalalal")
                '''
                if insn.called_function.name.startswith('llvm.ctlzs'):
                    symbolic_locals[insn] == handleCTLZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.cttzs'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.uadd'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.bswap'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.memset.p0i8'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.memcpy.p0i8'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.returnaddress'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.lifetime.start'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)
                elif insn.called_function.name.startswith('llvm.lifetime.end'):
                    symbolic_locals[insn] == handleCTTZS(operand[1], insn.type.width)'''
            else:
                raise ValueError("unknown function %s encountered" % insn.called_function.name)
            
        elif insn.opcode == OPCODE_ALLOCA:
            pass
        
        elif insn.opcode == OPCODE_PTRTOINT:
            if insn.operands[0] == symbolic_locals['env_ptr']:
                symbolic_locals[insn] = env 
            else:
                symbolic_locals[insn] = lookup_operand(insn.operands[0], symbolic_locals)
        
        elif insn.opcode == OPCODE_GETELEMENTPTR:
            if insn.operands[0] == symbolic_locals['env_ptr']:
                symbolic_locals[insn] = sorted_cpu[lookup_operand(insn.operands[2], symbolic_locals)][1][0]
                print ("DEBUG: The sorted CPU at index ", lookup_operand(insn.operands[2],symbolic_locals), " is ", symbolic_locals[insn])
                #cast to flattened format in Z3 type
                symbolic_locals[insn] = arm.cpu_types['ARMCPU'][1]['env'][0] + symbolic_locals[insn]
                symbolic_locals[insn] = BitVecVal(symbolic_locals[insn], 64)
                print ("DEBUG: ")
            else:
                raise NotImplemented("This struct is undefined o.O what could it be?")
        
        elif (insn.opcode == OPCODE_INTTOPTR or
              insn.opcode == OPCODE_BITCAST):
            symbolic_locals[insn] = lookup_operand(insn.operands[0], symbolic_locals)
        
        elif insn.opcode == OPCODE_LOAD:
            entry = plog.next().llvmEntry
            m = insn.get_metadata('host')
            #check(entry, LLVMType.FUNC_CODE_INST_LOAD, insn)
            if m and m.getOperand(0).getName() == 'rrupdate' or (m and m.getOperand(0).getName() == 'pcupdate'):
                print (m)
                print (m.getOperand(0).getName())
                print ("DEBUG: ignoring instruction tagged as rrupdate/ pcupdate")
                pass
            else:
                #entry = plog.next().llvmEntry
                check(entry, LLVMType.FUNC_CODE_INST_LOAD)
                addr = lookup_operand(insn.operands[0], symbolic_locals)
                cpu_slot = get_cpu_slot(addr)
                print (cpu_slot)
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    print ("DEBUG: Found entry in CPU slot: %s" % slot_name)
                    print (insn)
                    print (insn.type)
                    try: #may fail for instruction type PointerVale (has no attribute width)
                        symbolic_locals[insn] = lookup_cpu(slot_name, insn.type.width, symbolic_cpu)
                    except:
                        symbolic_locals[insn] = lookup_cpu(slot_name, 64, symbolic_cpu)
                else:
                    print ("DEBUG: Didn't find %#x in the CPU, retrieving from host RAM" % entry.address)
                    symbolic_locals[insn] = host_ram[entry.address]
        
        elif insn.opcode == OPCODE_MUL:
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate':
                pass
            else: 
                x = lookup_operand(insn.operands[0], symbolic_locals) 
                y = lookup_operand(insn.operands[1], symbolic_locals)
                symbolic_locals[insn] = (x*y) 

        elif insn.opcode == OPCODE_ADD:
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate':
                pass
            else: 
                x = lookup_operand(insn.operands[0], symbolic_locals) 
                y = lookup_operand(insn.operands[1], symbolic_locals)
                symbolic_locals[insn] = (x+y)            
        
        elif insn.opcode == OPCODE_SUB:
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate':
                pass
            else: 
                x = lookup_operand(insn.operands[0], symbolic_locals) 
                y = lookup_operand(insn.operands[1], symbolic_locals)
                symbolic_locals[insn] = (x-y)   
        
        elif insn.opcode == OPCODE_STORE:
            m = insn.get_metadata('host')
            #entry = plog.next().llvmEntry #only walk plog if instruction recorded
            if m and m.getOperand(0).getName() == 'rrupdate' or (m and m.getOperand(0).getName() == 'pcupdate'):
                print ("DEBUG: ignoring instruction tagged as rrupdate/ pcupdate")
                pass
            else:
                entry = plog.next().llvmEntry
                check(entry, LLVMType.FUNC_CODE_INST_STORE)
                #assert entry.address % 8 == 0 # this doesnt seem to work ... 
                addr = BitVecVal(entry.address, 64)
                cpu_slot = get_cpu_slot2(addr)
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    print ("DEBUG: Found entry in CPU slot: %s" % slot_name)
                    symbolic_cpu[slot_name] = lookup_operand(insn.operands[0], symbolic_locals)     
                else:
                    host_ram[entry.address] = lookup_operand(insn.operands[0], symbolic_locals) 
        
        elif insn.opcode == OPCODE_SELECT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals)
            o3 = lookup_operand(insn.operands[2], symbolic_locals)
            print ("SHOW ME THIS GUY")
            print (entry)
            #print (plog.next())
            print (insn.operands[0])
            print (insn.operands[1])
            print (insn.operands[2])
            print (o1)
            print (o2)
            print (o3)
            entry = plog.next().llvmEntry
            if (entry.condition == 1):
                symbolic_locals[insn] = lookup_operand(insn.operands[1], symbolic_locals)
            else:
                symbolic_locals[insn] = lookup_operand(insn.operands[2], symbolic_locals)
        
        elif insn.opcode == OPCODE_ICMP:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals)
            if insn.predicate == ICMP_NE:
                res = (o1 != o2)
            elif insn.predicate == ICMP_EQ:
                res = (o1 == o2)
            elif insn.predicate == ICMP_UGT:
                res = (o1 > o2)
            elif insn.predicate == ICMP_SGT:
                res = (o1 > o2)
            elif insn.predicate == ICMP_UGE:
                res = (o1 >= o2)
            elif insn.predicate == ICMP_SGE:
                res = (o1 >= o2)
            elif insn.predicate == ICMP_ULE:
                res = (o1 <= o2)
            elif insn.predicate == ICMP_SLT:
                res = (o1 < o2)
            else:
                raise NotImplemented("There are more predicates dum-dum")
            symbolic_locals[insn] = If(res,BitVecVal(1,1),BitVecVal(0,1))
        
        elif insn.opcode == OPCODE_SEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            print (o1)
            print (insn.operands[0])
            if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            symbolic_locals[insn] = SignExt(insn.type.width-o1.size(), o1)
            #assert symbolic_locals[insn].size() % 8 == 0 
        
        elif insn.opcode == OPCODE_ZEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            print (o1)
            print (insn.operands[0])
            if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            symbolic_locals[insn] = ZeroExt(insn.type.width-o1.size(), o1)
            #assert symbolic_locals[insn].size() % 8 == 0 
        
        elif insn.opcode == OPCODE_SWITCH:
            entry = plog.next().llvmEntry
            x = 0
            for operand in insn.operands:
                print (str(operand)[-4:-2])
                if x == 1:
                        successor = operand
                        x = 0
                if (str(entry.condition) == str(operand)[-4:-2]):
                        x = 1
        
        elif insn.opcode == OPCODE_BR:
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_BR)
            if (entry.condition == 111): #BR has condition 111 when used like JMP
                successor = insn.operands[0]
            else:
                successor = insn.operands[1 + entry.condition]
                path_condition.append(lookup_operand(insn.operands[0], symbolic_locals))
            previous_bb = bb
        
        elif insn.opcode == OPCODE_PHI:
            i = 0
            while i < insn.incoming_count:
                if (insn.get_incoming_block(i) == previous_bb):
                    o1 = lookup_operand(insn.get_incoming_value(i), symbolic_locals)
                    symbolic_locals[insn] = o1
                i = i+1    
        
        elif insn.opcode == OPCODE_AND:
            x = lookup_operand(insn.operands[0], symbolic_locals) #BitVecNumRef
            y = lookup_operand(insn.operands[1], symbolic_locals) #long
            symbolic_locals[insn] = (x & y)
        
        elif insn.opcode == OPCODE_OR:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)
            if isinstance(insn.operands[0], Instruction) and isinstance(insn.operands[1], Instruction):
                if (y.size() == 64 and x.size() == 32):
                    x = ZeroExt(32, x)
                if (x.size() == 64 and y.size() == 32):
                    y = ZeroExt(32, y)    
            symbolic_locals[insn] = (x | y) 
        
        elif insn.opcode == OPCODE_TRUNC:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            symbolic_locals[insn] = Extract(insn.type.width-1, 0, o1)

        elif insn.opcode == OPCODE_ASHR:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals)
            symbolic_locals[insn] = (o1 >> o2)

        elif insn.opcode == OPCODE_LSHR:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals)
            symbolic_locals[insn] = (o1 >> o2)

        elif insn.opcode == OPCODE_SHL:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals) 
            symbolic_locals[insn] = (o1 << o2)

        elif insn.opcode == OPCODE_XOR:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)
            if isinstance(insn.operands[0], Instruction) and isinstance(insn.operands[1], Instruction):
                if (y.size() == 64 and x.size() == 32):
                    x = ZeroExt(32, x)
                if (x.size() == 64 and y.size() == 32):
                    y = ZeroExt(32, y)    
            if (type(y) == long): o2 = BitVecVal(y, 32)
            symbolic_locals[insn] = (x ^ y)

        elif insn.opcode == OPCODE_RET:
            previous_bb = bb
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_RET)
            successor = None #Return should add sth to path_constraints?!
        
        else:
            print (insn)
            raise NotImplementedError("Pls implement this instr")

    return successor, entry.value

def exec_function(mod, plog, func, *params): #chose *params over params = {}, as it's sorted
    symbolic_locals = {}
    bb = func.entry_basic_block
    i = 0
    for arg in func.args:
        if i == 0:
            symbolic_locals['env_ptr'] = arg # if we put params[i] here it crashs
        else:
            if i<(len(params)):# ((i > 0) and (i < len(params)): 
                 symbolic_locals[arg] = params[i]#BitVecVal(params[i]. params[i].type)
        i = i+1
    print ("====== DEBUG: List of parameters: =======")
    i = 0
    for param in params:
        print (param)
    print ("====== DEBUG: List of func.args: =======")
    for arg in func.args:
        print (arg)
        print ("object:", arg)  
    print ("====== DEBUG: List of Symbolic_Locals: =======")
    for symloc in symbolic_locals:
        print (symloc, symbolic_locals[symloc])
    while True:
        bb, retVal = exec_bb(mod, plog, bb, symbolic_locals)
        if not bb: break
    return retVal

mod = Module.from_bitcode(file(sys.argv[1]))
plog = plog_reader.read(sys.argv[2])
print plog
print plog.next()

s = Solver()

while True:
    try:
        entry = plog.next()
        print entry
    except StopIteration:
        break
    check(entry.llvmEntry, LLVMType.LLVM_FN)
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    exec_function(mod, plog, f, f.args[0])