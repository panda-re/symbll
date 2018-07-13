#!/usr/bin/env python

#import IPython
from z3 import *
from llvm import *
from llvm.core import *
from collections import defaultdict
import enum
import sys
import plog_reader
from plog_enum import LLVMType
#import i386 
#from i386_flat import *
import arm
from arm_flat import *
import logging
import pdb


logging.basicConfig(level=logging.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

offset_to_slot = {}
for slot in ARMCPU_flat.keys():
    offset = ARMCPU_flat[slot]
    offset_to_slot[offset] = slot
'''
def handleCTLZS(operand):
    o1 = lookup_operand(operand, symbolic_locals)
    for i in o1.size():
        if operand[:i] == 0: 
            return BitvecVal(i, o1.size()) 
'''
def initialize_to(plog, addr):
    while True:
        entry = plog.next()
        if entry.llvmEntry.tb_num == addr: 
            break
    check(entry.llvmEntry, LLVMType.LLVM_FN)
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    exec_function(mod, plog, f, f.args[0])

def unhandled_ram():
    print ("WARNING: returning nonsense for unhandled RAM read")
    return 0xdeadbeefdeadbeef

host_ram = defaultdict(unhandled_ram)

initial_cpu_state = {}
symbolic_cpu = {}
concrete_cpu = {}
sorted_cpu = sorted(arm.cpu_types['CPUARMState'][1].items(), key=lambda item: item[1][0]) #unflattened ARM CPU but sorted so we can access via index as in GetElementPointer

path_condition = []

bb_counter = 0
previous_bb = 0 

def check(entry, expected):
    if entry.type != expected.value:
        print ("ERROR: misaligned log. Have",LLVMType(entry.type),"in plog; expected",expected," from BC")
        print ("Log entry:")
        print (entry)
        global bb_counter
        print (bb_counter)
        global previous_bb
        print  (previous_bb)
        raise AssertionError("entry.type != expected.value")
    else:
        pass
        logger.info("DEBUG:",LLVMType(entry.type),"==",expected)

def lookup_operand(operand, symbolic_locals):
    if isinstance(operand, Instruction) or isinstance(operand, Argument):
        return symbolic_locals[operand]
    #elif isinstance(operand, Argument):
    #    return symbolic_locals[operand]     
    elif isinstance(operand, ConstantInt):
        return operand.s_ext_value
    elif isinstance(operand, ConstantPointerNull):
        return None
    else:
        print ("ERROR: Operand couldnt be found:")
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
        ###print ("DEBUG: that simplify thing returned", offs) #e.g. offs = 33420
        if (offs in offset_to_slot):# 
            return (offs, offset_to_slot[offs]) #return e.g. (33420, registername)
        else:
           ### print (addr, offs)
            raise ValueError("How can addr simplify to a number and not be a slot?")
    except:
        raise

def get_cpu_slot2(addr):
    try:
        offs = simplify(substitute(addr, (env, BitVecVal(arm.cpu_types['ARMCPU'][1]['env'][0], 64)))).as_signed_long()
        ###print ("DEBUG: that simplify thing returned", offs) #e.g. offs = 33420
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
    logger.warning(bb_counter)
    bb_counter = bb_counter + 1
    print (bb_counter)
    logger.debug("====== DEBUG: BB dump ======")
    #print(bb)
    #entry = plog.next().llvmEntry
    entry = plog.next().llvmEntry
    print ("entry:")
    print (entry.type)
    #if bb_counter >= 10000:
    #    print (bb)
    #    print (entry)
    check(entry, LLVMType.BB)
    for insn in bb.instructions:
        #if (bb_counter >= 10000):
        #    print("instr : " + str(insn))

        if insn.opcode == OPCODE_CALL:
            if insn.called_function.name.startswith('record'):
                pass

            elif insn.called_function.name.startswith('helper_le_ld') or insn.called_function.name.startswith('helper_ret_ld'):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_LOAD)
                assert entry.addr_type == 2
                #plog entry LOAD (type 20) has field VALUE now
                #Thanks to Ray Wang
                val = BitVecVal(entry.value, entry.num_bytes*8)
                host_ram[entry.address] = val
                symbolic_locals[insn] = val
            
            elif insn.called_function.name.startswith('helper_le_st') or insn.called_function.name.startswith('helper_ret_st'):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_STORE)
                assert entry.addr_type == 2
                val = BitVecVal(entry.value, entry.num_bytes*8)
                host_ram[entry.address] = val
                symbolic_locals[insn] = val

            elif insn.called_function.name.startswith('helper_set_cp_reg_llvm'):
                # contains function pointer
                # do not go in to fnction on LLVM side
                # skip 5 entries on plog side

                #Function Pointer/ Dynamic Function calls are now supported
                #Thanks to Ray Wang
S
                #pdb.set_trace()

                print ("FN")
                print (plog.next)
                print ("BB")
                print (plog.next()) #bb
                print ("LOAD")
                print (plog.next())
                print ("RETURN")
                print (plog.next())
                print ("CALL")
                print (plog.next())

            elif (insn.called_function.name.startswith('helper_cpsr_read_llvm') 
              or insn.called_function.name.startswith('helper_cpsr_write_llvm') 
              or insn.called_function.name.startswith('cpsr_read') 
              or insn.called_function.name.startswith('cpsr_write') 
              or insn.called_function.name.startswith('helper_cpsr_write_eret_llvm') 
              or insn.called_function.name.startswith('switch_mode') 
              or insn.called_function.name.startswith('helper_shl_cc_llvm') 
              or insn.called_function.name.startswith('helper_shr_cc_llvm') 
              or insn.called_function.name.startswith('helper_set_user_reg_llvm') 
              or insn.called_function.name.startswith('helper_get_user_reg_llvm') 
              or insn.called_function.name.startswith('helper_vfp_set_fpscr_llvm') 
              or insn.called_function.name.startswith('helper_vfp_get_fpscr_llvm') 
              or insn.called_function.name.startswith('raise_exception') # Interrupt?!
              or insn.called_function.name.startswith('helper_exception_with_syndrome_llvm')):    
                symbolic_locals_preserved = symbolic_locals
                subfunction = insn.called_function
                parameters = [] # chose to use list over dict, becaue list is sorted
                for i in range(len(insn.operands)):
                    if (i == insn.operand_count-1): #the last operand is the called function itself
                        continue
                    if (i == 0): #assuming that the first param always is the env ptr
                        parameters.append(env)
                    elif i > 0:
                        parameters.append(lookup_operand(insn.operands[i], symbolic_locals))
                retVal = exec_function(mod, plog, subfunction, *parameters)
                symbolic_locals = symbolic_locals_preserved
                try: 
                    symbolic_locals[insn] = BitVecVal(retVal, insn.type.width)
                except:
                    try:
                        symbolic_locals[insn] = retVal
                    except AttributeError: #return may have type VOID - should be verified in an assertion
                        pass
                entry = plog.next().llvmEntry # fucntion call is recorded AFTER execution
            
            elif insn.called_function.name.startswith('llvm'):
                symbolic_locals[insn] = BitVec(insn.called_function.name, insn.type.width)

            else:
                logger.error("insn:"+ str(insn))
                logger.error(bb_counter)
                logger.error(previous_bb)
                logger.error(bb)
                logger.error(entry)
                logger.error(plog.next().llvmEntry)
                logger.error(plog.next().llvmEntry)
                logger.error(plog.next().llvmEntry)
                logger.error(plog.next().llvmEntry)
                raise ValueError("unknown function %s encountered" % insn.called_function.name)
            
        elif insn.opcode == OPCODE_LOAD:
            entry = plog.next().llvmEntry
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate' or (m and m.getOperand(0).getName() == 'pcupdate'):
                logger.debug("DEBUG: ignoring instruction tagged as rrupdate/ pcupdate")
                pass
            else:
                check(entry, LLVMType.FUNC_CODE_INST_LOAD)
                addr = lookup_operand(insn.operands[0], symbolic_locals)
                cpu_slot = get_cpu_slot(addr)
                #check if operand is address of a CPU slot
                #this can only be true if operand is constant value, so we should check that instead to save some time here
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    logger.debug("DEBUG: Found entry in CPU slot: %s" % slot_name)
                    try: #may fail for instruction type PointerValue (has no attribute width)
                        x = lookup_cpu(slot_name, insn.type.width, symbolic_cpu)
                        #originally was: symbolic_locals[insn] = lookup_cpu(slot_name, 64, symbolic_cpu)
                        #split this way to assure correct z3 type
                        if not(slotname in initial_cpu_state):
                            initial_cpu_state[slotname] = entry.value #holding the initial state so it can later be exported/ reused for subsequent runs
                        symbolic_cpu[slotname] = entry.value #holding the current state, so it's accessable at any time
                        #symbolic_locals[insn] = BitVec(str(x),32)
                        symbolic_locals[insn] = symbolic_cpu[slotname]
                    except:
                        x = lookup_cpu(slot_name, 64, symbolic_cpu)
                        symbolic_locals[insn] = BitVec(str(x),32)
                else:
                    logger.debug("DEBUG: Didn't find %#x in the CPU, retrieving from host RAM" % entry.address)
                    symbolic_locals[insn] = host_ram[entry.address]
        
        elif insn.opcode == OPCODE_STORE:
            m = insn.get_metadata('host')
            #entry = plog.next().llvmEntry #only walk plog if instruction recorded
            if m and m.getOperand(0).getName() == 'rrupdate' or (m and m.getOperand(0).getName() == 'pcupdate'):
                logger.debug("DEBUG: ignoring instruction tagged as rrupdate/ pcupdate")
                pass
            else:
                entry = plog.next().llvmEntry
                check(entry, LLVMType.FUNC_CODE_INST_STORE)
                #assert entry.address % 8 == 0 # this doesnt seem to work ... 
                addr = BitVecVal(entry.address, 64)
                cpu_slot = get_cpu_slot2(addr)
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    logger.debug("DEBUG: Found entry in CPU slot: %s" % slot_name)
                    symbolic_cpu[slot_name] = lookup_operand(insn.operands[0], symbolic_locals)     
                else:
                    host_ram[entry.address] = lookup_operand(insn.operands[0], symbolic_locals) 

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

        elif insn.opcode == OPCODE_GETELEMENTPTR:
            #pdb.set_trace()
            if insn.operands[0] == symbolic_locals['env_ptr']:
                symbolic_locals[insn] = sorted_cpu[lookup_operand(insn.operands[2], symbolic_locals)][1][0]
                logger.debug("DEBUG: The sorted CPU at index ", lookup_operand(insn.operands[2],symbolic_locals), " is ", symbolic_locals[insn])
                #cast to flattened format in Z3 type
                symbolic_locals[insn] = arm.cpu_types['ARMCPU'][1]['env'][0] + symbolic_locals[insn]
                symbolic_locals[insn] = BitVecVal(symbolic_locals[insn], 64)
            else: #<-- should assert type somehow
                symbolic_locals[insn] = BitVecVal(lookup_operand(insn.operands[1], symbolic_locals), 64)
            #else:
                #raise NotImplemented("This struct is undefined o.O what could it be?")
        
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
                try:
                    symbolic_locals[insn] = (x+y) 
                except:
                    symbolic_locals[insn] = BitVec('fake',64)
                    pass           
        
        elif insn.opcode == OPCODE_SUB:
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate':
                pass
            else: 
                x = lookup_operand(insn.operands[0], symbolic_locals) 
                y = lookup_operand(insn.operands[1], symbolic_locals)
                try:
                    symbolic_locals[insn] = (x-y) 
                except:
                    symbolic_locals[insn] = BitVec('fake',32)
                    pass             
        
        elif insn.opcode == OPCODE_SEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            symbolic_locals[insn] = SignExt(insn.type.width-o1.size(), o1)
            #assert symbolic_locals[insn].size() % 8 == 0 
        
        elif insn.opcode == OPCODE_ZEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            try:
                symbolic_locals[insn] = ZeroExt(insn.type.width-o1.size(), o1)
            except:
                pass
            #assert symbolic_locals[insn].size() % 8 == 0 

     
        elif insn.opcode == OPCODE_AND:
            x = lookup_operand(insn.operands[0], symbolic_locals) #BitVecNumRef
            y = lookup_operand(insn.operands[1], symbolic_locals) #long
            symbolic_locals[insn] = (x & y)
        
        elif insn.opcode == OPCODE_OR:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)   
            symbolic_locals[insn] = (x | y)

        elif insn.opcode == OPCODE_XOR:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)
            if (type(y) == long): o2 = BitVecVal(y, 32)
            symbolic_locals[insn] = (x ^ y)
        
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


        elif insn.opcode == OPCODE_PHI:
            for i in range(insn.incoming_count):
                if (insn.get_incoming_block(i) == previous_bb):
                    o1 = lookup_operand(insn.get_incoming_value(i), symbolic_locals)
                    symbolic_locals[insn] = o1

        elif insn.opcode == OPCODE_SWITCH:
            entry = plog.next().llvmEntry
            x = False
            condition_str = str(entry.condition)
            for i in range(len(insn.operands)):
                #if i > 1 and i%2 == 0:
                #print (insn.operands[i])
                if x == True:
                    successor = insn.operands[i]
                    break
                elif i > 1 and i%2 == 0 and condition_str == str(insn.operands[i])[-4:-2]:
                    x = True
            r = 0

        elif insn.opcode == OPCODE_SELECT:
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
            #symbolic_locals[insn] = If(res,BitVecVal(1,1),BitVecVal(0,1))
            symbolic_locals[insn] = If(res, True, False)

        elif insn.opcode == OPCODE_BR:
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_BR)
            if (entry.condition == 111): #BR has condition 111 when used like JMP
                successor = insn.operands[0]
            else:
                print (insn)
                print (entry.condition)
                print (lookup_operand(insn.operands[0], symbolic_locals))
                if entry.condition == 0:
                    successor = insn.operands[1 + entry.condition]
                    path_condition.append(lookup_operand(insn.operands[0], symbolic_locals))
                elif entry.condition == 1:
                    successor = insn.operands[1 + entry.condition]
                    #path_condition.append(Not(lookup_operand(insn.operands[0], symbolic_locals)))
                    path_condition.append(lookup_operand(insn.operands[0], symbolic_locals))
            previous_bb = bb
            r = 0

        elif insn.opcode == OPCODE_RET:
            previous_bb = bb
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_RET)
            successor = None #Return should add sth to path_constraints?!
            try:
                r = insn.operands[0].s_ext_value
            except:
                for o in insn.operands:
                    print (o)

                try:
                    print (symbolic_locals[insn.operands[0]])
                    r = lookup_operand(insn.operands[0], symbolic_locals)
                except:
                    r = 0
        else:
            logger.error("insn:"+ str(insn))
            logger.error(bb_counter)
            logger.error(previous_bb)
            logger.error(bb)
            logger.error(entry)
            logger.error(plog.next().llvmEntry)
            logger.error(plog.next().llvmEntry)
            logger.error(plog.next().llvmEntry)
            logger.error(plog.next().llvmEntry)
            raise NotImplementedError("Pls implement this instr")

    return successor, r#insn.operands[0].s_ext_value#entry.value #lookup_operand(insn.operands[0],symbolic_locals)

def exec_function(mod, plog, func, *params): #chose *params over params = {}, as it's sorted
    print ("executed")
    symbolic_locals = {}
    bb = func.entry_basic_block
    for i in range(len(func.args)):
        if i == 0:
            symbolic_locals['env_ptr'] = func.args[0] # if we put params[i] here it crashs
        else:
            if i<(len(params)):# ((i > 0) and (i < len(params)): 
                 symbolic_locals[func.args[i]] = params[i]#BitVecVal(params[i]. params[i].type)               
    logger.debug("====== DEBUG: List of parameters: =======")

    for param in params:
        logger.debug(param)
    logger.debug("====== DEBUG: List of func.args: =======")
    for arg in func.args:
        logger.debug(arg)
        logger.debug("object:", arg)  
    logger.debug("====== DEBUG: List of Symbolic_Locals: =======")
    for symloc in symbolic_locals:
        logger.debug(symloc, symbolic_locals[symloc])
    while True:
        bb, retVal = exec_bb(mod, plog, bb, symbolic_locals)
        if not bb: break
    return retVal

mod = Module.from_bitcode(file(sys.argv[1]))
plog = plog_reader.read(sys.argv[2])

plog.next()

MAIN_FUNC_ADDR = 14728 #SAGE example pc = 0x104CC
initialize_to(plog, MAIN_FUNC_ADDR)

#ctr = 0
while True:
    #ctr += 1
    #if ctr == 10:
    #    break
    try:
        entry = plog.next()
    except StopIteration:
        break   
    check(entry.llvmEntry, LLVMType.LLVM_FN)
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    exec_function(mod, plog, f, f.args[0])

s = Solver()
file = open("symbll_results", "w")
file.write("Processed BBs:\n")
file.write(str(bb_counter))
file.write("Path Constraints:\n")
for con in path_condition:
    file.write(str(con)) 
    file.write("\n") 
file.close 

for i in range(len(path_condition)):
    s.add(path_condition[i])
    print (path_condition[i])
    print (s.check())
    if s.check() == sat:
        print (s.model())

print (initial_cpu_state)
print (symbolic_cpu)
print (cpu)

print ("run successful")