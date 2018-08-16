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


# TO DO :
## Make concrete CPU the right format
## Can we remove SOTREs to CPU registers?
## is env ptr == concrete cpu?! - damn it's late
## we do not zext/sext some values - does this cause any trouble?

logging.basicConfig(level=logging.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

offset_to_slot = {}
for slot in ARMCPU_flat.keys():
    offset = ARMCPU_flat[slot]
    offset_to_slot[offset] = slot
'''
## TO DO ##
##model this function! ##

def handleCTLZS(operand):
    o1 = lookup_operand(operand, symbolic_locals)
    for i in o1.size():
        if operand[:i] == 0: 
            return BitvecVal(i, o1.size()) 
'''


initial_cpu_state = {}
symbolic_cpu = {}
concrete_cpu = {}
sorted_cpu = sorted(arm.cpu_types['CPUARMState'][1].items(), key=lambda item: item[1][0]) #unflattened ARM CPU but sorted so we can access via index as in GetElementPointer

path_condition = []

bb_counter = 0
previous_bb = 0 # crucial for LLVM SELECT instruction

CONST_REGISTER_SIZE = 64
env = BitVec('env', CONST_REGISTER_SIZE)


def initialize_to(plog, addr): #fast forward the plog to the desired memory address
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

def check(entry, expected): # verifies that plog and LLVM are in sync
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
       # logger.info("DEBUG:",LLVMType(entry.type),"==",str(expected)) # TO DO: Why does this logger throw an error

def lookup_operand(operand, symbolic_locals): # gets operand from symbolic_local storage 
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

def get_cpu_slot(addr): # returns the according register name to a given offset
    try:
        # z3.substitute replaces manipulates addr by replacing all occurences of env by the envptr address
        # addr has format (env+x)
        # env is replaced by env's address
        # (3340 + x) is received
        # simplify solves this
        offs = simplify(substitute(addr, (env, BitVecVal(arm.cpu_types['ARMCPU'][1]['env'][0], 64)))).as_signed_long()
        if (offs in offset_to_slot):# 
            return (offs, offset_to_slot[offs]) #return e.g. (33420, registername)
    except:
        raise

def exec_bb(mod, plog, bb, symbolic_locals):
    global bb_counter 
    global previous_bb
    global initial_cpu_state
    logger.warning(bb_counter)
    bb_counter = bb_counter + 1
    print (bb_counter)
    logger.debug("====== DEBUG: BB dump ======")
    print(bb)
    entry = plog.next().llvmEntry
    #print ("entry:")
    #print (entry.type)
    #if bb_counter >= 10000:
    #    print (bb)
    #    print (entry)
    check(entry, LLVMType.BB)
    for insn in bb.instructions:
        #if (bb_counter >= 10000):
        print("instr : " + str(insn))

##########################
##########################
######## Memory ##########
######## Access ##########
##########################
##########################

        if insn.opcode == OPCODE_CALL:
            if insn.called_function.name.startswith('record'):
                pass

            # handle LOAD helpers and STORE helpers
            # we can handle LOAD and STORE the SAME way
            # The plog entry is the single point of truth for the LOADED/STORED value
            # we may want to keep host_ram for assertion though
            elif (insn.called_function.name.startswith('helper_le_ld') or insn.called_function.name.startswith('helper_ret_ld')):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_LOAD)
                assert entry.addr_type == 2
                #plog entry LOAD (type 20) has field VALUE now
                #Thanks to Ray Wang
                #val = BitVecVal(entry.value, entry.num_bytes*8)
                #host_ram[entry.address] = val     
                #symbolic_locals[insn] = val
                if (entry.address >= 536871373 and entry.address <= 536871473):
                    #try:# not applicable because host_ram always returnes SOMETHING
                    #    symbolic_locals[insn] = host_ram[entry.address] # if already in host_ram take from there
                    #except:
                    symbolic_locals[insn] = BitVec(entry.address, entry.num_bytes*8) # otherwise take create new symbolic value
                    host_ram[entry.address] = BitVec(entry.address, entry.num_bytes*8)
                    global end # end loop on first hit
                    end = True
                    #path_condition.append(If(BitVec(entry.address, entry.num_bytes*8) == BitVecVal(entry.value, entry.num_bytes*8),True, False))
                    #pdb.set_trace()
                    print (entry)
                    #print (host_ram[entry.address])
                    #print (host_ram[entry.address].sort())
                    #s = Solver()
                    #s.add(If(symbolic_locals[insn] == entry.value, True, False))
                    #print (s.check())
                    #print (s.model())

                else:
                    symbolic_locals[insn] = BitVecVal(entry.value, entry.num_bytes*8) # if load is not in range of interest create concrete value
                #print (entry)



            # handle STORE helpers 
            elif insn.called_function.name.startswith('helper_le_st') or insn.called_function.name.startswith('helper_ret_st'):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_STORE)
                assert entry.addr_type == 2
                val = BitVecVal(entry.value, entry.num_bytes*8)
                host_ram[entry.address] = val
                symbolic_locals[insn] = val
            
            # this function operates on function pointers!
            #elif insn.called_function.name.startswith('helper_set_cp_reg_llvm'):
                # contains function pointer
                # do not go in to fnction on LLVM side
                # skip 5 entries on plog side

                #Function Pointer/ Dynamic Function calls are now supported
                #Thanks to Ray Wang
                #pdb.set_trace()

            #    print ("FN")
            #    print (plog.next)
            #    print ("BB")
            #   print (plog.next()) #bb
            #    print ("LOAD")
            #    print (plog.next())
            #    print ("RETURN")
            #    print (plog.next())
            #    print ("CALL")
            #    print (plog.next())


            #handle functions that do not expect the env ptr as parameter
            elif (insn.called_function.name.startswith('helper_udiv_llvm')
              or insn.called_function.name.startswith('helper_rbit_llvm')):
                #pdb.set_trace()
                symbolic_locals_preserved = symbolic_locals
                subfunction = insn.called_function
                parameters = [] # chose to use list over dict, becaue list is sorted
                for i in range(len(insn.operands)):
                    if (i == insn.operand_count-1): #the last operand is the called function itself
                        continue
                    parameters.append(lookup_operand(insn.operands[i], symbolic_locals))
                retVal = exec_function2(mod, plog, subfunction, *parameters)
                symbolic_locals = symbolic_locals_preserved
                try: 
                    symbolic_locals[insn] = BitVecVal(retVal, insn.type.width)
                except:
                    try:
                        symbolic_locals[insn] = retVal
                    except AttributeError: #return may have type VOID - should be verified in an assertion
                        pass
                entry = plog.next().llvmEntry # fucntion call is recorded AFTER execution
             

            # handle helper functions
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
            
            # These functions are LLVM intrinsics and have to be symbolically modelled individually
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
                # LOAD can access MEMORY or CPU Registers
                # Validate if accessed address belongs to CPU register (IF)
                # Otherwise handle as RAM access (ELSE)
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    logger.debug("DEBUG: Found entry in CPU slot: %s" % slot_name)
                    global initial_cpu_state
                    # record as initial cpu state if CPU register is accessed the very first time
                    if slot_name not in initial_cpu_state:
                        initial_cpu_state[slot_name] = entry.value #holding the initial state so it can later be exported/ reused for subsequent runs
                    
                    # save value as both, concrete and symbolic
                    concrete_cpu[slot_name] = BitVecVal(entry.value, insn.type.width)
                    symbolic_cpu[slot_name] = BitVec(slot_name,insn.type.width) #holding the current state, so it's accessable at any time
                    # make part of the exectution symbolic
                    # and the other part concrete                    
                    if offs == 0:
                        symbolic_locals[insn] = symbolic_cpu[slot_name]
                    else:
                        symbolic_locals[insn] = concrete_cpu[slot_name]
                        # To Do : concre value should be  the correct type - otherwise causes issues
                else:
                    logger.debug("DEBUG: Didn't find %#x in the CPU, retrieving from host RAM" % entry.address)
                    if (entry.address >= 536871373 and entry.address <= 536871473):
                        try:
                            symbolic_locals[insn] = host_ram[entry.address]
                        except:
                            symbolic_locals[insn] = BitVec(entry.address, insn.type.width)
                    else:
                        symbolic_locals[insn] = BitVecVal(entry.value, insn.type.width)

                    global end
                    end = True

        elif insn.opcode == OPCODE_STORE:
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate' or (m and m.getOperand(0).getName() == 'pcupdate'):
                logger.debug("DEBUG: ignoring instruction tagged as rrupdate/ pcupdate")
                pass
            else:
                #pdb.set_trace()
                entry = plog.next().llvmEntry
                check(entry, LLVMType.FUNC_CODE_INST_STORE)
                #assert entry.address % 8 == 0 # this doesnt seem to work ... 
                addr = BitVecVal(entry.address, CONST_REGISTER_SIZE) # shorter would cut the address off
                
                cpu_slot = get_cpu_slot(addr)

                # STORE can access MEMORY or CPU Registers
                # Validate if accessed address belongs to CPU register (IF)
                # Otherwise handle as RAM access (ELSE)
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    logger.debug("DEBUG: Found entry in CPU slot: %s" % slot_name)
                    symbolic_cpu[slot_name] = lookup_operand(insn.operands[0], symbolic_locals)     
                else:
                    host_ram[entry.address] = lookup_operand(insn.operands[0], symbolic_locals) 

        elif insn.opcode == OPCODE_ALLOCA:
            # memory allocation does not affect us, as we model our owhn shadow host_ram
            pass
        
        elif insn.opcode == OPCODE_PTRTOINT:
            # catch environment pointer manipulation
            if insn.operands[0] == symbolic_locals['env_ptr']:
                symbolic_locals[insn] = env 
            else:
                symbolic_locals[insn] = lookup_operand(insn.operands[0], symbolic_locals)
        
        elif (insn.opcode == OPCODE_INTTOPTR or
              insn.opcode == OPCODE_BITCAST):
            symbolic_locals[insn] = lookup_operand(insn.operands[0], symbolic_locals)

        elif insn.opcode == OPCODE_GETELEMENTPTR:
            if insn.operands[0] == symbolic_locals['env_ptr']:
                symbolic_locals[insn] = sorted_cpu[lookup_operand(insn.operands[2], symbolic_locals)][1][0]
                logger.debug("DEBUG: The sorted CPU at index ", lookup_operand(insn.operands[2],symbolic_locals), " is ", symbolic_locals[insn])
                #cast to flattened format in Z3 type
                symbolic_locals[insn] = arm.cpu_types['ARMCPU'][1]['env'][0] + symbolic_locals[insn]
                symbolic_locals[insn] = BitVecVal(symbolic_locals[insn], 64)
            else: #<-- should assert type somehow
                #symbolic_locals[insn] = BitVecVal(lookup_operand(insn.operands[1], symbolic_locals), 64)
                raise NotImplemented("This struct is undefined o.O what could it be?")
        



##########################
##########################
####### Arithmetic  ######
####### Operations #######
##########################
##########################



        elif insn.opcode == OPCODE_UDIV:
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate':
                pass
            else: 
                insn.operands[0]
                x = lookup_operand(insn.operands[0], symbolic_locals) 

                insn.operands[1]
                y = lookup_operand(insn.operands[1], symbolic_locals)
                symbolic_locals[insn] = (x/y)

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
                o1 = lookup_operand(insn.operands[0], symbolic_locals) 
                o2 = lookup_operand(insn.operands[1], symbolic_locals)
                #if type(o1)==long: o1=BitVecVal(o1,insn.type.width)
                #if type(o2)==long: o2=BitVecVal(o2,insn.type.width)
                symbolic_locals[insn] = (o1-o2)             

##########################
##########################
####### Boolean  #########
###### Operations ########
##########################
##########################

        elif insn.opcode == OPCODE_SEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            #if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            symbolic_locals[insn] = SignExt(insn.type.width-o1.size(), o1)
            #assert symbolic_locals[insn].size() % 8 == 0 
        
        elif insn.opcode == OPCODE_ZEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            #if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            #if (type(o1) == Bool): o1 = BitVecVal(o1, 1)
            try:
                symbolic_locals[insn] = ZeroExt(insn.type.width-o1.size(), o1) #o1 of type "ISNTANCE" cannot be ZEXT'ed. But we do not need this either.
                #symbolic_locals[insn] = ZeroExt(insn.type.width-o1.type.width, o1)
            except:
                pass
            #assert symbolic_locals[insn].size() % 8 == 0 
     
        elif insn.opcode == OPCODE_AND:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)
            symbolic_locals[insn] = (x & y)
        
        elif insn.opcode == OPCODE_OR:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)   
            symbolic_locals[insn] = (x | y)

        elif insn.opcode == OPCODE_XOR:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)
            symbolic_locals[insn] = (x ^ y)
        
        elif insn.opcode == OPCODE_TRUNC:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            #if (type(o1) == long): o1 = BitVecVal(o1, insn.type.width)
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

##########################
##########################
####### Control ##########
######### Flow ###########
##########################
##########################

        elif insn.opcode == OPCODE_PHI:
            # leverage api
            for i in range(insn.incoming_count):
                if (insn.get_incoming_block(i) == previous_bb):
                    o1 = lookup_operand(insn.get_incoming_value(i), symbolic_locals)
                    symbolic_locals[insn] = o1

        elif insn.opcode == OPCODE_SWITCH:
            # no api
            # evaluate every second operand
            # when case is found, succedd to subsequent operand
            entry = plog.next().llvmEntry
            x = False
            condition_str = str(entry.condition)
            for i in range(len(insn.operands)):
                if x == True:
                    successor = insn.operands[i]
                    break
                elif i > 1 and i%2 == 0 and condition_str == str(insn.operands[i])[-4:-2]:
                    x = True
            r = 0

        elif insn.opcode == OPCODE_SELECT:
            entry = plog.next().llvmEntry
            symbolic_locals[insn] = If(lookup_operand(insn.operands[0], symbolic_locals), lookup_operand(insn.operands[1], symbolic_locals), lookup_operand(insn.operands[2], symbolic_locals))
            #symbolic_locals[insn] = If(lookup_operand(insn.operands[0], symbolic_locals), True, False)
            
            s = Solver()
            s.add(If(lookup_operand(insn.operands[0], symbolic_locals), True, False))
            if s.check()==sat:
                operand = lookup_operand(insn.operands[0], symbolic_locals)
                path_condition.append(operand)
                print ("1")
                print (operand)
            else:
                operand = lookup_operand(insn.operands[0], symbolic_locals)
                inverted_operand = Not(operand)
                path_condition.append(inverted_operand)
                print ("0")
                print (inverted_operand)
            print (len(path_condition))

            #print ("AAAAAAA")
            #print (z)
            #if (entry.condition == 1):
            #    symbolic_locals[insn] = lookup_operand(insn.operands[1], symbolic_locals)
            #else:
            #    symbolic_locals[insn] = lookup_operand(insn.operands[2], symbolic_locals)
        
        elif insn.opcode == OPCODE_ICMP:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            o2 = lookup_operand(insn.operands[1], symbolic_locals)
            #if type(o1)==long: o1=BitVecVal(o1,insn.type.width)
            #if type(o2)==long: o2=BitVecVal(o2,insn.type.width)
            print (o1)
            print (o2)
            print (type(o1))
            if insn.predicate == ICMP_NE:
                res = (o1 != o2)
                print(res)
            elif insn.predicate == ICMP_EQ:
                res = (o1 == o2)
            elif insn.predicate == ICMP_UGT:
                res = (o1 > o2)
            elif insn.predicate == ICMP_SGT:
                res = (o1 > o2)
            elif insn.predicate == ICMP_UGE:
                #if bb_counter ==47: pdb.set_trace()
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
            print( symbolic_locals[insn] )

        elif insn.opcode == OPCODE_BR:
            # Branches are when path constraints are collected!!!
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_BR)
            # BRANCHES have 3 different conditions:
            # True (1)
            # False(0)
            # JUMP (111)
            if (entry.condition == 111): #BR has condition 111 when used like JMP
                successor = insn.operands[0]

            elif entry.condition == 0:
            # False case: add neglected condition    
                successor = insn.operands[1 + entry.condition]
                operand = lookup_operand(insn.operands[0], symbolic_locals)
                inverted_operand = Not(operand)
                path_condition.append(inverted_operand)
                print ("00000")
                print (inverted_operand)
            elif entry.condition == 1:
            # True case: add condition
                successor = insn.operands[1 + entry.condition]
                operand = lookup_operand(insn.operands[0], symbolic_locals)
                path_condition.append(operand)
                print ("11111")
                print (operand)
            previous_bb = bb
            r = 0

        elif insn.opcode == OPCODE_RET:
            previous_bb = bb
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_RET)
            successor = None 
            try:
                r = insn.operands[0].s_ext_value
            except:
                for o in insn.operands:
                    print (o)

                try:
                    #print (symbolic_locals[insn.operands[0]])
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
            print (insn)
            raise NotImplementedError("Pls implement this instr")

    return successor, r

def exec_function2(mod, plog, func, *params): #chose *params over params = {}, as it's sorted
# crucial for functions that do not work on the environment pointer!
    symbolic_locals = {}
    bb = func.entry_basic_block
    for i in range(len(func.args)):
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


def exec_function(mod, plog, func, *params): #chose *params over params = {}, as it's sorted
    symbolic_locals = {}
    bb = func.entry_basic_block
    for i in range(len(func.args)):
        if i == 0:
            symbolic_locals['env_ptr'] = func.args[0] # if we put params[i] here it crashs
        else:
            if i<(len(params)):
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

# Comment in the following two lines
# in order to fast forward the plog to your function of interest

#MAIN_FUNC_ADDR = 14728 #SAGE example pc = 0x104CC
#initialize_to(plog, MAIN_FUNC_ADDR)
end = False
ctr = 0
while end == False:
    #ctr += 1
    #if ctr == 150:
    #    break
    try:
        entry = plog.next()
    except StopIteration:
        break   
    check(entry.llvmEntry, LLVMType.LLVM_FN)
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    exec_function(mod, plog, f, f.args[0])

print ("INFO: The File was successfully parsed!")
print ("The initial CPU state was recorded as:")
print (initial_cpu_state)

##########################
##########################
### Save collecete PCs ###
##########################
##########################

s = Solver()
file = open("symbll_results\n", "w")
file.write("Processed BBs:\n")
file.write(str(bb_counter))
file.write("Initial CPU state:\n")
file.write(str(initial_cpu_state))
file.write("Path Constraints:\n")
for con in path_condition:
    file.write(str(con)) 
    file.write("\n") 
file.close 

##########################
##########################
####print SMT results ####
##########################
##########################

s.reset()

cmps = Solver()
cmps.add(BitVecVal("10",32)<11)
cmps.check()
cmpm = cmps.model()

for i in range(len(path_condition)):
    s.add(path_condition[i])
    #print (path_condition[i])
    #print (s.check())
    if s.check() == sat:
        #if s.model != cmpm:
        print (path_condition[i])
        print (s.check())
        print(s.model())

##########################
##########################
###generate new inputs####
##########################
##########################

#pdb.set_trace()
if s.check() != sat:
    print ("ERROR: try to collect satisfiable constraints only!")
else:
    print("INFO: Generating new inputs...")
    s.reset()
    new_inputs=[]

    for i in range(len(path_condition)):
        global new_inputs
        s.push()
        s.add(Not(path_condition[i]))
        if s.check() == sat:
           new_inputs.append(s.model())
        s.pop()
        s.add(path_condition[i])
        s.check()
    print (new_inputs)

#print (path_condition[33])
#print (path_condition[34])
#print (path_condition[35])
