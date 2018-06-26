#!/usr/bin/env python
# ls trace bb = 2375721

#import IPython
from z3 import *
from llvm import *
from llvm.core import *
from collections import defaultdict
#import enum
#import sys
import plog_reader
#import i386 
#from i386_flat import *
import arm
from arm_flat import *
import logging
import pdb

logging.basicConfig(level=logging.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s')
logging.debug('This is a log message.')

logger = logging.getLogger()

offset_to_slot = {}
for slot in ARMCPU_flat.keys():
    offset = ARMCPU_flat[slot]
    offset_to_slot[offset] = slot
from plog_enum import LLVMType

guest_ram = {}

fs= [cpsr_read, helper_cpsr_read_llvm, cpsr_write, helper_cpsr_write_llvm, switch_mode, helper_cpsr_write_eret_llvm, helper_shl_cc_llvm, helper_set_user_reg_llvm, helper_get_user_reg_llvm, helper_vfp_get_fpscr_llvm, helper_shr_cc_llvm, helper_vfp_set_fpscr_llvm, helper_set_user_reg_llvm, raise_exception, helper_exception_with_syndrome_llvm]

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
    if entry.type != expected.value:
        print ("ERROR: misaligned log. Have",LLVMType(entry.type),"expected",expected)
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
    entry = plog.next().llvmEntry
    if bb_counter >= 10000:
        print (bb)
        print (entry)
    check(entry, LLVMType.BB)
    for insn in bb.instructions:
        if (bb_counter >= 10000):
            print("instr : " + str(insn))
        if insn.opcode == OPCODE_CALL:
            if insn.called_function.name.startswith('record'):
                pass
            '''
            elif insn.called_function.name.startswith('helper_le_stl_mmu_panda') or insn.called_function.name.startswith('helper_le_ldul_mmu_panda') or insn.called_function.name.startswith('helper_ret_ldub_mmu_panda') or insn.called_function.name.startswith('helper_ret_stb_mmu_panda'):
                entry = plog.next().llvmEntry
                symbolic_locals[insn] = entry.value
            '''
            elif insn.called_function.name.startswith('helper_le_ld') or insn.called_function.name.startswith('helper_ret_ld'):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_LOAD)
                assert entry.addr_type == 2
                asd = BitVecVal(entry.value, 32)## should be VALUE of course, once its generated
                host_ram[entry.address] = asd #asentry.addr_type #should be value of course but value is not implemented yet
                symbolic_locals[insn] = asd #entry.addr_type
            
            elif insn.called_function.name.startswith('helper_le_st') or insn.called_function.name.startswith('helper_ret_st'):
                entry = plog.next().llvmEntry
                check (entry, LLVMType.FUNC_CODE_INST_STORE)
                assert entry.addr_type == 2
                val = BitVecVal(entry.value, 32)
                host_ram[entry.address] = val
                symbolic_locals[insn] = val

            elif insn.called_function.name.startswith('helper_set_cp_reg_llvm'):
                # do not go in to fnction on LLVM side
                # skip 3 entries on plog side
                '''print (previous_bb)
                print (bb)
                print (insn)
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
                print ("and")
                print (plog.next())
                print ("some")
                print (plog.next())
                print ("more")
                print (plog.next())
                raise
                '''
                #pdb.set_trace()
                subfunction = insn.called_function
                parameters = [] # chose to use list over dict, as its sorted
                for i in range(len(insn.operands)):
                    if (i == insn.operand_count-1): #the last operand is the called function itself
                        continue
                    if (i == 0): #assuming that the first param always is the env ptr
                        parameters.append(env)
                    elif i > 0:
                        parameters.append(lookup_operand(insn.operands[i], symbolic_locals))
                
                retVal = exec_function(mod, plog, subfunction, *parameters)
                print ("to late")

            elif insn.called_function.name.startswith('helper_cpsr_read_llvm') 
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
              or insn.called_function.name.startswith('raise_exception') 
              or insn.called_function.name.startswith('helper_exception_with_syndrome_llvm'):
                #pdb.set_trace()
                symbolic_locals_preserved = symbolic_locals
                subfunction = insn.called_function
                parameters = [] # chose to use list over dict, as its sorted
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
                except AttributeError: #return may have type VOID - should be verified in an assertion
                    pass
                entry = plog.next().llvmEntry # fucntion call is recorded AFTER execution
            elif insn.called_function.name.startswith('llvm'):
                symbolic_locals[insn] = BitVec('x', insn.type.width)
                '''
                print ("This is where we are:")
                print ("insn:"+ str(insn))
                print (bb_counter)
                print (previous_bb)
                print (bb)
                print (entry)
                print (plog.next().llvmEntry)
                print (plog.next().llvmEntry)
                print (plog.next().llvmEntry)
                print (plog.next().llvmEntry)
                print ("STOP!")
                
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
                logger.debug("DEBUG: The sorted CPU at index ", lookup_operand(insn.operands[2],symbolic_locals), " is ", symbolic_locals[insn])
                #cast to flattened format in Z3 type
                symbolic_locals[insn] = arm.cpu_types['ARMCPU'][1]['env'][0] + symbolic_locals[insn]
                symbolic_locals[insn] = BitVecVal(symbolic_locals[insn], 64)
            else: #<-- should assert type somehow
                print (insn)
                for o in insn.operands:
                    print (o)
                    #print (insn.type.width) // POINTER TYPE has no attribute WIDTH
                    print (o.type)
                symbolic_locals[insn] = BitVecVal(lookup_operand(insn.operands[1], symbolic_locals), 64)
                #if insn.operands[0].type == "i8*":
                #    print ("hi")

            #else:
                #raise NotImplemented("This struct is undefined o.O what could it be?")
        
        elif (insn.opcode == OPCODE_INTTOPTR or
              insn.opcode == OPCODE_BITCAST):
            symbolic_locals[insn] = lookup_operand(insn.operands[0], symbolic_locals)
        
        elif insn.opcode == OPCODE_LOAD:
            entry = plog.next().llvmEntry
            '''
            if bb_counter >= 4906:
                print (entry)
                a = plog
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
                print (a.next())
            '''
                
            m = insn.get_metadata('host')
            if m and m.getOperand(0).getName() == 'rrupdate' or (m and m.getOperand(0).getName() == 'pcupdate'):
                logger.debug("DEBUG: ignoring instruction tagged as rrupdate/ pcupdate")
                pass
            else:
                check(entry, LLVMType.FUNC_CODE_INST_LOAD)
                addr = lookup_operand(insn.operands[0], symbolic_locals)
                cpu_slot = get_cpu_slot(addr)
                if cpu_slot:
                    (offs, slot_name) = cpu_slot
                    logger.debug("DEBUG: Found entry in CPU slot: %s" % slot_name)
                    try: #may fail for instruction type PointerVale (has no attribute width)
                        symbolic_locals[insn] = lookup_cpu(slot_name, insn.type.width, symbolic_cpu)
                    except:
                        symbolic_locals[insn] = lookup_cpu(slot_name, 64, symbolic_cpu)
                else:
                    logger.debug("DEBUG: Didn't find %#x in the CPU, retrieving from host RAM" % entry.address)
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
            symbolic_locals[insn] = If(res,BitVecVal(1,1),BitVecVal(0,1))
        
        elif insn.opcode == OPCODE_SEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            symbolic_locals[insn] = SignExt(insn.type.width-o1.size(), o1)
            #assert symbolic_locals[insn].size() % 8 == 0 
        
        elif insn.opcode == OPCODE_ZEXT:
            o1 = lookup_operand(insn.operands[0], symbolic_locals)
            if (type(o1) == long): o1 = BitVecVal(o1, 32) #type long needs special treatment, has no attribute size()
            symbolic_locals[insn] = ZeroExt(insn.type.width-o1.size(), o1)
            #assert symbolic_locals[insn].size() % 8 == 0 
        
        elif insn.opcode == OPCODE_SWITCH:
            x = False
            condition_str = str(entry.llvmEntry.condition)
            for i in range(len(insn.operands)):
                #if i > 1 and i%2 == 0:
                #print (insn.operands[i])
                if x == True:
                    successor = insn.operands[i]
                    break
                elif i > 1 and i%2 == 0 and condition_str == str(insn.operands[i])[-4:-2]:
                    x = True
        ''' 
            entry = plog.next().llvmEntry
            x = False
            for operand in insn.operands:
                if x == True:
                        successor = operand
                        x = False
                if (str(entry.condition) == str(operand)[-4:-2]):
                        x = True
        '''
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
            for i in range(insn.incoming_count):
                if (insn.get_incoming_block(i) == previous_bb):
                    o1 = lookup_operand(insn.get_incoming_value(i), symbolic_locals)
                    symbolic_locals[insn] = o1
     
        elif insn.opcode == OPCODE_AND:
            x = lookup_operand(insn.operands[0], symbolic_locals) #BitVecNumRef
            y = lookup_operand(insn.operands[1], symbolic_locals) #long
            symbolic_locals[insn] = (x & y)
        
        elif insn.opcode == OPCODE_OR:
            x = lookup_operand(insn.operands[0], symbolic_locals)
            y = lookup_operand(insn.operands[1], symbolic_locals)
            #if isinstance(insn.operands[0], Instruction) and isinstance(insn.operands[1], Instruction):
            #    if (y.size() == 64 and x.size() == 32):
            #        x = ZeroExt(32, x)
            #    if (x.size() == 64 and y.size() == 32):
            #        y = ZeroExt(32, y)    
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
            #if isinstance(insn.operands[0], Instruction) and isinstance(insn.operands[1], Instruction):
            #    if (y.size() == 64 and x.size() == 32):
            #        x = ZeroExt(32, x)
            #    if (x.size() == 64 and y.size() == 32):
            #        y = ZeroExt(32, y)    
            if (type(y) == long): o2 = BitVecVal(y, 32)
            symbolic_locals[insn] = (x ^ y)

        elif insn.opcode == OPCODE_RET:
            previous_bb = bb
            entry = plog.next().llvmEntry
            check(entry, LLVMType.FUNC_CODE_INST_RET)
            return_value = lookup_operand[insn.opcodes[0], symbolic_locals]
            successor = None #Return should add sth to path_constraints?!
        
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

    return successor, return_value#entry.value

def exec_function(mod, plog, func, *params): #chose *params over params = {}, as it's sorted
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
#logger.debug(plog)
#logger.debug(plog.next())
plog.next()

s = Solver()

while True:
    try:
        entry = plog.next()
    except StopIteration:
        break
    check(entry.llvmEntry, LLVMType.LLVM_FN)
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc))
    exec_function(mod, plog, f, f.args[0])
