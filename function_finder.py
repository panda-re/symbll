
from llvm import *
from llvm.core import *
from collections import defaultdict
import enum
import sys
import plog_reader

list_defined_functions = []
list_declared_functions = []
list_functionpointer = []

bb_counter = 0

def exec_bb(mod, plog, bb):
    global bb_counter
    bb_counter = bb_counter+1
    print (bb_counter)
    '''
    if (bb_counter>4905):
        print (bb)
    '''
    for insn in bb.instructions:
        '''
        if (bb_counter):
            if (bb_counter>4905):
                print ("insn:")
                print (insn)
        '''
        if insn.opcode == OPCODE_CALL:
            '''
            if bb_counter > 4905:
                print (insn)
                print (insn.called_function.name)
                print (insn.called_function)
            '''
            function_name = insn.called_function.name
            if function_name.startswith('record'):
                pass
            else:
                if function_name.startswith('helper_set_cp_reg_llvm'):
                    # do not go in to fnction on LLVM side
                    # skip 3 entries on plog side
                    while True:
                        entry = plog.next()
                        #print (entry)
                        if entry.llvmEntry.type == 34: break
                    print (bb)

                else: 
                    if function_name:
                        try:
                            subfunction = insn.called_function
                            exec_function(mod, plog, subfunction) #breaks when it cannot get entry_bb, so if a function is only declared not defined
                            if function_name not in list_defined_functions:
                                list_defined_functions.append(function_name)
                        except:
                            plog.next()
                            if function_name not in list_declared_functions:
                               list_declared_functions.append(function_name)
                    else:
                        print (bb)
                        print (insn)
                        list_functionpointer.append(insn) #when a function does not have a name we save the instruction
                        print(plog.next())
                        print(plog.next())
                        print(plog.next())
                        print(plog.next())
                        print(plog.next())

        if insn.opcode == OPCODE_BR:
            while True:
                entry = plog.next()
                #print (entry)
                if entry.llvmEntry.type == 11: break

                    #print (insn)
                    #print (entry)
            if (entry.llvmEntry.condition == 111): #BR has condition 111 when used like JMP
                successor = insn.operands[0]

            elif (entry.llvmEntry.condition == 11): #BR has condition 111 when used like JMP
                successor = insn.operands[0]
            else:
                try:
                    successor = insn.operands[1 + entry.llvmEntry.condition]
                except:
                    successor = insn.operands[0] 

        
        elif insn.opcode == OPCODE_RET: #10
            while True:
                entry = plog.next()
                if entry.llvmEntry.type == 10:
                    #print (insn)
                    #print (entry)
                    break
            successor = None
            if bb_counter > 2000:
                print ("Comprehensive Function List:")
                print (list_defined_functions)
                print (list_declared_functions)
                print (list_functionpointer)
                file = open("function_finder_results", "w")
                file.write("Defined Functions:")
                for l in list_defined_functions:
                    file.write(l) 
                    file.write("\n") 
                file.write("Declared Functions:")
                for l in list_declared_functions:
                    file.write(l) 
                    file.write("\n")
                file.write("Function Pointers:")
                for l in list_functionpointer:
                    file.write(l) 
                    file.write("\n")
                file.close 
                raise
        
        elif insn.opcode == OPCODE_SWITCH:
            while True:
                entry = plog.next()
                if entry.llvmEntry.type == 12: break
                    #print (insn)
                    #print (entry)
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
                #i = i+1
            '''
                for operand in insn.operands:
                    print operand
                    if x == True:
                        successor = operand
                        break
                    elif condition_str == str(operand)[-4:-2]:
                        x = True
            '''
            
        else:
            pass
            #print (insn)
    return successor

def exec_function(mod, plog, func):
    bb = func.entry_basic_block
    print (func.name)
    while True:
        bb = exec_bb(mod, plog, bb)
        if not bb: break

mod = Module.from_bitcode(file(sys.argv[1]))
plog = plog_reader.read(sys.argv[2])

plog.next()

while True:
    try:
        entry = plog.next()
    except StopIteration:
        print ("Comprehensive Function List:")
        print (list_defined_functions)
        break
    f = mod.get_function_named('tcg-llvm-tb-%d-%x' % (entry.llvmEntry.tb_num, entry.pc)) 
    exec_function(mod, plog, f)

print ("Comprehensive Function List:")
print (list_defined_functions)
print (list_declared_functions)
print (list_functionpointer)

file = open("function_finder_results", "w")
file.write("Defined Functions:")
for l in list_defined_functions:
    file.write(l) 
    file.write(" \n") 
file.write("Declared Functions:")
for l in list_declared_functions:
    file.write() 
file.write("Function Pointers:")
for l in list_functionpointer:
    file.write(l) 
file.close 

'''
enum{
declare %struct.AddressSpace* @cpu_get_address_space(%struct.CPUState*, i32) #7
declare %struct._GSList* @object_class_get_list(i8*, i1 zeroext) #7
declare %struct._GSList* @g_slist_sort(%struct._GSList*, i32 (i8*, i8*)*) #7
declare %struct.CPUState* @cpu_generic_init(i8*, i8*) #7
declare %struct.ObjectClass* @object_class_dynamic_cast_assert(%struct.ObjectClass*, i8*, i8*, i32, i8*) #7
declare %struct.ObjectClass* @object_get_class(%struct.Object*) #7
declare %struct._GList* @g_hash_table_get_keys(%struct._GHashTable*) #7
declare %struct._GList* @g_list_sort(%struct._GList*, i32 (i8*, i8*)*) #7
declare %struct._panda_cb_list* @panda_cb_list_next(%struct._panda_cb_list*) #7
declare %struct.Object* @object_dynamic_cast_assert(%struct.Object*, i8*, i8*, i32, i8*) #7

declare void @recordLoad(i8*, i64, i64)
declare void @recordStore(i8*, i64, i64)
declare void @recordCall(i64)
declare void @recordSelect(i8)
declare void @recordSwitch(i64)
declare void @recordBranch(i8)
declare void @recordStartBB(i8*, i64)
declare void @recordBB(i8*, i32)
declare void @recordReturn()

declare i32 @helper_le_ldul_mmu_panda(%struct.CPUARMState*, i32, i32, i64)
declare void @helper_le_stl_mmu_panda(%struct.CPUARMState*, i32, i32, i32, i64)
declare i32 @helper_cpsr_read(%struct.CPUARMState*)
declare void @helper_cpsr_write(%struct.CPUARMState*, i32, i32)
declare void @helper_cpsr_write_eret(%struct.CPUARMState*, i32)
declare i16 @helper_le_lduw_mmu_panda(%struct.CPUARMState*, i32, i32, i64)
declare i8 @helper_ret_ldub_mmu_panda(%struct.CPUARMState*, i32, i32, i64)
declare void @helper_le_stw_mmu_panda(%struct.CPUARMState*, i32, i16, i32, i64)
declare void @helper_ret_stb_mmu_panda(%struct.CPUARMState*, i32, i8, i32, i64)
declare void @helper_set_cp_reg(%struct.CPUARMState*, i64, i32)
declare i32 @helper_shl_cc(%struct.CPUARMState*, i32, i32)
declare void @helper_set_user_reg(%struct.CPUARMState*, i32, i32)
declare void @helper_exception_with_syndrome(%struct.CPUARMState*, i32, i32, i32)
declare i32 @helper_get_user_reg(%struct.CPUARMState*, i32)
declare void @helper_le_stq_mmu_panda(%struct.CPUARMState*, i32, i64, i32, i64)
declare i32 @helper_vfp_get_fpscr(%struct.CPUARMState*)
declare i32 @helper_shr_cc(%struct.CPUARMState*, i32, i32)
declare i64 @helper_le_ldq_mmu_panda(%struct.CPUARMState*, i32, i32, i64)
declare void @helper_vfp_set_fpscr(%struct.CPUARMState*, i32)
declare void @helper_ret_stb_mmu(%struct.CPUARMState*, i32, i8 zeroext, i32, i64) #7
declare zeroext i16 @helper_le_ldw_cmmu(%struct.CPUARMState*, i32, i32, i64) #7
declare i32 @helper_le_ldl_cmmu(%struct.CPUARMState*, i32, i32, i64) #7

declare i64 @llvm.ctlz.i64(i64, i1) #6
declare i32 @llvm.ctlz.i32(i32, i1) #6
declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64) #6
declare { i32, i1 } @llvm.uadd.with.overflow.i32(i32, i32) #6
declare void @llvm.lifetime.start(i64, i8* nocapture) #10
declare void @llvm.lifetime.end(i64, i8* nocapture) #10
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture, i8* nocapture, i64, i32, i1) #10
declare i8* @llvm.returnaddress(i32) #6
declare i32 @llvm.cttz.i32(i32, i1) #6
declare { i16, i1 } @llvm.uadd.with.overflow.i16(i16, i16) #6
declare { i8, i1 } @llvm.uadd.with.overflow.i8(i8, i8) #6
declare i32 @llvm.bswap.i32(i32) #6
declare void @llvm.memset.p0i8.i64(i8* nocapture, i8, i64, i32, i1) #10

declare i32 @qemu_log(i8*, ...) #7
declare i64 @qemu_clock_get_ns(i32) #7
declare void @timer_del(%struct.QEMUTimer*) #7
declare void @qemu_set_irq(%struct.IRQState*, i32) #7
declare void @timer_mod(%struct.QEMUTimer*, i64) #7

declare void @cpu_watchpoint_remove_by_ref(%struct.CPUState*, %struct.CPUWatchpoint*) #7
declare i32 @cpu_watchpoint_insert(%struct.CPUState*, i64, i64, i32, %struct.CPUWatchpoint**) #7
declare void @cpu_watchpoint_remove_all(%struct.CPUState*, i32) #7
declare void @cpu_breakpoint_remove_by_ref(%struct.CPUState*, %struct.CPUBreakpoint*) #7
declare i32 @cpu_breakpoint_insert(%struct.CPUState*, i64, i32, %struct.CPUBreakpoint**) #7
declare void @cpu_breakpoint_remove_all(%struct.CPUState*, i32) #7

declare void @gdb_register_coprocessor(%struct.CPUState*, i32 (%struct.CPUARMState*, i8*, i32)*, i32 (%struct.CPUARMState*, i8*, i32)*, i32, i8*, i32) #7

declare void @g_slist_foreach(%struct._GSList*, void (i8*, i8*)*, i8*) #7
declare void @g_slist_free(%struct._GSList*) #7

declare void @armv7m_nvic_set_pending(i8*, i32) #7
declare void @armv7m_nvic_complete_irq(i8*, i32) #7
declare i32 @armv7m_nvic_acknowledge_irq(i8*) #7
declare void @arm_handle_psci_call(%struct.ARMCPU*) #7
declare zeroext i1 @arm_is_psci_call(%struct.ARMCPU*, i32) #7
declare i32 @do_arm_semihosting(%struct.CPUARMState*) #7

declare i64 @crc32(i64, i8*, i32) #7
declare i32 @crc32c(i32, i8*, i32) #7

declare void @stl_phys(%struct.AddressSpace*, i64, i32) #7
declare i32 @ldl_phys(%struct.AddressSpace*, i64) #7

declare i32 @address_space_ldl_be(%struct.AddressSpace*, i64, i32, i32*) #7
declare i32 @address_space_ldl_le(%struct.AddressSpace*, i64, i32, i32*) #7
declare i64 @address_space_ldq_be(%struct.AddressSpace*, i64, i32, i32*) #7
declare i64 @address_space_ldq_le(%struct.AddressSpace*, i64, i32, i32*) #7
declare i32 @address_space_ldl(%struct.AddressSpace*, i64, i32, i32*) #7

declare void @tlb_flush_page_by_mmuidx(%struct.CPUState*, i32, ...) #7
declare void @tlb_flush_by_mmuidx(%struct.CPUState*, ...) #7
declare void @tlb_flush_page(%struct.CPUState*, i32) #7
declare void @tlb_flush(%struct.CPUState*) #7
declare void @tlb_set_page_with_attrs(%struct.CPUState*, i32, i64, i32, i32, i32, i32) #7

declare noalias i8* @g_memdup(i8*, i32) #7
declare i32 @__fprintf_chk(%struct._IO_FILE*, i32, i8*, ...) #7
declare i32 @g_hash_table_insert(%struct._GHashTable*, i8*, i8*) #7
declare i8* @object_class_get_name(%struct.ObjectClass*) #7
declare noalias i8* @g_malloc0(i64) #7
declare noalias i8* @g_strndup(i8*, i64) #7
declare i64 @strlen(i8* nocapture) #11
declare noalias i8* @g_strdup(i8*) #7
declare void @g_free(i8*) #7
declare i32 @strcmp(i8* nocapture, i8* nocapture) #11
declare i32 @gettimeofday(%struct.timeval*, %struct.timezone*) #12
declare i32 @getpid() #12
declare zeroext i1 @cpu_restore_state(%struct.CPUState*, i64) #7
declare void @cpu_loop_exit(%struct.CPUState*) #8
declare void @__assert_fail(i8*, i8*, i32, i8*) #4
declare void @g_assertion_message_expr(i8*, i8*, i32, i8*, i8*) #8
declare void @g_list_foreach(%struct._GList*, void (i8*, i8*)*, i8*) #7
declare noalias i8* @g_malloc_n(i64, i64) #7
declare void @g_list_free(%struct._GList*) #7
declare void @abort() #4
declare i8* @g_hash_table_lookup(%struct._GHashTable*, i8*) #7
declare zeroext i1 @semihosting_enabled() #7
declare void @cpu_abort(%struct.CPUState*, i8*, ...) #8
'''