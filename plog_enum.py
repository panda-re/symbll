#!/usr/bin/env python

from enum import Enum

class LLVMType(Enum):
    FUNC_CODE_DECLAREBLOCKS    =  1  # DECLAREBLOCKS: [n]
    FUNC_CODE_INST_BINOP       =  2  # BINOP:      [opcode, $
    FUNC_CODE_INST_CAST        =  3  # CAST:       [opcode, $
    FUNC_CODE_INST_GEP         =  4  # GEP:        [n x oper$
    FUNC_CODE_INST_SELECT      =  5  # SELECT:     [ty, opva$
    FUNC_CODE_INST_EXTRACTELT  =  6  # EXTRACTELT: [opty, op$
    FUNC_CODE_INST_INSERTELT   =  7  # INSERTELT:  [ty, opva$
    FUNC_CODE_INST_SHUFFLEVEC  =  8  # SHUFFLEVEC: [ty, opva$
    FUNC_CODE_INST_CMP         =  9  # CMP:        [opty, op$
    FUNC_CODE_INST_RET         = 10  # RET:        [opty,opv$
    FUNC_CODE_INST_BR          = 11  # BR:         [bb#, bb#$
    FUNC_CODE_INST_SWITCH      = 12  # SWITCH:     [opty, op$
    FUNC_CODE_INST_INVOKE      = 13  # INVOKE:     [attr, fn$
    # 14 is unused.
    FUNC_CODE_INST_UNREACHABLE = 15  # UNREACHABLE
    FUNC_CODE_INST_PHI         = 16  # PHI:        [ty, val0$
    # 17 is unused.
    # 18 is unused.
    FUNC_CODE_INST_ALLOCA      = 19  # ALLOCA:     [instty, $
    FUNC_CODE_INST_LOAD        = 20  # LOAD:       [opty, op$
    # 21 is unused.
    # 22 is unused.
    FUNC_CODE_INST_VAARG       = 23  # VAARG:      [valistty$
    # This store code encodes the pointer type  rather than $
    # this is so information only available in the pointer t$
    # spaces) is retained.
    FUNC_CODE_INST_STORE       = 24  # STORE:      [ptrty,pt$
    # 25 is unused.
    FUNC_CODE_INST_EXTRACTVAL  = 26  # EXTRACTVAL: [n x oper$
    FUNC_CODE_INST_INSERTVAL   = 27  # INSERTVAL:  [n x oper$
    # fcmp/icmp returning Int1TY or vector of Int1Ty. Same a$
    # support legacy vicmp/vfcmp instructions.
    FUNC_CODE_INST_CMP2        = 28  # CMP2:       [opty, op$
    FUNC_CODE_INST_VSELECT     = 29  # VSELECT:    [ty,opval$
    FUNC_CODE_INST_INBOUNDS_GEP= 30  # INBOUNDS_GEP: [n x op$
    FUNC_CODE_INST_INDIRECTBR  = 31  # INDIRECTBR: [opty, op$
    # 32 is unused.
    FUNC_CODE_DEBUG_LOC_AGAIN  = 33  # DEBUG_LOC_AGAIN
    FUNC_CODE_INST_CALL        = 34  # CALL:       [attr, fn$
    FUNC_CODE_DEBUG_LOC        = 35  # DEBUG_LOC:  [Line,Col$
    FUNC_CODE_INST_FENCE       = 36  # FENCE: [ordering, syn$
    FUNC_CODE_INST_CMPXCHG     = 37  # CMPXCHG: [ptrty,ptr,c$
                                     #           ordering  s$
    FUNC_CODE_INST_ATOMICRMW   = 38  # ATOMICRMW: [ptrty,ptr$
                                     #             align  vo$
                                     #             ordering $
    FUNC_CODE_INST_RESUME      = 39  # RESUME:     [opval]
    FUNC_CODE_INST_LANDINGPAD  = 40  # LANDINGPAD: [ty,val,v$
    FUNC_CODE_INST_LOADATOMIC  = 41  # LOAD: [opty, op, alig$
                                     #        ordering  sync$
    FUNC_CODE_INST_STOREATOMIC = 42  # STORE: [ptrty,ptr,val$
                                     #         ordering  syn$
    BB = 43 
    LLVM_FN = 44 
    LLVM_EXCEPTION = 45


