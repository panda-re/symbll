#!/usr/bin/env python

base_type_sizes = {
    'pointer': 8,           # PANDA only works on 64-bit hosts anyway
    'unsigned long': 8,
    'unsigned int': 4,
    'unsigned short': 2,
    'unsigned char': 1,
    'signed long': 8,
    'signed int': 4,
    'signed short': 2,
    'signed char': 1,
    'long': 8,
    'int': 4,
    'short': 2,
    'char': 1,
}

def sizeof(types, t):
    if t[0] in types:
        return types[t[0]][0]
    elif t[0] == 'array':
        return t[1] * sizeof(types, t[2])
    else:
        return base_type_sizes[t[0]]

def flatten(types, typ, offset=0, prefix=None):
    if prefix is None: prefix = []
    if typ[0] == 'array':
        for i in range(typ[1]):
            flatten(types, typ[2], offset+sizeof(types,typ[2])*i, prefix + ["[%d]" % i])
    elif typ[0] in types:
        # Struct. Iterate over members and flatten them
        struct_members = types[typ[0]][1]
        for memb in sorted(struct_members, key = lambda k: struct_members[k][0]):
            moff, mtyp = struct_members[memb]
            flatten(types, mtyp, offset+moff, prefix + [memb])
    else:
        # Must be a primitive type; print the whole thing
        # HACK: turn ".[" into "[" to make arrays prettier
        flat_name = '.'.join(prefix).replace(".[","[")
        print "'%s': %d," % (flat_name, offset)
        return

if __name__ == "__main__":
    import sys
    import importlib
    cpu = importlib.import_module(sys.argv[1])
    root_struct = sys.argv[2]
    print "%s_flat = {" % sys.argv[2]
    flatten(cpu.cpu_types, [root_struct], prefix=[root_struct])
    print "}"
