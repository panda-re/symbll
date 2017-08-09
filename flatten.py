#!/usr/bin/env python

base_type_sizes = {
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
    if t in types:
        return types[t][0]
    else:
        return base_type_sizes[t]

def flatten(types, name, offset=0, prefix=None):
    if prefix is None: prefix = [name]
    if name not in types:
        # Must be a primitive type
        print "'%s': %d," % ('.'.join(prefix), offset)
        return
    struct_members = types[name][1]
    for memb in sorted(struct_members, key = lambda k: struct_members[k][0]):
        moff, typ = struct_members[memb]
        if typ[0] == 'array':
            for i in range(typ[1]):
                flatten(types, typ[2][0], offset+sizeof(types,typ[2][0])*i, prefix + ["%s[%d]" % (memb, i)])
        else:
            flatten(types, typ[0], offset+moff, prefix + [memb])

if __name__ == "__main__":
    import sys
    import importlib
    cpu = importlib.import_module(sys.argv[1])
    root_struct = cpu.cpu_name
    print "{"
    flatten(cpu.cpu_types, root_struct)
    print "}"
