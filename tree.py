import sys
import r2pipe


r2 = r2pipe.open(sys.argv[1])
r2.cmd("aa")
def dump_fun(name, depth=0):
    print('\t'*depth + name)
    r2.cmd('s %s' % name)
    r2.cmd('af %s' % name)
    for line in r2.cmdj('pdfj @%s' % name)['ops']:
        if line['type'] != 'call':
            continue
        nxt = line['disasm'].split(' ')[1]
        if 'sym.imp.' in nxt:
            continue
        if nxt == name:
            continue
        try:
            dump_fun(nxt, depth+1)
        except:
            continue

dump_fun('main')

