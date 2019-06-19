#!/usr/bin/env python3
"""
Print and logging stuff is here.
"""
import sys
import threading

"""
Colors
"""
COLOR_NONE        = '\033[00m'
COLOR_BOLD        = "\033[01m"

COLOR_BLACK       = '\033[30m'
COLOR_DARK_RED    = '\033[31m'
COLOR_DARK_GREEN  = '\033[32m'
COLOR_BROWN       = '\033[33m'
COLOR_DARK_BLUE   = '\033[34m'
COLOR_DARK_PURPLE = '\033[35m'
COLOR_DARK_CYAN   = '\033[36m'
COLOR_GREY        = '\033[37m'

COLOR_DARK_GREY   = '\033[90m'
COLOR_RED         = '\033[91m'
COLOR_GREEN       = '\033[92m'
COLOR_YELLOW      = '\033[93m'
COLOR_BLUE        = '\033[94m'
COLOR_PURPLE      = '\033[95m'
COLOR_CYAN        = '\033[96m'
COLOR_WHITE       = '\033[97m'

loglock = threading.Lock()

"""
Thread-safe print
"""
def tprint(string='', color=COLOR_NONE, new_line=True, stdout=True, file=sys.stdout):
    lines = []
    lines.append(color+string+COLOR_NONE)
    if stdout:
        with loglock:
            for line in lines:
                print(line, end=('\n' if new_line else ''), file=file)
    return lines

def newline(stdout=True):
    lines = []
    lines.append('')
    if stdout:
        with loglock:
            for line in lines:
                print(line)
    return lines

"""
OK, INFO, WARN, ERR, QUESTION
"""
def show_marked(c, color='', *args, new_line=True, stdout=True, file=sys.stdout, offset=0):
    #lines = []
    #lines.append('%s%s%s%s%s' % (color, COLOR_BOLD, c, COLOR_NONE, str(string)))
    #if stdout:
    #    with loglock:
    #        for line in lines:
    #            print(line, end=('\n' if new_line else ''), file=file)
    #return lines
    start = '%s%s%s%s%s' % (color, COLOR_BOLD, c, COLOR_NONE, ' ' * offset)
    if stdout:
        print(start, *args, end='', file=file)
        if new_line:
            print('', file=file)        
        return None
    else:
        return start + ' ' + ' '.join(str(a) for a in args)
        


def ok(*args, new_line=True, stdout=True, offset=0):
    return show_marked('[+]', COLOR_GREEN, *args, new_line=new_line, stdout=stdout, offset=offset)
 
def info(*args, new_line=True, stdout=True, file=sys.stderr, offset=0):
    return show_marked('[.]', COLOR_BLUE, *args, new_line=new_line, stdout=stdout, offset=offset)
 
def warn(*args, new_line=True, stdout=True, file=sys.stderr, offset=0):
    return show_marked('[!]', COLOR_YELLOW, *args, new_line=new_line, stdout=stdout, offset=offset)
 
def err(*args, new_line=True, stdout=True, file=sys.stderr, offset=0):
    return show_marked('[-]', COLOR_RED, *args, new_line=new_line, stdout=stdout, offset=offset)
 
def question(*args, new_line=True, stdout=True, offset=0):
    return show_marked('[?]', COLOR_CYAN, *args, new_line=new_line, stdout=stdout, offset=offset)
 

"""
Debug functions
"""
def debug_command(string=''):
    if positive(config['debug.command'].value):
        show_marked('cmd.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_config(string=''):
    if positive(config['debug.config'].value):
        show_marked('cnf.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_mapping(string=''):
    if positive(config['debug.mapping'].value):
        show_marked('map.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_parsing(string=''):
    if positive(config['debug.parsing'].value):
        show_marked('prs.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_server(string=''):
    if positive(config['debug.server'].value):
        show_marked('srv.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_socket(string=''):
    if positive(config['debug.socket'].value):
        show_marked('sck.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_chunks(string=''):
    if positive(config['debug.chunks'].value):
        show_marked('cnk.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_tampering(string=''):
    if positive(config['debug.tampering'].value):
        show_marked('tpr.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_analysis(string=''):
    if positive(config['debug.analysis'].value):
        show_marked('anl.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_protocol(string=''):
    if positive(config['debug.protocol'].value):
        show_marked('prt.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)

def debug_flow(string=''):
    if positive(config['debug.flow'].value):
        show_marked('flw.', COLOR_DARK_GREY, COLOR_DARK_GREY+str(string)+COLOR_NONE)


