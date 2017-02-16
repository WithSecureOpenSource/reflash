#! /usr/bin/env python

#
# Tool for creating a Replay database
#
#


import glob
import sys
import os
import sqlite3
import base64
import pyamf
import re
import yara
import binascii
import tempfile
import shutil
from pyamf import amf3
from optparse import OptionParser



def insert_stackval(c, value_id, event_id, t, data, parent, level):
    datatype = type(data)
    bits = ""
    
    # XXX: bug in pyamf3 decoder?
    if level > 10:
        #print "Warning: AMF object recursion level exceeded"
        return value_id
    
    if datatype == pyamf.ASObject:
        amf_type = "Object"
        bits = "[]"
    elif datatype == pyamf.MixedArray:
        amf_type = "Object"
        bits = "[]"
    elif datatype == list:
        amf_type = "Array"
        bits = "[]"
    elif datatype == pyamf.amf3.ObjectVector:
        amf_type = "Vector"
        bits = "[]"
    elif datatype == pyamf.amf3.ByteArray:
        amf_type = "ByteArray"
        try:
            bits = data.read()
        except:
            bits = ""
    elif datatype == unicode:
        amf_type = "String"
        bits = data
    elif datatype == str:
        amf_type = "String"
        bits = data
    elif datatype == int:
        amf_type = "Integer"
        bits = str(data)
    elif datatype == float:
        amf_type = "Number"
        bits = str(data)
    elif datatype == bool:
        amf_type = "Boolean"
        bits = str(data)
    else:
        amf_type = "Undefined"
        bits = repr(data)
        if bits == "pyamf.Undefined":
            bits = ""

    c.execute("INSERT INTO stack_values (value_id, stack_event, type, amf_type, data, parent) VALUES (?,?,?,?,?,?);",
        (value_id, event_id, t, amf_type, bits, parent))
    
    parent_id = value_id   
    value_id  = value_id + 1
    
    if amf_type == "Array":
        level = level + 1
        for d in data:
            value_id = insert_stackval(c, value_id, event_id, t, d, parent_id, level)
            
    if amf_type == "Vector":
        level = level + 1
        max = 256
        i = 0
        for d in data:
            if i >= max:
                print "Warning: max vector size exceeded (%d/%d)" % (max, len(data))
                break
            value_id = insert_stackval(c, value_id, event_id, t, d, parent_id, level)
            i = i + 1
            
    if amf_type == "Object":
        level = level + 1
        for k,v in data.iteritems():
            value_id = insert_stackval(c, value_id, event_id, t, k, parent_id, level)
            value_id = insert_stackval(c, value_id, event_id, t, v, value_id-1, level)
                
    #if dbtool.verbose == True:
    #    print "  ", value_id, t, amf_type, repr(bits)[:64]
    return value_id

def parse_stacktrace(filename, c, e, v):
    
    event_id = e
    value_id = v
    
    with open(filename, "rb") as f:
        
        buf = f.read()
        
        pos = 0

        while True:
            context = amf3.Context()
            decoder = amf3.Decoder(buf[pos:], context)
            try:
                data = decoder.readElement()
            except pyamf.EOStream:
                #print "EOStream"
                break
            except IOError: # premature end of stream
                #print "IOError"
                break
            except Exception,e:
                print "Warning:", e, pos
                pos = pos + 1
                continue
            if not data:
                pos = pos + 1
                continue
            pos = pos + decoder.stream.tell()
            
            if type(data) != list:
                print "Warning: top level data not valid: ", type(data)
                continue
            
            l = len(data)
            name, session, method, opcode = data[0].split(":",4)
            c.execute("INSERT INTO stack_events (event_id,session_method,opcode) VALUES (?,?,?);",
                    (event_id, "%s:%s" % (session, method), opcode))
            
            #if dbtool.verbose:
            #    print "\n", event_id, data[0]
            for i in range(0, (l-1)/2):
                t  = data[(i*2)+1]
                a  = data[(i*2)+2]
                #print event_id, t, data[0], repr(a)[:32]
                if type(a) != pyamf.amf3.ByteArray:
                    print "Warning: top level data not valid: ", type(a)
                    d = None
                else:
                    try:
                        d = amf3.Decoder(a).readElement()
                    except:
                        print "Warning: decoder failed @", data[0],t
                        d = ""        
                    
                value_id = insert_stackval(c, value_id, event_id, t, d, -1, 0)
 
            event_id = event_id + 1
        
        return (event_id,value_id)
            
def parse_disasm(dir, c):
    
    c.execute("CREATE TABLE methods (session_method text primary key, name text);")
    c.execute("CREATE TABLE opcodes (opcode_id int primary key, session_method text, opcode_index int, mnemonic text, args text);")
    
    opcode_id = 0
    for file in glob.glob(dir + "/s*.txt"):
        with open(file) as f:
            
            session = ""
            method = ""
            name = ""
            
            for line in f:
                # method start
                if line[:2] != "  ":
                    s = line.split(":")
                    session = s[0]
                    method = s[1]
                    name = s[2]
                    opcode_index = 0
                    c.execute("INSERT INTO methods (session_method,name) VALUES (?,?);", ("%s:%s" % (session,method), name))

                else:
                    instruction = line[12:]
                    sp = instruction.find(" ")
                    op = ""
                    args = ""
                    if (sp != -1):
                        op = instruction[:sp].strip()
                        args = instruction[sp:].strip()
                    else:
                        op = instruction.strip()
                        
                    c.execute("INSERT INTO opcodes (opcode_id, session_method, opcode_index, mnemonic, args) VALUES (?,?,?,?,?);",
                        (opcode_id, "%s:%s" % (session,method), opcode_index, op, args))
                    opcode_id = opcode_id + 1
                    opcode_index = opcode_index + 1

def runyara(yarafile, db, cb, dbconn=False):
    
    rules = yara.compile(filepath=yarafile)
    
    match_str = {}
    match_events = {}
    
    matches = rules.match(db)
    for m in matches:
        for s in m.strings:
            match_str[s[2]] = m.rule

    if len(match_str):
        if dbconn == False:
            conn = sqlite3.connect(db)
        else:
            conn = dbconn
        conn.text_factory = str
        
        for k,v in match_str.iteritems():
            # 1. Search from stack_values
            c = conn.cursor()
            data = "%" + binascii.hexlify(k) + "%"
            c.execute("SELECT * from stack_values where hex(data) like ? or hex(type) like ?;", (data,data))
            for row in c:
                if row[1] in match_events:
                    match_events[row[1]][k] = True
                else:
                    match_events[row[1]] = {k: True}

            # 2. Search from opcodes.args
            c = conn.cursor()
            data = "%" + binascii.hexlify(k) + "%"
            c.execute("SELECT * from opcodes where hex(args) like ?;", (data,))
            for row in c:
                session_method = row[1]
                opcode = row[2]
                
                c = conn.cursor()
                c.execute("SELECT * from stack_events where session_method is ? and opcode is ?;", (session_method,opcode))
                for r in c:
                    if r[0] in match_events:
                        match_events[r[0]][k] = True
                    else:
                        match_events[r[0]] = {k: True}

        for k,v in match_events.iteritems():
            for x,y in v.iteritems():
                cb(k, x, match_str[x])
                
        if (dbconn == False):
            conn.close()


def doyara(yarafile, db):
    print "Running yara, please wait..."
    
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmpname = tmp.name
    tmp.close()
    shutil.copy(db, tmpname)
    
    conn = sqlite3.connect(db)
    
    def cb(event, data, rule):
        print ("[%.8d]  %s (rule: %s)" % (event, repr(data), rule))
    
    runyara(yarafile, tmpname, cb, dbconn=conn)
    conn.close()
    os.remove(tmpname)


def create(dir, out):
    
    logfiles = sorted(glob.glob(dir + "/log-*.dat"))
    if len(logfiles) == 0:
        return 0
        
    if os.path.exists(out):
        os.remove(out)
    
    conn = sqlite3.connect(out)
    conn.text_factory = str
    c = conn.cursor()
    
    parse_disasm(dir, c)
    
    c.execute("CREATE TABLE stack_events (event_id int primary key, session_method text, opcode int);")
    c.execute("CREATE TABLE stack_values (value_id int primary key, stack_event int, type text, amf_type text, data blob, parent int);")
    
    event_id = 0
    value_id = 0
    for lpath in logfiles:
        event_id,value_id = parse_stacktrace(lpath, c, event_id, value_id)
    
    conn.commit()
    conn.close()
    return 1

def raw(db, out):
    print "Exporting raw data, please wait..."
    
    f = open(out, "wb")
    
    conn = sqlite3.connect(db)
    conn.text_factory = str
    
    c = conn.cursor()
    c.execute("SELECT * from stack_values;")
    for row in c:
        f.write(str(row[4]))

    c = conn.cursor()
    c.execute("SELECT * from opcodes;")
    for row in c:
        f.write(str(row[4]))
    
    f.close()
    
    conn.close()

def pretty(db, out):
    print "Making it pretty, please wait..."
    
    currentMethod = ""
    
    if out == None:
        f = tempfile.NamedTemporaryFile()
    else:
        f = open(out, "wb")
    
    conn = sqlite3.connect(db)
    conn.text_factory = str
    
    c = conn.cursor()
    c.execute("SELECT * from stack_events;")
    for row in c:
        event_id, session_method, opcode = row[0],row[1],row[2]

        c = conn.cursor()
        c.execute("SELECT * from opcodes WHERE session_method is ? AND opcode_index is ?;", (session_method,opcode))
        d = c.fetchone()
        mnemonic = d[3]
        args = d[4]
        
        if (mnemonic.find("call") != 0):
            continue
            
        c = conn.cursor()
        c.execute("SELECT * from methods WHERE session_method is ?;", (session_method,))
        d = c.fetchone()
        method_name = d[1]
        if method_name != currentMethod:
            if currentMethod != "":
                f.write("}\n")
            f.write(method_name + ":\n{\n")
            currentMethod = method_name

        arg_a = args.split(',')
        arg_count = int(arg_a[len(arg_a)-1].strip())
        
        if (arg_count == 0):
            continue

        # Function name
        if mnemonic == "call":
            mname = "(closure)"
        else:
            mname = "(%s)" % mnemonic[4:]
            
        is_multiname = args.find("Multiname")
        
        names = re.findall(r'"(.*?)"', args)
        for n in names:
            b = n.find("builtin")
            if b != -1:
                n = "AS_builtin"
            mname = mname + ":" + n
            if is_multiname == 0:
                break
        
        f.write("  [%.8d]  %s\n  (\n" % (event_id, mname))
        
        # Handle arguments
        
        a = []
        c = conn.cursor()
        c.execute("SELECT * from stack_values WHERE stack_event is ? and parent is ?;", (event_id,-1))
        for row in c:
            a.append(row)
    
        i = 0
        for row in a:
            data = repr(row[4])
            if len(data) > 48:
                data = data[:47] + "[...]"
            if (i < len(a)-arg_count):
                id = "obj:"
            else:
                id = "arg:"
            
            if row[3] == "Object" or row[3] == "Array" or row[3] == "Undefined":
                typeid = repr(row[2])
            else:
                typeid = row[3]
            f.write("    %s%s:%s\n" % (id, typeid, data))
            i = i + 1
        
        f.write("  )\n")

    if out == None:
        f.seek(0)
        print f.read()
            
    f.close()    
    conn.close()



def main(argv):
    opt_parser = OptionParser()
    opt_parser.add_option('-c', '--create', action = 'store_true', dest = 'create', help = 'Create a new database from Input dir')
    opt_parser.add_option('-r', '--raw', action = 'store_true', dest = 'raw', help = 'Export raw data from Input database')
    opt_parser.add_option('-p', '--pretty', action = 'store_true', dest = 'pretty', help = 'Export a pretty call trace from Input database')
    opt_parser.add_option('-i', '--input', dest = 'input', help = 'Input')
    opt_parser.add_option('-o', '--output', dest = 'output', help = 'Output')
    opt_parser.add_option('-y', '--yara', dest = 'yara', help = 'Run yara file')
    opt_parser.add_option('-v', '--verbose', action = 'store_true', dest = 'verbose', help = 'Be verbose')
    
    (options,args) = opt_parser.parse_args(argv)
    
    if options.create and options.input and options.output:
        if not create(options.input, options.output):
            print "Database not created, please check the directory \"%s\"" % options.input
    elif options.raw and options.input and options.output:
        raw(options.input, options.output)
    elif options.pretty and options.input:
        pretty(options.input, options.output)
    elif options.yara and options.input:
        doyara(options.yara, options.input)
        
    else:
        print "Don't know what to do!"
    
if __name__ == "__main__":
     main(sys.argv[1:])



