/*
 * 
 * Reflash - re-flash flash files
 * Copyright 2016 Jarkko Turkulainen, F-Secure corp.
 * 
 * Reflash is GPL3, see the file LICENSE for more details.
 * Based partially on redasm, Copyright 2014, 2016 Xavier Mendez.
 * Uses heavily RABCDAsm - Robust ABC, AS2/3 [Dis-]Assembler.
 *
 */
 
module reflash;

import std.regex;
import std.file;
import std.path;
import std.stdio;
import std.datetime;
import std.conv;
import std.array;
import std.getopt;
import std.random;
import std.string;
import std.json;
import std.format;

import abcfile;
import asprogram;
import assembler;
import disassembler;
import swffile;

import instrument;


enum ReflashError
{
    ERROR_NO_ERROR = 0,
    ERROR_GENERIC = 1,
    ERROR_FILE = 2,
    ERROR_WORKDIR = 3,
    ERROR_NOT_SWF = 4,
}

string getRandomName()
{
    int i = uniform(4,12);
    
    string str;
    for (int ii = 0; ii < i; ii++)
    {
        int c = uniform(97, 122);
        str ~= cast(ubyte)c;
    }
    return str;
}

// StBuilder code copied from RABCDasm
final class StBuilder
{
	enum BUF_SIZE = 256*1024;

	static char[] buf;
	static size_t pos;

	string filename;
	File file;

	this(string filename)
	{
		this.filename = filename;
		file = File(filename, "wb");
	}

	static this()
	{
		buf = new char[BUF_SIZE];
	}

	void put(in char[] s)
	{
		checkIndent();
		auto end = pos + s.length;
		if (end > buf.length)
		{
			flush();
			end = s.length;
			while (end > buf.length)
				buf.length = buf.length*2;
		}
		buf[pos..end] = s[];
		pos = end;
	}

	void put(char c)
	{
		if (pos == buf.length) // speed hack: no indent check
			flush();
		buf[pos++] = c;
	}

	alias put opCatAssign;

	void write(T)(T v)
	{
		checkIndent();
		formattedWrite(this, "%s", v);
	}

	void flush()
	{
		if (pos)
		{
			file.rawWrite(buf[0..pos]);
			pos = 0;
		}
	}

	void save()
	{
		flush();
		file.close();
	}

	int indent;
	bool indented;
	string linePrefix;

	void newLine()
	{
		this ~= '\n';
		indented = false;
	}

	void noIndent()
	{
		indented = true;
	}

	void checkIndent()
	{
		if (!indented)
		{
			for (int i=0; i<indent; i++)
				this ~= ' ';
			indented = true;
			if (linePrefix)
				this ~= linePrefix;
		}
	}
}

// All dump* functions copied from RABCDasm disassembler code
void dumpInt(StBuilder sb, long v)
{
    if (v == ABCFile.NULL_INT)
        sb ~= "null";
    else
        sb.write(v);
}

// All dump* functions copied from RABCDasm disassembler code
void dumpUInt(StBuilder sb, ulong v)
{
    if (v == ABCFile.NULL_UINT)
        sb ~= "null";
    else
        sb.write(v);
}

// Copied from RABCDasm disassembler code
static struct StaticBuf(T, size_t size)
{
    T[size] buf;
    size_t pos;
    void put(T v) { buf[pos++] = v; }
    void put(in T[] v) { buf[pos..pos+v.length] = v[]; pos+=v.length; }
    T[] data() { return buf[0..pos]; }
}

// All dump* functions copied from RABCDasm disassembler code
void dumpDouble(StBuilder sb, double v)
{
    if (v == ABCFile.NULL_DOUBLE)
        sb ~= "null";
    else
    {
        StaticBuf!(char, 64) buf;
        formattedWrite(&buf, "%.18g", v);
        char[] s = buf.data();

        static double forceDouble(double d) { static double n; n = d; return n; }
        if (s != "nan" && s != "inf" && s != "-inf")
        {
            if (forceDouble(to!double(s)) == v)
            {
                foreach_reverse (i; 1..s.length)
                    if (s[i]>='0' && s[i]<='8')
                    {
                        s[i]++;
                        if (forceDouble(to!double(s[0..i+1]))==v)
                            s = s[0..i+1];
                        else
                            s[i]--;
                    }
                while (s.length>2 && s[$-1]!='.' && forceDouble(to!double(s[0..$-1]))==v)
                    s = s[0..$-1];
            }
            else
            {
                buf.pos = 0;
                formattedWrite(&buf, "%.13a", v);
                s = buf.data();
                auto n = forceDouble(to!double(s));
                assert(n == v,
                    "reflash: Can't print precise representation of double: %(%02X %) (%.18g) => %s => %(%02X %) (%.18g)".format(
                        cast(ubyte[])cast(void[])[v], v,
                        s,
                        cast(ubyte[])cast(void[])[n], n,
                    ));
            }
        }
			sb ~= s;
    }
}

// All dump* functions copied from RABCDasm disassembler code
void dumpString(StBuilder sb, string str)
{
    if (str is null)
        sb ~= "null";
    else
    {
        static const char[16] hexDigits = "0123456789ABCDEF";

        sb ~= '"';
        foreach (c; str)
            if (c == 0x0A)
                sb ~= `\n`;
            else
            if (c == 0x0D)
                sb ~= `\r`;
            else
            if (c == '\\')
                sb ~= `\\`;
            else
            if (c == '"')
                sb ~= `\"`;
            else
            if (c < 0x20)
            {
                sb ~= `\x`;
                sb ~= hexDigits[c / 0x10];
                sb ~= hexDigits[c % 0x10];
            }
            else
                sb ~= c;
        sb ~= '"';
    }
}

// All dump* functions copied from RABCDasm disassembler code
void dumpNamespace(StBuilder sb, ASProgram.Namespace namespace, RefBuilder refs)
{
    if (namespace is null)
        sb ~= "null";
    else
    {
        sb ~= ASTypeNames[namespace.kind];
        sb ~= '(';
        dumpString(sb, namespace.name);
        if (refs.hasHomonyms(namespace))
        {
            sb ~= ", ";
            auto label = refs.namespaces[namespace.kind].getName(namespace.id);
        //	label ~= format(" (%d)", namespace.id);
            dumpString(sb, label);
        }
        sb ~= ')';
    }
}

// All dump* functions copied from RABCDasm disassembler code
void dumpNamespaceSet(StBuilder sb, ASProgram.Namespace[] set, RefBuilder refs)
{
    if (set is null)
        sb ~= "null";
    else
    {
        sb ~= '[';
        foreach (i, ns; set)
        {
            dumpNamespace(sb, ns, refs);
            if (i < set.length-1)
                sb ~= ", ";
        }
        sb ~= ']';
    }
}

// All dump* functions copied from RABCDasm disassembler code
void dumpMultiname(StBuilder sb, ASProgram.Multiname multiname, RefBuilder refs)
{
    if (multiname is null)
        sb ~= "null";
    else
    with (multiname)
    {
        sb ~= ASTypeNames[kind];
        sb ~= '(';
        switch (kind)
        {
            case ASType.QName:
            case ASType.QNameA:
                dumpNamespace(sb, vQName.ns, refs);
                sb ~= ", ";
                dumpString(sb, vQName.name);
                break;
            case ASType.RTQName:
            case ASType.RTQNameA:
                dumpString(sb, vRTQName.name);
                break;
            case ASType.RTQNameL:
            case ASType.RTQNameLA:
                break;
            case ASType.Multiname:
            case ASType.MultinameA:
                dumpString(sb, vMultiname.name);
                sb ~= ", ";
                dumpNamespaceSet(sb, vMultiname.nsSet, refs);
                break;
            case ASType.MultinameL:
            case ASType.MultinameLA:
                dumpNamespaceSet(sb, vMultinameL.nsSet, refs);
                break;
            case ASType.TypeName:
                dumpMultiname(sb, vTypeName.name, refs);
                sb ~= '<';
                foreach (i, param; vTypeName.params)
                {
                    dumpMultiname(sb, param, refs);
                    if (i < vTypeName.params.length-1)
                        sb ~= ", ";
                }
                sb ~= '>';
                break;
            default:
                throw new .Exception("reflash: Unknown Multiname kind");
        }
        sb ~= ')';
    }
}
    
// All dump* functions copied from RABCDasm disassembler code
void dumpLabel(StBuilder sb, ref ABCFile.Label label)
{
    //sb ~= 'L';
    sb.write(format("%.8d  ", label.index));
    if (label.offset != 0)
    {
        if (label.offset > 0)
            sb ~= '+';
        sb.write(label.offset);
    }
}

bool fixTargets(ref ASProgram.Instruction[] instructions, ulong index, ulong count)
{
    // Single opcode, no need for fixups
    if (count == 0)
        return true;
    
    foreach (ii, ref instruction; instructions) {
        // Not interested in instrumented code, that's fixed already
        if ((ii >= index) && (ii < index+count))
            continue;
        foreach (i, type; opcodeInfo[instruction.opcode].argumentTypes)
            if ((type == OpcodeArgumentType.JumpTarget) ||
                (type == OpcodeArgumentType.SwitchDefaultTarget))
            {
                if (instruction.arguments[i].jumpTarget.index > index)
                    instruction.arguments[i].jumpTarget.index += count;
            }
            else if (type == OpcodeArgumentType.SwitchTargets)
            {
                auto targets = instruction.arguments[i].switchTargets;
                foreach (ref t; targets)
                {
                    if (t.index > index)
                        t.index += count;
                }
            }
    }
    return true;
}

bool fixExceptions(ref ASProgram.Exception[] exceptions, ulong index, ulong count)
{
    // Single opcode, no need for fixups
    if (count == 0)
        return true;
        
    foreach (ref e; exceptions)
    {
        // e.from.index == try block start
        // e.to.index = try block end
        // e.target.index = handler
        if (e.from.index > index)
        {
            e.from.index += count;
        }
        if (e.to.index > index)
        {
            e.to.index += count;
        }
        if (e.target.index > index)
        {
            e.target.index += count;
        }
     }

    return true;
}


// Check for dangerous instructions, fix branch targets

bool validateCode(ref ASProgram.Instruction[] instructions, uint index)
{
    foreach (ref instruction; instructions) {
        foreach (i, type; opcodeInfo[instruction.opcode].argumentTypes) {
            if (type == OpcodeArgumentType.JumpTarget) {
                
                // Branching allowed only inside the block:
                if (instruction.arguments[i].jumpTarget.index > instructions.length)
                {
                    writefln("reflash: Illegal JumpTarget in instrumented opcode %s @%d: %d, sizeof(block): %d",
                        opcodeInfo[instruction.opcode].name,
                        index,
                        instruction.arguments[i].jumpTarget.index,
                        instructions.length);
                    
                    return false;
                // Fix to absolute target
                } else {                 
                    instruction.arguments[i].jumpTarget.index += index;
                }
                
            }
        }
    }
    
    return true;
}


bool parseMethodBody(ref ASProgram.MethodBody mbody, RefBuilder refs, Instrument instrument, ref Config cfg, string session)
{
    auto refName = refs.objects.getName(mbody.method);
        
    instrument.startCodeBlock(&mbody.method, mbody, refName, session);

    if (cfg.stream)
    {
        cfg.sb ~= session ~ ":" ~ to!string(mbody.method.id) ~ ":" ~ refName ~ ":";
        cfg.sb.newLine();
        
        for (uint index = 0; index < mbody.instructions.length; index++) {
            auto instruction = mbody.instructions[index];        
        
			cfg.sb ~= "  " ~ format("%.8d  ", index) ~ opcodeInfo[instruction.opcode].name;
            
			auto argTypes = opcodeInfo[instruction.opcode].argumentTypes;
			if (argTypes.length)
			{
				foreach (i; opcodeInfo[instruction.opcode].name.length..20)
					cfg.sb ~= ' ';
				foreach (i, type; argTypes)
				{
					final switch (type)
					{
						case OpcodeArgumentType.Unknown:
							throw new Exception("reflash: Don't know how to disassemble OP_" ~ opcodeInfo[instruction.opcode].name);

						case OpcodeArgumentType.ByteLiteral:
							cfg.sb.write(instruction.arguments[i].bytev);
							break;
						case OpcodeArgumentType.UByteLiteral:
							cfg.sb.write(instruction.arguments[i].ubytev);
							break;
						case OpcodeArgumentType.IntLiteral:
							cfg.sb.write(instruction.arguments[i].intv);
							break;
						case OpcodeArgumentType.UIntLiteral:
							cfg.sb.write(instruction.arguments[i].uintv);
							break;

						case OpcodeArgumentType.Int:
							dumpInt(cfg.sb, instruction.arguments[i].intv);
							break;
						case OpcodeArgumentType.UInt:
							dumpUInt(cfg.sb, instruction.arguments[i].uintv);
							break;
						case OpcodeArgumentType.Double:
							dumpDouble(cfg.sb, instruction.arguments[i].doublev);
							break;
						case OpcodeArgumentType.String:
							dumpString(cfg.sb, instruction.arguments[i].stringv);
							break;
						case OpcodeArgumentType.Namespace:
							dumpNamespace(cfg.sb, instruction.arguments[i].namespacev, refs);
							break;
						case OpcodeArgumentType.Multiname:
							dumpMultiname(cfg.sb, instruction.arguments[i].multinamev, refs);
							break;
						case OpcodeArgumentType.Class:
							if (instruction.arguments[i].classv is null)
								cfg.sb ~= "null";
							else
								dumpString(cfg.sb, refs.objects.getName(instruction.arguments[i].classv));
							break;
						case OpcodeArgumentType.Method:
							if (instruction.arguments[i].methodv is null)
								cfg.sb ~= "null";
							else
								dumpString(cfg.sb, refs.objects.getName(instruction.arguments[i].methodv));
							break;

						case OpcodeArgumentType.JumpTarget:
						case OpcodeArgumentType.SwitchDefaultTarget:
							dumpLabel(cfg.sb, instruction.arguments[i].jumpTarget);
							break;

						case OpcodeArgumentType.SwitchTargets:
							cfg.sb ~= '[';
							auto targets = instruction.arguments[i].switchTargets;
							foreach (ti, t; targets)
							{
								dumpLabel(cfg.sb, t);
								if (ti < targets.length-1)
									cfg.sb ~= ", ";
							}
							cfg.sb ~= ']';
							break;
					}
					if (i < argTypes.length-1)
						cfg.sb ~= ", ";
				}
			}
			cfg.sb.newLine();
        }
    }
    
    uint orig_index = 0;
    for (uint index = 0; index < mbody.instructions.length;) {
        auto instruction = mbody.instructions[index];
        
        ASProgram.Instruction[] insts;
        int maxstack;
        cfg.opcodeCount++;
        if (instrument.instrumentCode(&mbody.method, instruction, orig_index, insts) &&
            validateCode(insts, index)) {
            
            if (index == 0) {
                mbody.instructions = insts ~ mbody.instructions[1..mbody.instructions.length];
            } else if (index == mbody.instructions.length-1) {
                mbody.instructions = mbody.instructions[0..index] ~ insts;
            } else {
                auto a = mbody.instructions[0..index];
                auto b = mbody.instructions[index+1..mbody.instructions.length];
                mbody.instructions = a ~ insts ~ b;
            }
            fixTargets(mbody.instructions, index, insts.length-1);
            fixExceptions(mbody.exceptions, index, insts.length-1);
            index += insts.length;
            instrument.instrumented = true;
            cfg.instrumentCount++;
        }
        else index++;
        orig_index++;
    }
    
    instrument.endCodeBlock(&mbody.method, mbody);
    return true;
}


bool parseMethod(ASProgram.Method method, RefBuilder refs, Instrument instrument, ref Config cfg, string session)
{
    if (method.vbody) {
        parseMethodBody(method.vbody, refs, instrument, cfg, session);
        parseTraits(method.vbody.traits, refs, instrument, cfg, session);
    }
    
    return true;
}


bool parseTraits(ASProgram.Trait[] traits, RefBuilder refs, Instrument instrument, ref Config cfg, string session)
{
    
    foreach (/*ref*/ trait; traits) {
        
        switch (trait.kind) {
            case TraitKind.Class:
                parseClass(trait.vClass.vclass, refs, instrument, cfg, session);
                break;
            case TraitKind.Function:
                parseMethod(trait.vFunction.vfunction, refs, instrument, cfg, session);
                break;
            case TraitKind.Method:
            case TraitKind.Getter:
            case TraitKind.Setter:
                parseMethod(trait.vMethod.vmethod, refs, instrument, cfg, session);
                break;
            default:
        }
    }
    
    return true;
}

bool parseInstance(ASProgram.Instance instance, RefBuilder refs, Instrument instrument, ref Config cfg, string session)
{
    
    parseMethod(instance.iinit, refs, instrument, cfg, session);
    parseTraits(instance.traits, refs, instrument, cfg, session);
    return true;
}

bool parseClass(ASProgram.Class vclass, RefBuilder refs, Instrument instrument, ref Config cfg, string session)
{
    parseInstance(vclass.instance, refs, instrument, cfg, session);
    parseMethod(vclass.cinit, refs, instrument, cfg, session);
    parseTraits(vclass.traits, refs, instrument, cfg, session);
    return true;
}

bool manipulateAS(ASProgram as, Instrument instrument, ref Config cfg, string session)
{
    RefBuilder refs = new RefBuilder(as);
    refs.run();
    
    foreach (uint i, script; as.scripts) {
        parseMethod(script.sinit, refs, instrument, cfg, session);
        parseTraits(script.traits, refs, instrument, cfg, session);
    }
    
    foreach (i, vclass; as.orphanClasses) {
        parseClass(vclass, refs, instrument, cfg, session);
    }
    
    foreach (i, method; as.orphanMethods) {
        parseMethod(method, refs, instrument, cfg, session);
    }
    
    return true;
}


// processSWF based on Xavier Mendez's "redasm"
// https://github.com/jmendeth/redasm-abc
void processSWF(string root, SWFFile swf, ref Config cfg) {
    int idx = 0;
    foreach (ref tag; swf.tags) {
        if (tag.type == TagType.DoABC || tag.type == TagType.DoABC2) {
            if (tag.type == TagType.DoABC2) {
                auto ptr = tag.data.ptr + 4; // skip flags
                while (*ptr++) {} // skip name

                auto data = tag.data[ptr-tag.data.ptr..$];
                auto header = tag.data[0..ptr-tag.data.ptr];
                processTag(root, data, idx, cfg);
                tag.data = header ~ data;
            } else {
                processTag(root, tag.data, idx, cfg);
            }
            tag.length = cast(uint) tag.data.length;
            idx++;
        }
    }

    if (cfg.dbg && (idx == 0)) {
        writeln("reflash: The SWF didn't contain ABC tags.");
    }
}


bool getIncludes(string dir, string file, ref Config cfg)
{
    auto f = File(file, "r");
    
    bool found_inc = false;
    bool patched = false;
    
    foreach (string line; lines(f))
    {
        ptrdiff_t i = indexOf(line, "#include");
        if (i != -1)
        {
            char[] inc = line.dup;
            inc = inc[i+8..inc.length];
            inc = strip(inc);
            if ((inc[0] == '"') && (inc[inc.length-1] == '"'))
                inc = inc[1..inc.length-1];
            
            string include = dir ~ "/" ~ inc.idup;
            cfg.includes ~= include;
        }
    }
    return true;
}


string patchIncludes(string file, Config cfg)
{
    string file_r = file;
    string file_w = file_r ~ ".p";
    
    auto f_r = File(file_r, "r");
    auto f_w = File(file_w, "w");
        
    bool found_inc = false;
    bool patched = false;
    foreach (string line; lines(f_r))
    {
        if (indexOf(line, "#include") != -1)
        {
            found_inc = true;
            f_w.write(line);
        }
        else if (found_inc == true && patched == false)
        {
            foreach (inc; cfg.includes)
            {
                f_w.writef(" #include \"%s\"\n", inc);
            }
            patched = true;
            f_w.write("\n");
        }
        else
            f_w.write(line);
    }
    return file_w;
}

// processTag based on Xavier Mendez's "redasm"
// https://github.com/jmendeth/redasm-abc
void processTag(string root, ref ubyte[] data, int idx, ref Config cfg) {
    string name = "block-" ~ to!string(idx);
    string dir = buildPath(root, name);
    
    if (cfg.mode == Mode.MODE_ASM)
    {
        assemble(dir, name, data);
        return;
    }
    
    scope abc = ABCFile.read(data);
    scope as = ASProgram.fromABC(abc);

    // Manipulate ASProgram
    scope instrument = new Instrument(cfg.dbg);
    if (cfg.mode != Mode.MODE_DISASM)
    {
        foreach (target; cfg.opcodeHooks)
        {
            instrument.addOpcodeHook(target);
        }
        if (cfg.inject_pkg)
            instrument.setInstrumentPackage(cfg.inject_pkg);
            
        manipulateAS(as, instrument, cfg, cfg.id ~ "-" ~ to!string(idx));
    }
    
    scope disassembler = new Disassembler(as, dir, name);
    disassembler.disassemble();
    
    // Get includes from injected file
    if (cfg.get_includes)
    {
        getIncludes(name, dir ~ "/" ~ name ~ ".main.asasm", cfg);
        return;
    }
    
    // Patch includes
    if ((cfg.mode != Mode.MODE_DISASM) && instrument.instrumented)
    {
        string file_r = dir ~ "/" ~ name ~ ".main.asasm";
        string file_w = patchIncludes(file_r, cfg);
        remove(file_r);
        rename(file_w, file_r);
    }

    // reassemble back
    if (cfg.mode == Mode.MODE_INSTRUMENT)
        assemble(dir, name, data);
}

// assemble based on Xavier Mendez's "redasm"
// https://github.com/jmendeth/redasm-abc
void assemble(string dir, string name, ref ubyte[] data) {
    scope as = new ASProgram;
    scope assembler = new Assembler(as);
    assembler.assemble(buildPath(dir, name ~ ".main.asasm"));
    scope abc = as.toABC();
    data = abc.write();
}

enum Mode
{
    MODE_INSTRUMENT = 0,
    MODE_DISASM = 1,
    MODE_ASM = 2,
}

struct Config
{
    int mode;
    bool dbg;
    bool quiet;
    string work_dir;
    string tmp_tag;
    string swfFile;
    string input;
    string output;
    string config;
    string inject;
    string inject_pkg;
    string stream;
    string id;
    StBuilder sb;
    bool get_includes;
    string[] includes;
    string[] opcodeHooks;
    int opcodeCount;
    int instrumentCount;
}


bool parseConfig(ref Config cfg)
{
    if (!cfg.config)
        return true;
    
    auto content = to!string(read(cfg.config));
    
    JSONValue json = parseJSON(content);
    JSONValue conf = json["reflashConfig"];
    
    const(JSONValue)* p;
    if ((p = "input" in conf) != null)
    {
        cfg.input = p.str;
    }
    if ((p = "output" in conf) != null)
    {
        cfg.output = p.str;
    }
    if ((p = "work_dir" in conf) != null)
    {
        cfg.work_dir = p.str;
    }
    if ((p = "inject" in conf) != null)
    {
        cfg.inject = p.str;
    }
    if ((p = "inject_pkg" in conf) != null)
    {
        cfg.inject_pkg = p.str;
    }
    if ((p = "stream" in conf) != null)
    {
        cfg.stream = p.str;
    }
    if ((p = "id" in conf) != null)
    {
        cfg.id = p.str;
    }
    if (((p = "quiet" in conf) != null) && (p.type == JSON_TYPE.TRUE))
    {
        cfg.quiet = true;
    }
    if (((p = "dbg" in conf) != null) && (p.type == JSON_TYPE.TRUE))
    {
        cfg.dbg = true;
    }
    if ((p = "opcodeHooks" in conf) != null)
    {
        JSONValue opcodeHooks[] = conf["opcodeHooks"].array;
        foreach (c; opcodeHooks)
        {
            cfg.opcodeHooks ~= c.str;
        }
    }  
    return true;
}

void usage()
{
    writeln("\nUsage: reflash <cmd> <args>\n");
    writeln("  Commands (one required):");
    writeln("    i|instrument        Instrument file defined with --input");
    writeln("    d|disassemble       Disassemble file defined with --input");
    writeln("    a|assemble          Assemble from directory defined with --dir");
    writeln("\n  Arguments:");
    writeln("    --input  <swf>      Input flash file.");
    writeln("    --inject <swf>      Inject a flash file.");
    writeln("    --inject_pkg <pkg>  Inject flash package.");
    writeln("    --output <swf>      Output flash file (default=<input>.reflash)");
    writeln("    --dir    <path>     Working directory (default=random tmp dir)");
    writeln("    --config <file>     Load configuration from JSON file (overrides cmdline)");
    writeln("    --stream <file>     Produce a stream disassembly");
    writeln("    --id     <string>   Session id for stream disassembler");
    writeln("    --debug             Be verbose and leave temporary files for further inspection.");
    writeln("    --quiet             Be very quiet.");
    writeln("    -h|--help           This message.\n");
}

int main(string[] args) {
    string tagfile = ".reflash";
    Config cfg;
  
    if (args.length < 3)
    {
        usage();
        return ReflashError.ERROR_GENERIC;
    }
    
    switch (args[1][0..1])
    {
        case "i":
            cfg.mode = Mode.MODE_INSTRUMENT;
            break;
        case "d":
            cfg.mode = Mode.MODE_DISASM;
            break;
        case "a":
            cfg.mode = Mode.MODE_ASM;
            break;
        default:
            writeln("reflash: Error: no command defined! Must be one of these:");
            writeln("  instrument, disassemble or assemble");
            usage();
            return ReflashError.ERROR_GENERIC;
    }

    try {
        auto helpInformation = getopt(
            args,
            "input", "Input file name.", &cfg.input,
            "output", "Output file name.", &cfg.output,
            "dir", "Working directory.", &cfg.work_dir,
            "inject", "SWF file to be injected.", &cfg.inject,
            "inject_pkg", "Injected SWF package.", &cfg.inject_pkg,
            "config", "Read configuration from JSON file.", &cfg.config,
            "stream", "Produce a stream disassembly and save it to file", &cfg.stream,
            "id", "Session id for stream disassembler", &cfg.id,
            "quiet", "Be quiet.", &cfg.quiet,
            "debug", "Be verbose and leave temporary files for further inspection.", &cfg.dbg);

        if (helpInformation.helpWanted)
        {
            usage();
            return ReflashError.ERROR_GENERIC;
        }
    }
    catch (Exception e) 
    {
       writeln("reflash: Error: " ~ e.msg);
       usage();
       return ReflashError.ERROR_GENERIC;
    }
    
    parseConfig(cfg);
    if (cfg.dbg)
        writeln(cfg);
        
    if ((cfg.mode == Mode.MODE_INSTRUMENT) && cfg.stream)
    {
        cfg.sb = new StBuilder(cfg.stream);
        cfg.sb.flush();
    }
    
    if (!cfg.id)
        cfg.id = "0";
    
    if (cfg.mode == Mode.MODE_DISASM)
    {
        if (!cfg.input)
        {
            writeln("reflash: Error: no input file defined.");
            usage();
            return ReflashError.ERROR_FILE;
        }
        if (!cfg.work_dir)
        {
            cfg.work_dir = tempDir() ~ "/" ~ tagfile ~ "-" ~ getRandomName();
            mkdir(cfg.work_dir);
            if (cfg.dbg)
            {
                writefln("reflash: Created temporary directory %s for analyzed file.", cfg.work_dir);
            }
        }
        cfg.swfFile = cfg.work_dir ~ "/tmp.swf";
        copy(cfg.input, cfg.swfFile);
    }
    else if (cfg.mode == Mode.MODE_INSTRUMENT)
    {
        if (!cfg.input)
        {
            writeln("reflash: Error: no input file defined.");
            usage();
            return ReflashError.ERROR_FILE;
        }
        if (!cfg.work_dir)
        {
            cfg.work_dir = tempDir() ~ "/" ~ tagfile ~ "-" ~ getRandomName();
        }
        else
        {
            cfg.work_dir ~= "/" ~ tagfile ~ "-" ~ getRandomName();
        }
        mkdir(cfg.work_dir);
        if (cfg.dbg)
        {
            writefln("reflash: Created temporary directory %s for analyzed file.", cfg.work_dir);
        }
        cfg.swfFile = cfg.work_dir ~ "/tmp.swf";
        copy(cfg.input, cfg.swfFile);
    }
    else if (cfg.mode == Mode.MODE_ASM)
    {
        if (!cfg.work_dir)
        {
            writeln("reflash: Error: no work directory defined.");
            usage();
            return ReflashError.ERROR_WORKDIR;
        }
        cfg.swfFile = cfg.work_dir ~ "/tmp.swf";
    }
    
    // Process injected SWF
    Config icfg;
    if ((cfg.mode == Mode.MODE_INSTRUMENT) && cfg.inject)
    {
        if (!cfg.inject_pkg)
        {
            writeln("reflash: Warning: no inject package name defined, using default.");
            cfg.inject_pkg = "instrument_package";            
        }
        icfg.mode = Mode.MODE_DISASM;
        icfg.get_includes = true;
        icfg.input = cfg.inject;
        icfg.tmp_tag = tagfile ~ "-" ~ getRandomName();
        icfg.work_dir = cfg.work_dir ~ "/" ~ icfg.tmp_tag;
        mkdir(icfg.work_dir);
        icfg.swfFile = icfg.work_dir ~ "/tmp.swf";
        copy(icfg.input, icfg.swfFile);
        try
        {        
            scope iswf = SWFFile.read(cast(ubyte[]) read(icfg.swfFile));
            processSWF(icfg.work_dir, iswf, icfg);
        }
        catch (Exception e) 
        {
            return ReflashError.ERROR_NOT_SWF;
        }
        foreach (inc; icfg.includes)
            cfg.includes ~= "../" ~ icfg.tmp_tag ~ "/" ~ inc;
    }

    // Process the actual SWF
    try
    { 
        scope swf = SWFFile.read(cast(ubyte[]) read(cfg.swfFile));
        processSWF(cfg.work_dir, swf, cfg);
        std.file.write(cfg.swfFile, swf.write());
    }
    catch (Exception e) 
    {
        return ReflashError.ERROR_NOT_SWF;
    }
    
    if (cfg.mode == Mode.MODE_INSTRUMENT)
    {
        if (!cfg.output)
            cfg.output = cfg.input ~ tagfile;
            
        copy(cfg.swfFile, cfg.output);
        
        if (cfg.stream)
            cfg.sb.save();
        
        if (!cfg.quiet)
        {
            writefln("reflash: Reflashed file: %s", cfg.output);
            writefln("reflash: Instrumented %d/%d opcodes", cfg.instrumentCount, cfg.opcodeCount);
        }
    }
    if ((cfg.mode == Mode.MODE_ASM) && !cfg.quiet)
    {
        writefln("reflash: Reflashed file: %s", cfg.swfFile);
    }
    if (!cfg.dbg && (cfg.mode == Mode.MODE_INSTRUMENT))
    {
        // For some reason, this fails to remove some files, sometimes.
        // Most likely related to VirtualBox. In that case, just leave it..
        try
        {
            rmdirRecurse(cfg.work_dir);
        }
        catch (Exception e) 
        {
            return ReflashError.ERROR_NO_ERROR;
        }
    }
    return ReflashError.ERROR_NO_ERROR;
}

