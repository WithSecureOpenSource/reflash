/*
 * 
 * Reflash instrumentation module
 * Copyright 2016 Jarkko Turkulainen, F-Secure corp.
 * 
 * Reflash is GPL3, see the file LICENSE for more details.
 * Uses heavily RABCDAsm - Robust ABC, AS2/3 [Dis-]Assembler.
 *
 */



module instrument;

import asprogram;
import abcfile;

import std.string : format; // exception formatting
import std.conv;
import std.exception;
import std.stdio;
import std.string;
import std.regex;

alias BlockId = ASProgram.Method *;


Regex!char[] opcodeRegexTable;


class Instrument
{
    bool initialized;
    bool instrumented;
    bool verbose;
    string instrument_pkg;
    uint maxScopeDepth;
    uint initScopeDepth;
    uint currentMaxScopeDepth;
    uint maxStack;
    uint currentStack;
    uint localCount;
    size_t paramCount;
    uint currentLocal;
    bool updateBody;
    uint currentId;
    string currentRefname;
    string currentSession;
    
    this(bool dbg)
    {
        initialized = true;
        instrumented = false;
        verbose = dbg;
    }
    
    void setInstrumentPackage(string pkg)
    {
        instrument_pkg = pkg;
    }
    
    // Additional hooks from configuration file
    void addOpcodeHook(string target)
    {
        opcodeRegexTable ~= regex(target);
    }
    
    bool hookOpcode(string s)
    {
        foreach (a; opcodeRegexTable)
        {
            auto c = matchFirst(s, a);
            if (! c.empty)
                return true;
        }
        return false;
    }
    
    void updateLocal(uint count)
    {
        updateBody = true;
        if (count > currentLocal)
        {
            currentLocal = count;
        }
    }
    
    void updateStack(uint count)
    {
        updateBody = true;
        if (count > currentStack)
        {
            currentStack = count;
        }
    }
    
    void updateMaxScopeDepth(uint count)
    {
        updateBody = true;
        if (count > currentMaxScopeDepth)
        {
            currentMaxScopeDepth = count;
        }
    }
    
    //
    // Notification callbacks for code block start/end
    //
    // Normally, there's no need to touch these, but in case your hooks use
    // local variables, or alter stack size, these can be used for maintaining
    // the state. Method body is provided as a reference, so be careful...
    //
    // 
    void startCodeBlock(BlockId id, ref ASProgram.MethodBody mbody, string refname, string session)
    {
        maxStack = mbody.maxStack;
        localCount = mbody.localCount;
        paramCount = mbody.method.paramTypes.length;
        currentLocal = 0;
        currentStack = 0;
        maxScopeDepth = mbody.maxScopeDepth;
        initScopeDepth = mbody.initScopeDepth;
        updateBody = false;
        currentRefname = refname;
        currentId = mbody.method.id;
        currentSession = session;
        
        // XXX: Don't mess with optional arguments
        if (mbody.method.flags & 0x08)
            paramCount = 0;
        
        if (verbose == true)
        {
            writefln("start: %s: id: %d, maxStack: %d, localCount: %d, maxScopeDepth: %d",
                refname, currentId, mbody.maxStack, mbody.localCount, mbody.maxScopeDepth);
        }
        
    }
    void endCodeBlock(BlockId id, ref ASProgram.MethodBody mbody)
    {
        if (updateBody)
        {
            mbody.maxStack = maxStack + currentStack;
            mbody.localCount = localCount + currentLocal;
            mbody.maxScopeDepth = maxScopeDepth + currentMaxScopeDepth;
        }
        
        if (verbose == true)
        {
            writefln("end: maxStack: %d, localCount: %d, maxScopeDepth: %d\n",
                mbody.maxStack, mbody.localCount, mbody.maxScopeDepth);
        }
    }

    //
    // Instrument.instrumentCode(): instrument a single instruction
    //
    // Return: true if instrumented, false if not
    // Arguments:
    // - id - Code block identifier (IN)
    // - inst - Instruction to be instrumented (IN)
    // - index - Opcode index within the method body (IN)
    // - instructions - Instrumented instruction array (OUT)
    //
    // Some points to consider:
    //
    // - Original instruction is overwritten by whatever comes in from
    //   the instrumentation. Just copy it to the array if you need it.
    //
    // - Do not instrument branch targets, that's not supported.
    //
    // - If you use branches in the instrumented code, they must
    //   reference inside the block. Branch targets
    //   inside instrumented block is always relative to the block.
    //
    // - If your code needs local variables, it is a good idea to
    //   maintain a state for methods with startCodeBlock/endCodeBlock.
    //   With the state, you can use locals, keep an eye on stack size etc.
    //
    // - IMPORTANT: fixing stack size and locals is the resposibility of
    //   instrument module! Update method body in endCodeBlock().
    //
    
    bool instrumentCode(BlockId id, ASProgram.Instruction inst, uint index, ref ASProgram.Instruction[] instructions)
    {
        // Special case of offset 0:
        if (index == 0)
        {
            return instrumentMethodEntry(inst, instructions);
        }
        
        // Misc. calls
        if ((inst.opcode == Opcode.OP_constructprop) ||
            (inst.opcode == Opcode.OP_callproperty) ||
            (inst.opcode == Opcode.OP_callproplex) ||
            (inst.opcode == Opcode.OP_callsuper) ||
            (inst.opcode == Opcode.OP_callsupervoid) ||
            (inst.opcode == Opcode.OP_callpropvoid))
        {
            uint s = getNameStackSize(inst.arguments[0].multinamev);
            return instrumentStack(inst, index, s+1, inst.arguments[1].uintv, instructions);            
        }
        
        // call <args>
        else if (inst.opcode == Opcode.OP_call)
        {
            return instrumentStack(inst, index, 2, inst.arguments[0].uintv, instructions);
        }
        
        // op index, args
        else if ((inst.opcode == Opcode.OP_callstatic) ||
                 (inst.opcode == Opcode.OP_callmethod) ||
                 (inst.opcode == Opcode.OP_construct) ||
                 (inst.opcode == Opcode.OP_constructsuper))
        {
            return instrumentStack(inst, index, 1, inst.arguments[0].uintv, instructions);
        }
        
        // Stack with one value
        else if ((inst.opcode == Opcode.OP_setlocal0) ||
                 (inst.opcode == Opcode.OP_setlocal1) ||
                 (inst.opcode == Opcode.OP_setlocal2) ||
                 (inst.opcode == Opcode.OP_setlocal3) ||
                 (inst.opcode == Opcode.OP_pop) ||
                 (inst.opcode == Opcode.OP_dup) ||
                 (inst.opcode == Opcode.OP_increment) ||
                 (inst.opcode == Opcode.OP_increment_i) ||
                 (inst.opcode == Opcode.OP_decrement) ||
                 (inst.opcode == Opcode.OP_decrement_i) ||
                 (inst.opcode == Opcode.OP_bitnot) ||
                 (inst.opcode == Opcode.OP_not) ||
                 (inst.opcode == Opcode.OP_negate) ||
                 (inst.opcode == Opcode.OP_negate_i) ||
                 (inst.opcode == Opcode.OP_setlocal))
        {
            return instrumentStack(inst, index, 1, 0, instructions);
        }
        
        // Stack with two values
        else if ((inst.opcode == Opcode.OP_add) ||
                 (inst.opcode == Opcode.OP_add_i) ||
                 (inst.opcode == Opcode.OP_swap) ||
                 (inst.opcode == Opcode.OP_bitand) ||
                 (inst.opcode == Opcode.OP_bitor) ||
                 (inst.opcode == Opcode.OP_bitxor) ||
                 (inst.opcode == Opcode.OP_modulo) ||
                 (inst.opcode == Opcode.OP_lshift) ||
                 (inst.opcode == Opcode.OP_rshift) ||
                 (inst.opcode == Opcode.OP_urshift) ||
                 (inst.opcode == Opcode.OP_multiply) ||
                 (inst.opcode == Opcode.OP_multiply_i) ||
                 (inst.opcode == Opcode.OP_subtract) ||
                 (inst.opcode == Opcode.OP_subtract_i) ||
                 (inst.opcode == Opcode.OP_divide))
        {
            return instrumentStack(inst, index, 2, 0, instructions);
        }
        
        // get/set property
        
        else if ((inst.opcode == Opcode.OP_setproperty) ||
                 (inst.opcode == Opcode.OP_initproperty))
        {
            uint s = getNameStackSize(inst.arguments[0].multinamev);
            return instrumentStack(inst, index, s+2, 0, instructions);            
        }
        else if ((inst.opcode == Opcode.OP_getproperty))
        {
            uint s = getNameStackSize(inst.arguments[0].multinamev);
            return instrumentStack(inst, index, 1, 0, instructions);
        }

        else return false;
    }
    
    // Generate trace()
    ASProgram.Instruction[] trace(string msg)
    {
        auto nsd = ns(ASType.PackageNamespace, "", 0);
        
        ASProgram.Instruction[] code = [
            {Opcode.OP_findproperty, [{multinamev:qn("trace", nsd)}]},
            {Opcode.OP_pushstring,   [{stringv:msg}]},
            {Opcode.OP_callpropvoid, [{multinamev:qn("trace", nsd)}, {ubytev:1}]},
        ];
        
        return code;
    }
    
    // Macros for generating multinames
    ASProgram.Namespace ns(ASType kind, string name, uint id)
    {
        auto n = new ASProgram.Namespace();
		n.kind = kind;
		n.name = name;
		n.id = id;
		return n;        
    }
 	ASProgram.Multiname qn(string name, ASProgram.Namespace ns)
	{
		auto n = new ASProgram.Multiname();
        n.kind = ASType.QName;
        n.vQName.name = name;
        n.vQName.ns = ns;
        return n;
    }
    
    bool instrumentMethodEntry(ASProgram.Instruction inst, ref ASProgram.Instruction[] instructions)
    {
        string opcode = "method_entry";
        
        if (!instrument_pkg)
            return false;
        
        if (!paramCount || !maxScopeDepth)
            return false;
            
        string s = opcode ~ ":" ~ currentSession ~ ":" ~ to!string(currentId) ~ ":" ~ to!string(0);
        
        if (hookOpcode(opcode))
        {
            if (verbose == true)
            {
                writefln("  %s", s);
            }
            uint local = localCount;
            auto nsd = ns(ASType.PackageNamespace, "", 0);
            
            ASProgram.Instruction[] code = [
            
                // Create a temporary scope stack
                {Opcode.OP_getlocal, [{uintv:0}]},
                {Opcode.OP_pushscope, [{}]},
                
                // getlex QName(PackageNamespace("instrument_package"), "Instrument")
                {Opcode.OP_getlex, [{multinamev:qn("Instrument", ns(ASType.PackageNamespace, instrument_pkg, 0))}]},
                
                // pushstring s        
                {Opcode.OP_pushstring, [{stringv:s}]},
                
                // First local (this)
                {Opcode.OP_getlocal, [{uintv:0}]},
                
            ];
            // Push rest
            for (auto i = 0; i < paramCount; i++)
            {
                ASProgram.Instruction getlocal = {Opcode.OP_getlocal, [{uintv:i+1}]};
                code ~= getlocal;
            }
            // Create array, call Instrument
            ASProgram.Instruction[] bcode = [
            
                {Opcode.OP_newarray, [{uintv:paramCount+1}]},
                {Opcode.OP_callpropvoid, [{multinamev:qn("InstrumentMethodEntry", nsd)}, {ubytev:2}]},
                {Opcode.OP_popscope, [{}]},
                inst,
            ];
            
            // Generate final instruction block
            instructions = code ~ bcode;
            
            // Update scope stack
            updateMaxScopeDepth(1);
            
            // Update stack
            updateStack(3 + cast(uint)paramCount);
            
            return true;
        }
        return false;
    }
    
    bool instrumentStack(
        ASProgram.Instruction inst,                 // instruction to be instrumented
        uint index,                                 // opcode index
        ulong objc,                                 // object arg count
        ulong argc,                                 // call/construct arg count
        ref ASProgram.Instruction[] instructions)   // reference to instruction array
    {
        if (! instrument_pkg)
            return false;
        
        string s = opcodeInfo[inst.opcode].name ~ ":" ~ currentSession ~ ":" ~ to!string(currentId) ~ ":" ~ to!string(index);

        if (hookOpcode(opcodeInfo[inst.opcode].name))
        {
            if (verbose == true)
            {
                writefln("  %s, objc: %d, argc: %d", s, objc, argc);
            }
            // First local
            uint local = localCount;
            
            auto nsd = ns(ASType.PackageNamespace, "", 0);
            
            // Save arguments to local variables
            ASProgram.Instruction[] acode;
            for (auto i = 0; i < argc+objc; i++)
            {
                ASProgram.Instruction setlocal = {Opcode.OP_setlocal, [{uintv:++local}]};
                acode ~= setlocal;
            }
            
            // Push them back to stack
            for (auto i = 0; i < argc+objc; i++)
            {
                ASProgram.Instruction getlocal = {Opcode.OP_getlocal, [{uintv:local-i}]};
                acode ~= getlocal;
            }
            
            ASProgram.Instruction[] bcode = [
                // Create a new array out of stack
                {Opcode.OP_newarray, [{uintv:argc+objc}]},
                // Set it as first available local
                {Opcode.OP_setlocal, [{uintv:localCount}]},
                // getlex QName(PackageNamespace("instrument_package"), "Instrument")
                {Opcode.OP_getlex, [{multinamev:qn("Instrument", ns(ASType.PackageNamespace, instrument_pkg, 0))}]},
                // pushstring s        
                {Opcode.OP_pushstring, [{stringv:s}]},
                // pushint objc ; argument index
                {Opcode.OP_pushint, [{uintv:objc}]},
                // getlocal n ; Array
                {Opcode.OP_getlocal, [{uintv:localCount}]},
                // callpropvoid  QName(PackageNamespace(""), "InstrumentStack"), 2
                {Opcode.OP_callproperty, [{multinamev:qn("InstrumentStack", nsd)}, {ubytev:3}]},
                // setlocal n ; Array
                // This contains now the (possibly) modified stack array, starting from argindex
                {Opcode.OP_setlocal, [{uintv:localCount}]},
            ];
            
            // Push args back to stack from locals - nothing is modified
            ulong i;
            for (i = 0; i < objc; i++)
            {
                ASProgram.Instruction getlocal = {Opcode.OP_getlocal, [{uintv:local-i}]};
                bcode ~= getlocal;
            }
            // Push rest of the args back to stack, by popping them off the array
            if (argc != 0)
            {
                auto ns_builtin = ns(ASType.Namespace, "http://adobe.com/AS3/2006/builtin", 0);
                ASProgram.Instruction getarray = {Opcode.OP_getlocal, [{uintv:localCount}]};
                ASProgram.Instruction undefined = {Opcode.OP_pushundefined, [{}]};
                ASProgram.Instruction popa = {Opcode.OP_callproperty, [{multinamev:qn("pop", ns_builtin)},{ubytev:0}]};
                ASProgram.Instruction pops = {Opcode.OP_pop, [{}]};
                ASProgram.Instruction dup = {Opcode.OP_dup, [{}]};

                for (; i < argc+objc; i++)
                {
                    // Branch offsets within the block
                    ulong i_iffalse = ((2*(argc+objc))) + 8 + objc + ((8*(i-objc))) + 6;
                    ulong i_jump = i_iffalse + 2;
                    
                    ASProgram.Instruction jump = {Opcode.OP_jump, [{uintv:cast(uint)i_jump}]};
                    ASProgram.Instruction ifeq = {Opcode.OP_ifeq, [{uintv:cast(uint)i_iffalse}]};
                    ASProgram.Instruction getlocal = {Opcode.OP_getlocal, [{uintv:local-i}]};
                    
                    bcode ~= getarray;
                    bcode ~= popa;
                    bcode ~= dup;
                    bcode ~= undefined;
                    bcode ~= ifeq; // undefined
                    bcode ~= jump; // ok
                    // undefined:
                    bcode ~= pops;
                    bcode ~= getlocal;
                    // ok:
                }
            }
            
            // Generate final instruction block
            
            // getproperty posthook:
            if (inst.opcode == Opcode.OP_getproperty)
            {
                ASProgram.Instruction[] xcode = [
                    // Save the property:
                    {Opcode.OP_setlocal, [{uintv:localCount}]},
                    // Get Instrument
                    {Opcode.OP_getlex, [{multinamev:qn("Instrument", ns(ASType.PackageNamespace, instrument_pkg, 0))}]},
                    // Push object
                    {Opcode.OP_getlocal, [{uintv:localCount+1}]},
                    // Push property
                    {Opcode.OP_getlocal, [{uintv:localCount}]},
                    // Call instumentation
                    {Opcode.OP_callproperty, [{multinamev:qn("InstrumentGetProperty", nsd)}, {ubytev:2}]},
                ];
                instructions = acode ~ bcode ~ inst ~ xcode;
                updateStack(6);
            }
            else
            {
                instructions = acode ~ bcode ~ inst;
                updateStack(4);
            }
            
            // Update locals
            
            updateLocal(cast(uint)(argc+objc) + 1);
            return true;
        }
        return false;
    }

    uint getNameStackSize(ASProgram.Multiname multiname)
	{
		if (multiname is null)
			return 0;
		else
        
		with (multiname)
		{
			switch (kind)
			{
				case ASType.QName:
				case ASType.QNameA:
                    return 0;
					break;
				case ASType.RTQName:
				case ASType.RTQNameA:
					return 1;
					break;
				case ASType.RTQNameL:
				case ASType.RTQNameLA:
                    return 2;
					break;
				case ASType.Multiname:
				case ASType.MultinameA:
					return 0;
					break;
				case ASType.MultinameL:
				case ASType.MultinameLA:
					return 1;
					break;
                // XXX ??
				//case ASType.TypeName:
				//	break;
				default:
					return 0;
			}
		}        
    }
}


