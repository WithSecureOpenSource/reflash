# Reflash - ActionScript instrumentation

`reflash` is the core instrumentation tool in the Reflash framework. It links against the extraordinary [RABCDAsm](http://github.com/CyberShadow/RABCDAsm) library directly, so it is itself also written in the D-language.

For more technical overview, please refer to [Reflash research paper](../reflash_paper.pdf).


## Basic usage

Typically, `reflash` is run transparently in the context of Reflash framework proxy. For manual usage, run `reflash` without any command line option to get the help text:

```bash
$ reflash

Usage: reflash <cmd> <args>

  Commands (one required):
    i|instrument        Instrument file defined with --input
    d|disassemble       Disassemble file defined with --input
    a|assemble          Assemble from directory defined with --dir

  Arguments:
    --input  <swf>      Input flash file.
    --inject <swf>      Inject a flash file.
    --output <swf>      Output flash file (default=<input>.reflash)
    --dir    <path>     Working directory (default=random tmp dir)
    --config <file>     Load configuration from JSON file (overrides cmdline)
    --stream <file>     Produce a stream disassembly
    --id     <string>   Session id for stream disassembler
    --debug             Be verbose and leave temporary files for further inspection.
    --quiet             Be very quiet.
    -h|--help           This message.

```

### Instrument

This is the most common mode of operation. You need to provide at least:

- Input file with __--input__
- Injected SWF with __--inject__ (typically __Instrument.swf__ generated with `recompile`)
- Configuration file with __--config__ describing the instrumentation hooks etc. (see __Configuration__ below)

Internally, __instrument__ executes __disassemble__ and __assemble__ modes after instrumentation and merging the injected SWF.

### Disassemble

This mode is sometimes needed to work with problematic files, but of course it can used as a generic flash disassembler.

- Input file with __--input__
- Output directory with __--dir__

`reflash` writes a bunch of files to the directory __--dir__. All the SWF blocks in __input__ are written in subdirectories `block-0` .. `block-N` (usually just block-0). In subdirectories, the disasseblies are stored according to their AS hierarchy with file extension _.asasm_, for example:

```bash
block-0/block-0.main.asasm
block-0/mx/core/ByteArrayAsset.class.asasm
```
Disassemblies are ASCII files, so you can easily for example _grep_ them through.

### Assemble

This mode takes a directory structure prepared by __disassemble__ mode and assembles it back to a valid SWF. 

- Output file with __--output__
- Input directory with __--dir__


## Configuration

`reflash` can be configured from command line and using a JSON configuration file. JSON file _always_ overrides command line.

Settings related to `reflash` in configuration file:

"reflashConfig":

- "input" - input file
- "output" - output file
- "work_dir" - temporary working directory (relative for 'i'-mode, absolute for 'd' and 'a')
- "inject" - instrument to inject
- "inject_pkg" - instrument package name
- "stream" - store stream disassembly to file
- "id" - session identifier in stream disassembly
- "quiet" - be quiet
- "dbg" - produce debug output, keep temp files etc.
- "opcodeHooks" - array of opcode hooks

Most of these are self-evident or explained above, or in the Reflash main README.md.

### Stream disassembly file

In __instrument__ mode, __Stream disassembly__ writes __all__ disassemblies to a single file in very streamlined format and stores it to the working directory. The purpose of this is to help database tool when associating stack trace to disassemblies.

### Session identifier

This is just a simple textual prefix used internally for separating different sessions (individual SWF files in proxy "live"-mode). Typically, no need to touch this.

### Opcode hooks

This is an array of regexp strings describing opcodes to hook. A very reasonable default set of hooks is in `config.json`:

```bash
"opcodeHooks":[
        "call.*",
        "init.*",
        ".etproperty",
        "construct.*"
]
```

More hooks mean more stack trace. Extreme case of instrumentation is to have a single catch-all regexp __".*"__. That makes flash execution very slow and doesn't really provide too much useful information in addition to the default settings.

In order to activate all the useful features in `Instrument.swf`, it is adviced to have at least __"call.*"__ and __"getproperty"__.


This is the list of supported opcodes:

```bash
constructprop
callproperty
callproplex
callsuper
callsupervoid
callpropvoid
call
callstatic
callmethod
construct
constructsuper
setlocal0
setlocal1
setlocal2
setlocal3
pop
dup
increment
increment_i
decrement
decrement_i
bitnot
not
negate
negate_i
setlocal
add
add_i
swap
bitand
bitor
bitxor
modulo
lshift
rshift
urshift
multiply
multiply_i
subtract
subtract_i
divide
initproperty
setproperty
getproperty

```
