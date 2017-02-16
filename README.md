
# Reflash flash research framework

Reflash is a _proof-of-concept_ framework for analysing flash files. It produces a SQL database of flash VM stack trace by injecting dynamically generated instrumentation to flash files. The SQL database can later be analyzed with various tools.

Main features of Reflash:

- Extract embedded flash images
- Fetch and analyze the flash stack trace
- Run YARA over the stack values and disassembly
- Browse the database with a GUI tool, which works like a tradtional debugger
- Fake flash player version

__Reflash__ (capital 'R') refers to an overall framework, and `reflash` to a standalone instrumentation tool.

__Disclamer__: Reflash is a _proof-of-concept_. So no proper packaging or system-wide installation, or anything like that. It might crash and burn every now and then. If it works for you, I'm very happy for you. Please give me feedback on any problems you face, and of course please do share your success stories as well.



## reflash

`reflash` is the actual tool for flash file manipulation. Together with the Instrument library (in directory "instrument"), it forms an instrumentation environment much like Intel pin or Dynamorio.

`reflash` has the capability to insert hooks for arbitrary opcodes (in practice, not all opcodes are supported). There are three types of hooks supported by `reflash`:

- Method entry hook for collecting method arguments
- Generic opcode hook for collecting stack trace and manipulating function call arguments prior to execution
- Post opcode hook for manipulating stack values (only "getproperty" supported in current version)

In addition to inserting instrumentation, `reflash` can be used for disassembling and assembling any flash file.

For more information, please read the [reflash documentation](reflash/README.md).


## Instrument

Instrument library is responsible for analyzing and manipulating arguments sent by the instrumentation hooks. It is an standalone SWF file, but it is required to implement a specific API corresponding to the hook types described above. Instrument is configured statically prior to execution with a recompiler tool included in the distribution.

Please see the directory "instrument/instrument_package" for more details.


## Framework

Framework is built around `mitmproxy`, the python man-in-the-middle proxy. In addition to HTTP(S) proxy, Framework collects stack trace from Instrument. Collected stack trace is put to a SQL database for later inspection.

In the "framework" directory, a collection tools can be found:

- `proxy.py`: main proxy module, also a standalone command line tool
- `dbtool.py`: module for manipulating SQL database, also a standalone command line tool
- `run_file.sh`: frontend script for the proxy
- `run_live.sh`: frontend script for the proxy
- `logserver.py`: log server module, also a standalone command line tool
- `recompile.py`: module for manipulating Instrument SWF file, also a standalone command line tool
- `replay`: graphical frontend for the database
- `monitor`: graphical frontend for the proxy


## Replay

`replay` is a graphical frontend for the database. Main features include:

- Disassembly
- Stack trace
- Stack data hex view
- Step back and forth, set breakpoints
- Search data
- Run YARA


# Installation

Source installation is described here only for 64-bit Ubuntu 14.04/16.04 LTS. Other systems might have a bit different set of prerequisities, but the instructions should be applicable to most debian-based systems with minor tweaks.


### Install D-compiler

For compiling `reflash`, [D compiler](https://dlang.org/download.html#dmd) is required. Download and install the _.deb_ package corresponding to your environment (Ubuntu/Debian x86_64 in this example).

Install the package (for example 2.0.73.0):

```bash
$ sudo dpkg -i dmd_2.073.0-0_amd64.deb
```


### Compile reflash

For compression support, install liblzma development package:

```bash
$ sudo apt-get install liblzma-dev
```

With liblzma and DMD installed, compile `reflash` with the following commands:

```bash
$ cd framework
$ make
```
This should produce a compiled binary `reflash` and a symbolic link to it in directory "framework".


### Python tools and modules

For installing rest the python modules, you first need to install `pip` and few other dependencies:
```bash
$ sudo apt-get install git python-qt4 python-pip python-dev libffi-dev libssl-dev libtiff5-dev libjpeg8-dev zlib1g-dev libwebp-dev libxml2-dev libxslt1-dev
```

#### misc. packages with pip

```bash
$ sudo pip install psutil
$ sudo pip install yara-python
$ sudo pip install setuptools --upgrade
```

#### pyamf

```bash
$ git clone https://github.com/fmoo/pyamf.git
$ cd pyamf
$ python setup.py build
$ sudo python setup.py install
```
_Note: this is an unofficial pyamf module for extended AMF datatype support_. __Do not install the official pyamf with pip__.


#### mitmproxy

Reflash python modules are written in python2, so you need a latest 0.18.x version of mitmproxy (0.17.x _is not compatible_ with reflash). For default `pip` (pip2), this should be straightforward as this:

```bash
$ sudo pip install mitmproxy==0.18.3
```

Mitmproxy tries hard to get rid of python2, so the latest versions (1.0+) support _only_ python3. If `pip` fails to install version 0.18.x, you need to get the source from github with 0.18.x tag and do manual build (python setup.py build etc.)

#### selenium (optional)

If you wish to use Selenium framework (see notes on Automated browsing below):

```bash
$ sudo pip install selenium
```



# Usage

The most typical usage work flow is to run Reflash as a proxy for remote machine, typically sitting inside a VM on same host machine. If this is your plan, please make sure you have the target VM guest up and running at this point.

All usage is done from command line, in the directory "framework". So please "cd" back there, in case you ever went away.

All the tools support at least command line option __-h__ or __--help__ for getting help. Frontend scripts `run_file.sh` and `run_live.sh` redirect command line options to `proxy.py` so all these scripts accept the same command line options. Only exception to this rule is that `run_file.sh` requires at least one argument: the actual SWF to be analyzed.

Before going into typical use cases, let's first finish the installation by setting up the environment.

## Setting up the evironment with unittest.swf

`unittest.swf` (in directory "framework") is a simple SWF file for testing out the installation. After few test rounds, it displays a message _Hello Reflash!_ on browser screen.


### Configure you browser settings

Now go to your flash analysis target machine (it can be also on the same machine for testing) and configure the browser proxy settings to match the following:

- IP address or name: where your proxy runs
- Port: by default, mitmproxy uses __8080__

The browser also needs to have flash player installed (version 9+). If you want to test on a local machine, make sure to use Chrome (flash player included by default) or install __flashplayer-plugin__ package for firefox.

Now go back to your proxy machine, again to directory "framework".

### Test unittest.swf with run_file.sh

Please make sure that the interface variables in frontend scripts `run_file.sh` and `run_live.sh` match to your
setup:

```bash
interface='eth0'
```
IP address in above interface should match to the proxy server name/address configured to the target analysis machine proxy settings.

Execute the following command:

```bash
$ ./run_file.sh unittest.swf
```

If everything is set up correctly, you should see something like this in the console:
```
  dump dir: /tmp/tmp.c8JRweb6ED, database: unittest.swf.db, landing page: index.html
  Proxy started.
  Hit ENTER to abort.
```

Next:

- Open browser on your __target__ machine and type in _any url followed by index.html_ for example: http://example.com/index.html
- Expect to see something along these lines in the console:
```
  << Landing page request: http://example.com/index.html
  << Payload request: http://example.com/unittest.swf
  << Reflash request: http://example.com/dHsdKJab/loadBytes
     Content saved as /tmp/tmp.c8JRweb6ED/13b00a897d2314552f7816376535045f.swf
  << Reflash request: http://example.com/dHsdKJab/loadBytes
     Content saved as /tmp/tmp.c8JRweb6ED/0a7fb7924a02518a6d320ca6d62ac1c2.swf
  << Reflash request
     Content saved as /tmp/tmp.c8JRweb6ED/855e7a3e2fb1d05b02218b34d50de0d3.swf
  << Flash trace data
```
- After you see "Flash trace data" message, hit ENTER.
- Run `replay` and open the database `unittest.swf.db`.
- Mess around with the database.
- __Note:__ by default, `run_file.sh` sets proxy timeout for 120 seconds.

### Install mitmproxy CA cert (optional)

First run of the proxy produces a CA certificate directory, by default, "cadir" under "framework". For smooth mitmproxy experience, copy the file `mitmproxy-ca-cert.cer` from directory "cadir" to your __target__ machine and install the CA certificate (example for IE11 on Windows 7):

- Right-click `mitmproxy-ca-cert.cer`
- "Install cerificate"
- Choose "Place all cerificates in the following store"
- Choose "Trusted Root Certification Authorities"
- Next, finish, Yes

Example for firefox:

- Open Preferences->Advanced->Certificates
- Click "View Certificates"
- Click "Import"
- Select `mitmproxy-ca-cert.cer`
- Choose "Trust this CA to identify websites"
- Press OK

CA cert installation is not _absolutely_ needed for Reflash, but for live sessions it is good to have.

## Test live connection with run_file.sh

From command line, run:

```bash
$ ./run_live.sh
```
Now go back to your target browser and type in URL http://www.adobe.com/software/flash/about/ (or some other site you know hosting some simple flash files). You should see few files coming in to your console. After "Flash trace data" message, press ENTER and open the file `live.db` (default file se by `run_live.sh`) with `replay`:

```bash
$ ./replay -f live.db
```


## Console messages

### Proxy started

Proxy is running.

### Landing page request

Proxy is serving the supplied landing page in "file" mode.

### Payload request

Proxy is serving the supplied payload in "file" mode.

### Flash content detected

Proxy detected SWF in "live" mode

### Reflash request

Embedded SWF is sent back to proxy for instrumentation.

### Flash trace data

Trace data received. This is the most important console message to monitor (if you want to abort the trace before timeout) because if it is missing, there is no data put to SQL database.

If there is no data, message "Nothing was logged." is written to console after trace termination.


  
## Analyzing standalone files

Standalone files are simple to analyze because there are no complicating factors, like javascript interaction with a live server. All the action happens in a closed circuit between Reflash proxy and the browser. This also means it limits the targets down to a simple, standalone files. Most modern Exploit Kits require some sort of interaction from a live server. Some go even so far that they cannot be correctly replayed using web replay dumps, such as [Fiddler](http://www.telerik.com/fiddler).

If your file is suitable for standalone analysis (most likely just a random file from VirusTotal _is not_), you can try out running it like `unittest.swf` in the above example. If you suspect the file requires arguments, you can supply them to the example `index.html` (see __FlashVars__). You can naturally build whatever supporting interaction is required in the landing page, but that is out of scope of this document.


## Analyzing live web traffic

For most cases like live Exploit Kits, live mode is what you want to use. Using Reflash in live mode is simple: run `run_live.sh` or just leave on "live" option in `monitor` and make sure the _timeout_ is long enough. When you think you captured all interesting exection (look for "Flash trace data" messages on the console), just press "Stop" (or ENTER when using command line tools).

It should noted that __all__ flash execution is monitored and logged in a single database during a live session. This can be observed nicely by browsing to [Adobe flash player test page](https://www.adobe.com/software/flash/about/) in live mode. It loads (at least) three simple SWF files.


# Advanced topics

## YARA

Reflash has integrated support for running YARA in the context of stack values and disassembly text. YARA scan can be activated automatically after the trace using any of the command line tools with command line option __--yara__ or with `dbtool.py` by directly manipulating ready-made database. See the usage of `dbtool.py` with __--help__.

In the GUI tool `replay`, YARA rules can be loaded with Ctrl+Y (Search->Run yara).

Example rules file `misc.yara` contains few rules detecting entities such as embedded SWF and some simple Exploit Kit shellcodes.


## Upstream proxy

Proxy tools can be instructed to forward all requests to an upstream proxy, for example [Fiddler](http://www.telerik.com/fiddler).

- Run Fiddler as upstream proxy for Reflash: start proxy with command line option __-U proxy_URL__ (for example -U http://localhost:9999)
- If you plan to run Fiddler on a same machine, you need to configure Fiddler as a standalone proxy. Open _Tools->Fiddler Options->Connections_
 * Use some other port than 8080 (Reflash proxy default) or 8888 (Reflash log server default), for example 9999
 *  Uncheck "Act as a system proxy on startup"
 *  Uncheck "Monitor all connections"
 * Check "Allow remote computers to connect"

## Automated browsing

There is a rudimentary support for running automated browsing with the proxy, using [Selenium](http://www.seleniumhq.org/). In order to activate that, please first read the Selenium documentation for setting up Selenium hub and node. In short, you need to run hub, most likely in the proxy machine (could be remote as well) and a node in __target__ machine.

If you want to play with this, please use proxy command line options __--browse__ and __--hub__ or JSON settin "hub" in "proxyConfig" (see below). By default, proxy sets up the webdriver connection with Internet Explorer default capabilities. For tweaking the capabilities, you need to edit function __run_browser__ in `proxy.py`.

Running hub on the local machine is as simple as downloading [Selenium standalone](http://www.seleniumhq.org/download/) and running the jar file:

```bash
$ java -jar selenium-server-standalone-3.0.1.jar -role hub
```

Setting up Selenium node for running Internet Explorer is described [in this document](https://github.com/SeleniumHQ/selenium/wiki/InternetExplorerDriver).

For even more automated configuration, please see the example script `run_vm.sh` in directory "framework". It uses VirtualBox for running preconfigured Selenium nodes.


## config.json

Some tools also use a JSON configuration file in addition to command line options. This can be supplied with cmdline options __-c__. JSON file has two sections: "proxyConfig" for proxy tools and "reflashConfig" for `reflash`.

Supported settings in `config.json`:

proxyConfig:
- "address" - IP address of the proxy
- "logdir" - directory for storing logs and other temporary data
- "logport" - log server port
- "proxyport" - proxy server port
- "cadir" - CA cert directory
- "dumpdir" - directory for storing dumps
- "upstream" - upstream proxy URL, for example Fiddler
- "landing_page" - landing page file
- "timeout" - timeout in seconds
- "tag" - loadBytes tag used by Instrument
- "namespace" - javascript namespace used by Instrument
- "package" - AS3 package name used by Instrument
- "noInstrument" - array of MD5 hashes for files not to be instrumented
- "version" - Fake flash player version (see notes below on faking flash version)
- "player" - Fake flash player type (see notes below on faking flash version)
- "os" - Fake flash player OS type (see notes below on faking flash version)
- "flash_in" - Flash instrument template file
- "flash_out" - Generated flash instrument file name
- "hub" - Selenium hub URL (something like http://localhost:4444/wd/hub)

reflashConfig:
- "input" - input file
- "output" - output file
- "work_dir" - temporary working directory (relative for 'i'-mode, absolute for 'd' and 'a')
- "inject" - instrument to inject
- "inject_pkg" - instrument package name
- "stream" - store stream disassembly to file
- "id" - session identifier in stream disassembly
- "quiet" - be quiet
- "dbg" - produce debug output, keep temp files etc.
- "opcodeHooks" - array of opcode hooks (please read the [reflash documentation](reflash/README.md))

Typically, you don't need to touch `config.json` because proxy automates for example template flash file generation. But you could for example set up a series of configuration files for different fake flash player versions etc.


## Faking flash version

Flash version information faking is a powerful feature implemented with the reflash post-opcode hooking mechanism. It is very useful for automated triggering of flash exploits that depend on specific flash version.

This feature can be configured with proxy command line options __--version__, __--os__ and __--player__, or alternatively with `config.json` settings "version", "os" and "player". There is some basic checking on the format of these setting:

- Version string must be an OS identification string and comma separated list of numbers indicating Major and Minor versions, according [to this document](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/system/Capabilities.html#version) For example: "WIN 21,0,0,192".
- OS type string typically consist of two strings, OS and version, example: "Windows XP". Please read [this document](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/system/Capabilities.html#os) for correct version format.
- Player type string must be [one of these](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/system/Capabilities.html#playerType), for example "ActiveX".


# Hacking / debugging tips

If you bump into application that doesn't like to be reflashed, it is a good practice to run it under debug flash player and use something like [Vizzy](https://github.com/capilkey/Vizzy-Flash-Tracer) for logging flash debug messages.

Each instrument hook prints out a trace message like this:

```bash
  InstrumentStack: callproperty:0-1:195:249
```

In the event of crash, the debug flash player most likely prints out an error message before stopping. Usually it is possible to get an idea of the bug by following the InstrumentStack trace messages right before the crash. You can then manually instrument the problematic file and disassemble it:

```bash
$ reflash i --input problem.swf --config config.json
$ reflash d --input problem.swf.reflash --dir <disasm_dir>
```

Then try to "grep" the hook identifier trace message "callproperty..." for locating the exact place where the trace message is coming from and work your way from there.

It might also be a good approach to start debugging problems by limiting Reflash features. For example, for making sure the proxy framework works in general, try first running the session with "noflash" flag (-x in command line tools). Next level of intrusiveness could be running `reflash` with non-matching/bogus "opcodeHooks" in `config.json`. Next, start adding hooks one by one, first "method_entry", followed by "callpropvoid" etc.

If you think the logging is the problem, create `Instrument.swf` without logging (`recompile` -T).

Note that most Exploit Kit flash files refuse to run under debug flash player.

Good luck!


# Licence 

GPL v3 or later.
