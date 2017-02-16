#! /usr/bin/env python

#
# NOTE: this is a HACK, highly dependent on the structure of Instrument.as !!
# If you need to modify Instrument more than this script does, well then you need to have Flex
# installed and should us it instead.
#

import glob
import sys
import os
import re
import tempfile
import shutil
import fileinput
import subprocess
from optparse import OptionParser
import re

# Reflash executable
reflash_cmd=os.path.normcase("./reflash")

# Templates
package_template="instrument_package"
address_template="##IP_ADDRESS##"
port_template="##PORT##"
namespace_template="##NAMESPACE##"
tag_template="##TAG##"
trace_template="##TRACE##"
version_template="##VERSION##"
os_template="##OS##"
player_template="##PLAYERTYPE##"

def replace(s1, s2, filename):
    for line in fileinput.input(filename, inplace=True):
        print line.replace(s1, s2),
        
    return True

def recompile(options):
    player = options.player
    os = options.os

    if options.version == "None":
        version = options.version
    else:
        scan = re.compile(r'([A-Z][A-Z][A-Z]) (\d+),(\d+),(\d+),(\d+)')
        result = scan.match(options.version)
        try:
            r = result.groups()
        except:
            if options.quiet == False:
                print "Error: incorrect version format (OS n,n,n,n)"
            return 0
        if ((r[0] == "WIN") or (r[0] == "MAC") or (r[0] == "LNX") or (r[0] == "AND")) and (int(r[1]) >= 9):
            version = r[0] + " " + r[1] + "," + r[2] + "," + r[3] + "," + r[4]
        else:
            if options.quiet == False:
                print "Error: incorrect version format (WIN|MAC|LNX|AND 9+,n,n,n)"
            return 0
        
    if options.quiet == False:
        print "address:", options.address
        if options.logport == "8888":
            print "port:", options.logport, "(default)"
        else:
            print "port:", options.logport
        if options.package == "instrument_package":
            print "package:", options.package, "(default)"
        else:
            print "package:", options.package
        if options.namespace == "NameSpace":
            print "namespace:", options.namespace, "(default)"
        else:
            print "namespace:", options.namespace
        if options.tag == "reflash":
            print "tag:", options.tag, "(default)"
        else:
            print "tag:", options.tag
        print "trace:", options.trace
        print "version:", version
        print "os:", os
        print "player:", player
        
    if options.trace == True:
        trace = "True"
    else:
        trace = "False"
        
    tmpdir = tempfile.mkdtemp()
    
    # reflash d --input Instrument.swf --dir tmpdir
    subprocess.call(reflash_cmd + " d --input " + options.flash_in + " --dir " + tmpdir, shell=True)
    
    replace(package_template,   options.package,   tmpdir + "/block-0/block-0.main.asasm")
    replace(package_template,   options.package,   tmpdir + "/block-0/instrument_package/Instrument.script.asasm")
    replace(package_template,   options.package,   tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(address_template,   options.address,   tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(port_template,      options.logport,   tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(namespace_template, options.namespace, tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(tag_template,       options.tag,       tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(trace_template,     trace,             tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(version_template,   version,           tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(os_template,        os,                tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(player_template,    player,            tmpdir + "/block-0/instrument_package/Instrument.class.asasm")
    replace(package_template,   options.package,   tmpdir + "/block-0/instrument_package/Base64.script.asasm")
    replace(package_template,   options.package,   tmpdir + "/block-0/instrument_package/Base64.class.asasm")
    
    # rename instrument_package -> package
    shutil.move(tmpdir + "/block-0/" + package_template, tmpdir + "/block-0/" + options.package)
    
    # reflash a --dir tmpdir --quiet
    subprocess.call(reflash_cmd + " a --dir " + tmpdir + " --quiet", shell=True)
    
    shutil.copyfile(tmpdir + "/tmp.swf", options.flash_out)
    shutil.rmtree(tmpdir)
    
    if options.quiet == False:
        print 'Done.'
    return 1

def main(argv):
    opt_parser = OptionParser()
    opt_parser.add_option('-i', '--input', dest = 'flash_in', help = 'Instrument template file')
    opt_parser.add_option('-o', '--output', dest = 'flash_out', default="Instrument.swf", help = 'Output file (default="Instrument.swf")')
    opt_parser.add_option('-p', '--package', dest = 'package', default="instrument_package", help = 'Instrument package name (default="instrument_package")')
    opt_parser.add_option('-a', '--address', dest = 'address', default="127.0.0.1",  help = 'Log server IP address (default=127.0.0.1)')
    opt_parser.add_option('-P', '--port', dest = 'logport', default="8888", help = 'Log server port (default=8888)')
    opt_parser.add_option('-n', '--namespace', dest = 'namespace', default="NameSpace",  help = 'JavaScript namespace (default="NameSpace")')
    opt_parser.add_option('-t', '--tag', dest = 'tag', default="reflash",  help = 'loadBytes identifier tag (default="reflash")')
    opt_parser.add_option('-T', '--trace', action = 'store_false', default=True, dest = 'trace', help = 'Do not send trace log (default=false)')
    opt_parser.add_option('-q', '--quiet', action = 'store_true', default=False, dest = 'quiet', help = 'Be quiet (default=False)')
    opt_parser.add_option('-v', '--version', dest = 'version', default="None", help = 'Fake version in format "OSS n,n,n,n" (default="None")')
    opt_parser.add_option('-O', '--os', dest = 'os', default="None", help = 'Fake OS version (default="None")')
    opt_parser.add_option('-L', '--player', dest = 'player', default="None", help = 'Fake player type (default="None")')
    
    (options,args) = opt_parser.parse_args(argv)
    
    if not options.flash_in:
        print "Please provide input file with --input"
        sys.exit(1)

    return recompile(options)


if __name__ == "__main__":
     main(sys.argv[1:])
