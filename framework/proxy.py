#! /usr/bin/env python


import sys
import os
import time
import signal
import dbtool
import logserver
import tempfile
import subprocess
import shutil
import shlex
import psutil
import socket
import threading
import hashlib
import base64
import json
import struct
import string
import random
import re

from optparse import OptionParser

import mitmproxy
from mitmproxy import flow, controller
from mitmproxy.proxy import ProxyServer, ProxyConfig
from mitmproxy.models import HTTPResponse
from netlib.http import Headers
from netlib.http import url
from netlib import tcp

import dbtool
import logserver
import recompile


def rand_str(size=6, chars=string.ascii_lowercase + string.ascii_uppercase):
    return ''.join(random.choice(chars) for _ in range(size))

# Reflash executable
reflash_cmd=os.path.normcase("./reflash")

# Reflash errors - update if reflash.d enum ReflashError changes !
reflash_error_codes = [
    "REFLASH_ERROR_NO_ERROR", 
    "REFLASH_ERROR_GENERIC",
    "REFLASH_ERROR_FILE",
    "REFLASH_ERROR_WORKDIR",
    "REFLASH_ERROR_NOT_SWF",
]

class ReflashProxy(flow.FlowMaster):
    def run(self):
        flow.FlowMaster.run(self)
        
    def excluded(self, path, md5):
        if self.options.noinst_flash == True:
            return True
        if len(self.options.excludes) == 0:
            return False
        if md5 == None:
            f = open(path, "rb")
            swf = f.read()
            md5 = hashlib.md5(swf).hexdigest()
        if md5 in self.options.excludes:
            self.options.log_cb("<< Instrumentation excluded")
            return True
        else:
            return False

    def reflash(self, path, md5):
        remove = True
        if self.excluded(path, md5) == False:
            rpath = reflash_cmd + " i --input %s --stream %s/s%d.txt --id %d --config %s --inject_pkg %s --inject %s" % \
                (path, self.options.logdir, self.options.sid, self.options.sid, self.options.config, self.options.package, self.options.flash_out)
            try:
                status = subprocess.call(rpath, shell=True)
                if status == 0:
                    f = open(path + ".reflash", "rb")
                else:
                    if status <= len(reflash_error_codes):
                        status_msg = reflash_error_codes[status]
                    else:
                        status_msg = "UNKNOWN"
                    self.options.log_cb("   Reflash status: %s (%d)" % (status_msg, status))
                    f = open(path, "rb")
            except Exception,e:
                self.options.log_cb(e.strerror)
                f = open(path, "rb")
        else:
            remove = False
            f = open(path, "rb")
        swf = f.read()
        f.close()
        if remove == True and os.path.exists(path + ".reflash"):
            os.remove(path + ".reflash")
        self.options.sid = self.options.sid + 1
        return swf

    def instrument_error(self):
        return HTTPResponse(
            "HTTP/1.1", 400, "Bad request",
            Headers(Content_Type="text/html"),
            "<html><body>Instrument error</body></html>")

    def simple_http(self):
        return HTTPResponse(
            "HTTP/1.1", 200, "OK",
            Headers(Content_Type="text/html"),
            "<html><body>Hello world!</body></html>")

    def simple_flash(self, swf):
        return HTTPResponse(
            "HTTP/1.1", 200, "OK",
            Headers(content_type="application/x-shockwave-flash-%s" % \
                self.options.tag, content_length=str(len(swf))),
            swf)
        
    def inline_flash(self, swf):
        content = base64.standard_b64encode(swf)
    
        return HTTPResponse(
            "HTTP/1.1", 200, "OK",
            Headers(content_type="text/html", content_length=str(len(content))),
            content)

    def landing_page(self):
        return HTTPResponse(
            "HTTP/1.1", 200, "OK",
            Headers(Content_Type="text/html"), self.options.lpage)

    @controller.handler
    def request(self, flow):

        # 1. Check if the request ends in landing page:
           
        if self.options.mode == "sandbox" and flow.request.path and \
            flow.request.path.endswith(self.options.lbasename):
            
            self.options.log_cb("<< Landing page request: " + flow.request.url)
            resp = self.landing_page()
            flow.response = resp
    
        # 2. Check for initial flash: reflash
    
        elif self.options.mode == "sandbox" and flow.request.path and \
            flow.request.path.endswith(self.options.ibasename):
            self.options.log_cb("<< Payload request: " + flow.request.url)
            resp = self.simple_flash(self.reflash(self.options.input, None))
            flow.response = resp
        
        # 3. Check if the request is "/loadBytes": reflash and serve
        
        elif flow.request.path and flow.request.path.endswith(self.options.tag + "/loadBytes"):
            self.options.log_cb("<< Reflash request: " + flow.request.url)

            content = base64.standard_b64decode(flow.request.content)
            md5 = hashlib.md5(content).hexdigest()
            if md5 in self.options.instrumented:
                self.options.log_cb("<< Already instrumented")
                resp = self.instrument_error()
            else:
                tmp_swf = self.options.dumpdir + "/" + md5 + ".swf"
                f = open(tmp_swf, "wb")
                f.write(content)
                f.close()
                self.options.log_cb("   Content saved as " + tmp_swf)
                instrumented = self.reflash(tmp_swf, md5)
                resp = self.inline_flash(instrumented)
                self.options.instrumented[hashlib.md5(instrumented).hexdigest()] = True
            flow.response = resp

        # Everything else:
        else:
            #self.options.log_cb("<< Web request: " + flow.request.url)
            if (self.options.mode == "sandbox"):
                resp = self.simple_http()
                flow.response = resp

    @controller.handler
    def response(self, flow):
        if not flow.response.headers.get("content-type"):
            return
        # Pass instrumented flash
        if flow.response.headers["content-type"] == "application/x-shockwave-flash-%s" % self.options.tag:
            flow.response.headers["content-type"] = "application/x-shockwave-flash"
        elif "content-type" in flow.response.headers and \
            flow.response.headers["content-type"] == "application/x-shockwave-flash":
            self.options.log_cb(">> Flash content detected, reflashing...")
            stripped = flow.response.content.rstrip('\n').strip('\n')
            md5 = hashlib.md5(stripped).hexdigest()
            tmp_swf = self.options.dumpdir + "/" + md5 + ".swf"
            f = open(tmp_swf, "wb")
            f.write(stripped)
            f.close()
            self.options.log_cb("   Content saved as " + tmp_swf)
            flow.response.content = self.reflash(tmp_swf, md5)
    
    def tick(self, timeout):
        if self.stopEvent.isSet():
            self.shutdown()
        return super(flow.FlowMaster, self).tick(timeout)


def run_mitmproxy(options, event):
    mode = "regular"

    upstream = None
    if options.upstream:
        upstream = options.upstream
        mode = "upstream"

    opts = mitmproxy.options.Options(
        mode=mode,
        listen_port=int(options.proxyport),
        cadir=os.path.abspath(options.cadir),
        upstream_server=upstream
    )
    config = ProxyConfig(opts)
    
    state = flow.State()
    server = ProxyServer(config)
    proxy = ReflashProxy(opts, server, state)
    proxy.options = options
    proxy.options.sid = 0
    proxy.options.instrumented = {}
    if not proxy.options.input:
        proxy.options.mode = "pass"
    else:
        proxy.options.mode = "sandbox"
    
    proxy.stopEvent = event
    proxy.run()


def run_logserver(options, event):
    server = logserver.LogServer(('', int(options.logport)), logserver.TCPConnection)
    server.timeout = 0.1
    
    logserver.TCPConnection.log_files = {}
    logserver.TCPConnection.logdir = options.logdir
    logserver.TCPConnection.log_cb = staticmethod(options.log_cb)

    while True:
        if event.isSet():
            break
        server.handle_request()

    for v in logserver.TCPConnection.log_files.itervalues():
        v.close()
    server.server_close()

def run_sleeper(t, event):
    event.wait(t)

def verify_config(options):
    # Defaults
    if not options.logport:
        options.logport = 8888
    if not options.proxyport:
        options.proxyport = 8080
    
    # Must have settings:
    if not options.dumpdir:
        return 0
    if not options.logdir:
        return 0
    if options.input and not options.landing_page:
        return 0
    if options.landing_page and not options.input:
        return 0
    if options.input and not os.path.exists(options.input):
        return 0
    if options.landing_page and not os.path.exists(options.landing_page):
        return 0
    
    # Make directories, if not existing:
    if not os.path.isdir(options.dumpdir):
        os.makedirs(options.dumpdir)
    if not os.path.isdir(options.logdir):
        os.makedirs(options.logdir)

    # Create instrumentation files from templates
    if not options.package:
        options.package = rand_str(size=8)
    if not options.namespace:
        options.namespace = rand_str(size=8)
    if not options.tag:
        options.tag = rand_str(size=8)
        
    options.quiet = True
    options.trace = True
    if not options.flash_out:
        options.flash_out = options.logdir + "/tmp.swf"
    if not recompile.recompile(options):
        return 0
    
    # Read landing page
    if options.landing_page:
        options.lbasename = os.path.basename(options.landing_page)
        options.ibasename = os.path.basename(options.input)
        with open(options.landing_page, "rb") as file:
            options.lpage = file.read()
            options.lpage = options.lpage.replace('##INPUT##', options.ibasename)

    return 1

def run_proxy(options, event):
    if not verify_config(options):
        options.log_cb("Error: illegal options.")
        return 0

    options.log_cb("Proxy started.")
    
    # Run proxy
    p = threading.Thread(target=run_mitmproxy, args=(options,event))
    p.start()
    
    # Run logserver
    l = threading.Thread(target=run_logserver, args=(options,event))
    l.start()
    
    # Run sleeper
    s = threading.Thread(target=run_sleeper, args=(int(options.timeout),event))
    s.start()
    
    timeout = 0.1
    while True:
        # Some of the threads is down, shutdown all other threads:
        if not s.isAlive() or not p.isAlive() or not l.isAlive():
            event.set()
            break
        event.wait(timeout)

    return 1

def run_browser(options, event):
    from selenium import webdriver
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
    options.browser = None
    try:
        driver = webdriver.Remote(
            command_executor=options.hub,
            desired_capabilities=webdriver.DesiredCapabilities.INTERNETEXPLORER,
            )
        driver.get(options.url)
    except:
        options.log_cb("Cannot open url %s, check Selenium hub/node." % options.url)
        return

    options.browser = driver
    return

def read_json_config(options):

    with open(options.config) as data:
        json_data = json.load(data)
        if not "proxyConfig" in json_data:
            return
        if "logdir" in json_data["proxyConfig"]:
            options.logdir = json_data["proxyConfig"]["logdir"].encode('utf-8')
        if "address" in json_data["proxyConfig"]:
            options.address =  json_data["proxyConfig"]["address"].encode('utf-8')
        if "logport" in json_data["proxyConfig"]:
            options.logport =  json_data["proxyConfig"]["logport"]
        if "proxyport" in json_data["proxyConfig"]:
            options.proxyport =  json_data["proxyConfig"]["proxyport"]
        if "cadir" in json_data["proxyConfig"]:
            options.cadir =  json_data["proxyConfig"]["cadir"].encode('utf-8')
        if "dumpdir" in json_data["proxyConfig"]:
            options.dumpdir =  json_data["proxyConfig"]["dumpdir"].encode('utf-8')
        if "upstream" in json_data["proxyConfig"]:
            options.upstream = json_data["proxyConfig"]["upstream"].encode('utf-8')
        if "landing_page" in json_data["proxyConfig"]:
            options.landing_page =  json_data["proxyConfig"]["landing_page"].encode('utf-8')
        if "timeout" in json_data["proxyConfig"]:
            options.timeout =  json_data["proxyConfig"]["timeout"]
        if "tag" in json_data["proxyConfig"]:
            options.tag =  json_data["proxyConfig"]["tag"].encode('utf-8')
            
        if "namespace" in json_data["proxyConfig"]:
            options.namespace =  json_data["proxyConfig"]["namespace"].encode('utf-8')
        if "package" in json_data["proxyConfig"]:
            options.package =  json_data["proxyConfig"]["package"].encode('utf-8') 
        if "version" in json_data["proxyConfig"]:
            options.version =  json_data["proxyConfig"]["version"].encode('utf-8')
        if "player" in json_data["proxyConfig"]:
            options.player =  json_data["proxyConfig"]["player"].encode('utf-8')
        if "os" in json_data["proxyConfig"]:
            options.os =  json_data["proxyConfig"]["os"].encode('utf-8')
            
        if "flash_in" in json_data["proxyConfig"]:
            options.flash_in =  json_data["proxyConfig"]["flash_in"].encode('utf-8')
        if "flash_out" in json_data["proxyConfig"]:
            options.flash_out =  json_data["proxyConfig"]["flash_out"].encode('utf-8')        
        
        if "hub" in json_data["proxyConfig"]:
            options.hub =  json_data["proxyConfig"]["hub"].encode('utf-8')        
        
        if "noInstrument" in json_data["proxyConfig"]:
            for ex in json_data["proxyConfig"]["noInstrument"]:
                options.excludes[ex] = True

# Common options for all proxy apps:
def read_cmdline(argv, opt_parser):
    opt_parser.add_option('-a', '--address', dest = 'address', default="127.0.0.1",  help = 'Log server IP address (default=127.0.0.1)')
    opt_parser.add_option('-i', '--input', dest = 'input', help = 'Input SWF')
    opt_parser.add_option('-c', '--config', default="config.json", dest = 'config', help = 'Configuration file, overrides cmdline (default="config.json")')
    opt_parser.add_option('-d', '--dumpdir', default="dumps", dest = 'dumpdir', help = 'Dump directory (default="dumps")')
    opt_parser.add_option('-D', '--logdir', dest = 'logdir', help = 'Log directory')
    opt_parser.add_option('-l', '--landing_page', dest = 'landing_page', help = 'Landing page HTML file')
    opt_parser.add_option('-t', '--timeout', default="60", dest = 'timeout', help = 'Timeout in seconds (default=60)')
    opt_parser.add_option('-L', '--logport', dest = 'logport', default="8888", help = 'Logserver port (default=8888)')
    opt_parser.add_option('-P', '--proxyport', dest = 'proxyport', default="8080", help = 'Proxy port (default=8080)')
    opt_parser.add_option('-U', '--upstream', dest = 'upstream', help = 'Upstream proxy')
    opt_parser.add_option('-C', '--cadir', default="cadir", dest = 'cadir', help = 'CA certificate directory (default="cadir")')
    opt_parser.add_option('-T', '--tag', dest = 'tag', help = 'loadBytes tag (default=random)')
    opt_parser.add_option('-x', '--noflash', action = 'store_true', dest = 'noinst_flash', default=False, help = 'Do not instrument flash (default=false)')
    opt_parser.add_option('-N', '--namespace', dest = 'namespace', help = 'Javascript namespace (default=random)')
    opt_parser.add_option('-g', '--package', dest = 'package', help = 'Instrument package name (default=random)')
    opt_parser.add_option('-I', '--flash_in', dest = 'flash_in', help = 'Flash instrument template file')
    opt_parser.add_option('-O', '--flash_out', dest = 'flash_out', help = 'Generated flash instrument file (default="logdir/tmp.swf")')
    opt_parser.add_option('-v', '--version', dest = 'version', default="None", help = 'Fake version in format "OSS n,n,n,n" (default="None")')
    opt_parser.add_option('-S', '--os', dest = 'os', default="None", help = 'Fake OS version (default="None")')
    opt_parser.add_option('-R', '--player', dest = 'player', default="None", help = 'Fake player type (default="None")')
    opt_parser.add_option('-b', '--browse', dest = 'url', help = 'Open URL with Selenium hub')
    opt_parser.add_option('-H', '--hub', dest = 'hub', help = 'Selenium hub URL')

    (options,args) = opt_parser.parse_args(argv)
    
    options.excludes = {}

    if options.config:
        read_json_config(options)

    return options


# Proxy cmdline app

def main(argv):
    
    def yara_cb(event, data, rule):
        print ("[%.8d]  %s (rule: %s)" % (event, repr(data), rule))
        sys.stdout.flush()
        
    def log_cb(string):
        print string
        sys.stdout.flush()
        if string == "Proxy started.":
            print "Hit ENTER to abort."
            sys.stdout.flush()
        
    usage = "Usage: %prog [Options]"
    opt_parser = OptionParser(usage=usage)
    opt_parser.add_option('-o', '--output', default="replay.db", dest = 'output', help = 'Output database (default="replay.db")')
    opt_parser.add_option('-r', '--raw', dest = 'raw', help = 'Produce raw output from database')
    opt_parser.add_option('-p', '--pretty', dest = 'pretty', help = 'Produce pretty output from database')
    opt_parser.add_option('-y', '--yara', dest = 'yara', help = 'Run yara file against the database')
    opt_parser.add_option('-k', '--keep', action = 'store_true', dest = 'keep', help = 'Leave temporary log files (default=false)')

    options = read_cmdline(argv, opt_parser)
    
    if options.input and not os.path.exists(options.input):
        print "Input file doesn't exist!"
        sys.exit(0)
    
    if (options.landing_page and not options.input):
        print "Please provide the input file"
        sys.exit(0)
            
    if (options.input and not options.landing_page):
        print "Please provide landing page for the input file"
        sys.exit(0)

    # Create a temporary directory
    if not options.logdir:
        options.logdir = tempfile.mkdtemp()
    if (options.keep):
        print ("Log dir: %s" % options.logdir)
        sys.stdout.flush()

    event = threading.Event()
    options.log_cb = log_cb

    x = threading.Thread(target=run_proxy, args=(options, event))
    x.start()
    t = threading.Thread(target=sys.stdin.read, args=(1,))
    t.daemon = True
    t.start()

    # Extra thread for local Selenium browsing
    if options.url:
        browser = threading.Thread(target=run_browser, args=(options, event))
        browser.daemon = True
        browser.start()

    timeout = 0.1
    while True:
        if not x.isAlive(): break # Proxy has died
        if not t.isAlive():
            event.set()
        time.sleep(timeout)
        
    print "Aborting..."
    sys.stdout.flush()    
    # Kill browser
    if options.url:
        if options.browser != None:
            try:
                options.browser.quit()
            except:
                print "Selenium hub/node is not responding."
        else:
            print "Note: Selenium driver never returned."

    print "Creating database, please wait..."
    sys.stdout.flush()
    if dbtool.create(options.logdir, options.output):
        print "Done."
        sys.stdout.flush()
        if options.raw: dbtool.raw(out, options.raw)
        if options.pretty: dbtool.pretty(options.output, options.pretty)
        if options.yara:
            dbtool.runyara(options.yara, options.output, yara_cb)
    else:
        print "Nothing was logged."
        sys.stdout.flush()
    if options.keep == None:
        shutil.rmtree(options.logdir)

    sys.exit(1)

if __name__ == "__main__":
     main(sys.argv[1:])

