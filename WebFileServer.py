#!/usr/bin/env python

from __future__ import division, print_function, with_statement

import os
import sys
import cgi
import uuid
import json
import shutil
import urllib
import posixpath
import mimetypes
from stat import *
from datetime import date
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

VERSION = '1.2.0'


class LocalFileStorage(object):

    def __init__(self, path, options={}):
        self.path = path
        self.options = options

    def save(self, filename, filecontent):
        basename = str(uuid.uuid4()).replace("-", "")
        if not self.options.get('noext'):
            _, extname = os.path.splitext(filename)
            if extname:
                basename += extname.lower()

        if self.options.get('hashdir'):
            storepath = basename[:2] + "/" + basename[2:4]
            storename = basename[4:]
        else:
            storepath = date.today().strftime('%Y/%m/%d')
            storename = basename

        filepath = (self.path + "/" + storepath).replace("//", "/")

        try:
            os.makedirs(filepath)
        except OSError as e:
            pass

        try:
            with open(filepath + "/" + storename, "wb") as fp:
                fp.write(filecontent)

            return storepath + "/" + storename
        except:
            return ""

    def info(self, pathname):
        try:
            stat = os.stat(self.path + "/" + pathname)
            if S_ISREG(stat.st_mode):
                return True, stat.st_size, stat.st_mtime
        except:
            pass

        return False, 0, 0

    def copyfileobj(self, pathname, fdst):
        try:
            with open(self.path + "/" + pathname, "rb") as fsrc:
                shutil.copyfileobj(fsrc, fdst)
        except:
            pass


class WebFileServerRequestHandler(BaseHTTPRequestHandler):

    def log_request(self, code):
        pass

    def do_HEAD(self):
        exists = False
        pathname = self._parse_pathname()
        if pathname:
            exists, size, mtime = self.server.storage.info(pathname)

        if not exists:
            self.send_response(404)
        else:
            self.send_response(200)
            self.send_header("Content-type", self._guest_type(pathname))
            self.send_header("Content-Length", str(size))
            self.send_header("Last-Modified", self.date_time_string(mtime))
            self.end_headers()

    def do_GET(self):
        exists = False
        pathname = self._parse_pathname()
        if pathname:
            exists, size, mtime = self.server.storage.info(pathname)

        if not exists:
            self.send_response(404)
        else:
            self.send_response(200)
            self.send_header("Content-type", self._guest_type(pathname))
            self.send_header("Content-Length", str(size))
            self.send_header("Last-Modified", self.date_time_string(mtime))
            self.end_headers()
            self.server.storage.copyfileobj(pathname, self.wfile)

    def do_POST(self):
        if self.path != '/upload':
            self.send_response(404)
        elif self.headers.getheader('upload-token') != self.server.upload_token:
            self.send_response(406)
        else:
            ctype, _ = cgi.parse_header(
                self.headers.getheader('content-type')
            )
            if ctype != 'multipart/form-data':
                self.send_response(406)
            else:
                self._process_upload(cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': self.headers['Content-Type']
                    }
                ))

    def _parse_pathname(self):
        path = self.path
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = posixpath.normpath(urllib.unquote(path))
        return None if path.find('../') != -1 else path

    def _guest_type(self, path):
        _type, _ = mimetypes.guess_type(path)
        return "application/octet-stream" if not _type else _type

    def _process_upload(self, form):
        response = {}
        keys = [x for x in form.keys() if form[x].filename]
        for key in keys:
            field = form[key]
            path = self.server.storage.save(field.filename, field.value)
            if path:
                response[key] = path

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response))


class WebFileServer(ThreadingMixIn, HTTPServer):

    def __init__(self, address, upload_token, storage):
        self.storage = storage
        self.upload_token = upload_token
        HTTPServer.__init__(self, address, WebFileServerRequestHandler)


################################################
from optparse import *


def execute(upload_token, path, options):
    mimetypes.init()
    storage = LocalFileStorage(path, {
        'noext': options.noext,
        'hashdir': options.hashdir
    })
    httpd = WebFileServer(
        (options.address, options.port),
        upload_token,
        storage
    )
    httpd.serve_forever()


def daemonize():
    try:
        pid = os.fork()
        if pid:
            sys.exit(0)
    except OSError as e:
        print("fork #1:", e)
        sys.exit(1)

    os.setsid()
    os.chdir("/")
    os.umask(0)
    try:
        pid = os.fork()
        if pid:
            sys.exit(0)
    except OSError as e:
        print("fork #2:", e)
        sys.exit(1)

    rnull = open("/dev/null", "r")
    wnull = open("/dev/null", "w")
    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(rnull.fileno(), sys.stdin.fileno())
    os.dup2(wnull.fileno(), sys.stdout.fileno())
    os.dup2(wnull.fileno(), sys.stderr.fileno())


def direct_main():
    parser = OptionParser("%prog [options] <upload-token> <storage-path>", version=VERSION,
                          description="Tiny hash file server")
    parser.add_option("-b", "--address",
                      dest="address", default="",
                      help="net address for bind")
    parser.add_option("-p", "--port",
                      type="int", dest="port", default="8000",
                      help="net port for bind, default 8000")
    parser.add_option("-N", "--noext",
                      action="store_true", dest="noext", default=False,
                      help="not reserve origin file extname")
    parser.add_option("-H", "--hashdir",
                      action="store_true", dest="hashdir",  default=False,
                      help="sote path use 'hash' style (xx/xx), default 'day' style (YYYY/mm/dd)")
    parser.add_option("-d", "--daemon",
                      action="store_true", dest="daemon", default=False,
                      help="start as daemon process (Unix/Linux)")

    if len(sys.argv) > 1:
        sys_argv = sys.argv
    else:
        sys_argv = [sys.argv[0], "--help"]

    (options, args) = parser.parse_args(sys_argv)

    if len(args) < 3:
        parser.print_help()
        sys.exit(-1)

    upload_token = args[1]
    storage_path = args[2]
    try:
        stat = os.stat(storage_path)
    except:
        raise Exception('Storage path not accesable')

    if not S_ISDIR(stat.st_mode):
        raise Exception('Storage path not directory')

    if not options.daemon or os.name != "posix":
        execute(upload_token, storage_path, options)
    else:
        daemonize()
        execute(upload_token, storage_path, options)


def main():
    try:
        direct_main()
    except Exception as e:
        print('Terminate:', e)


if __name__ == '__main__':
    main()
