#!/usr/bin/python3
# netrepl.py

from sys import argv
import json
import struct
import os
import sys
import socket
from time import time, sleep, strftime
import subprocess
import argparse
import getpass

# imports related to genhash
import hashlib
import binascii


MPY_EXLCUDES = ("boot.py", 
				"natives.py",
				"main.py",
				"mysecrets.py")

##################
# START WEBREPL
##################
WEBREPL_REQ_S = "<2sBBQLH64s"
WEBREPL_PUT_FILE = 1
WEBREPL_GET_FILE = 2
WEBREPL_GET_VER  = 3

class websocket:

	def __init__(self, s):
		self.s = s
		self.buf = b""
		self.debug = False

	def writetext(self, data):
		#print("writetext: ", len(data), data)
		l = len(data)
		if l < 126:
			hdr = struct.pack(">BB", 0x81, l)
		else:
			hdr = struct.pack(">BBH", 0x81, 126, l)
		self.s.send(hdr)
		self.s.send(data)

	def write(self, data):
		l = len(data)
		if l < 126:
			# TODO: hardcoded "binary" type
			hdr = struct.pack(">BB", 0x82, l)
		else:
			hdr = struct.pack(">BBH", 0x82, 126, l)
		self.s.send(hdr)
		self.s.send(data)

	def recvexactly(self, sz):
		res = b""
		while sz:
			#print("recvexactly: in while loop")
			data = self.s.recv(sz)
			if not data:
				break
			res += data
			sz -= len(data)
		#print("rcvexactly", res)
		return res

	def debugmsg(self, msg):
		if self.debug:
			print(msg)

	def read(self, size, text_ok=False, size_match=True):
		if not self.buf:
			while True:
				hdr = self.recvexactly(2)
				assert len(hdr) == 2
				fl, sz = struct.unpack(">BB", hdr)
				if sz == 126:
					hdr = self.recvexactly(2)
					assert len(hdr) == 2
					(sz,) = struct.unpack(">H", hdr)
				if fl == 0x82:
					break
				if text_ok and fl == 0x81:
					break
				self.debugmsg("[i] Got unexpected websocket record of type %x, skipping it" % fl)
				while sz:
					skip = self.s.recv(sz)
					self.debugmsg("[i] Skip data: %s" % skip)
					sz -= len(skip)
			data = self.recvexactly(sz)
			assert len(data) == sz
			self.buf = data

		d = self.buf[:size]
		self.buf = self.buf[size:]
		if size_match:
			assert len(d) == size, len(d)
		#print("read",d)
		return d

	def ioctl(self, req, val):
		assert req == 9 and val == 2

class Webrepl:

	def __init__(self, **params):
		self.host = self.getkey(params,"host")
		self.port = self.getkey(params,"port")
		self.password = self.getkey(params,"password")
		self.debug = self.getkey(params,"debug")
		self.verbose = self.getkey(params,"verbose")
		self.noauto = self.getkey(params,"noauto")
		self.timeout = self.getkey(params,"timeout")

		self.s=None
		self.ws=None

		self.connected=False

		if self.port == None:
			self.port = 8266

		if self.host != None and not self.noauto:
			self.connect(self.host, self.port)
		if self.password != None and self.ws != None and not self.noauto:
			self.login(self.password)

	def getkey(self, dict, key):
		if key in dict:
			return dict[key]
		return None

	def debugmsg(self, msg):
		if self.debug:
			print(msg)

	def client_handshake(self, sock):
		cl = sock.makefile("rwb", 0)
		cl.write(b"""\
GET / HTTP/1.1\r
Host: echo.websocket.org\r
Connection: Upgrade\r
Upgrade: websocket\r
Sec-WebSocket-Key: foo\r
\r
""")
		l = cl.readline()
  		#    print(l)
		while 1:
			l = cl.readline()
			if l == b"\r\n":
				break
		#sys.stdout.write(l)

	def connect(self, host, port):
		self.debugmsg("[d] connecting to %s %s" % (host,port))
		self.debugmsg("timeout: {}".format(self.timeout) )
		self.s = socket.socket()
		if self.timeout is not None:
			self.s.settimeout(self.timeout)
		ai = socket.getaddrinfo(host, port)
		addr = ai[0][4]
		#self.debugmsg("connecting to adr %r" % addr)

		self.s.connect(addr)
		#s = s.makefile("rwb")
		self.debugmsg("[d] handshake")
		self.client_handshake(self.s)
		self.ws = websocket(self.s)
		self.ws.debug = self.debug

	def disconnect(self):
		if self.s != None:
			self.s.shutdown(1)
			self.s.close()
		self.s = None
		self.ws = None

	def login(self, passwd):
		self.debugmsg("[d] login as %s" % passwd)
		while True:
			c = self.ws.read(1, text_ok=True)
			if c == b":":
				assert self.ws.read(1, text_ok=True) == b" "
				break
		self.ws.write(passwd.encode("utf-8") + b"\r")
		self.debugmsg("[d] login sent %s" % passwd)
		resp = self.ws.read(64, text_ok=True, size_match=False)
		# b'\r\nWebREPL connected\r\n>>> '
		# b'\r\nAccess denied\r\n'
		if b"WebREPL connected" in resp:
			self.connected=True
		self.debugmsg("[d] login resp %s" % resp)

	def pastecmd(self, cmd):
		return self.sendcmd(cmd, line_end=b"\r")
	
	def sendcmd(self, cmd, size=1024, line_end=b"\r\n"):
		if not self.connected:
			return b""
		self.debugmsg("[d] sending cmd %s" % cmd)
		bcmd = cmd.encode("utf-8")
		if cmd == chr(3):
			self.ws.writetext(bcmd)
		else:
			self.ws.writetext(bcmd + line_end)
		self.debugmsg("[d] getting response")
		resp = b''
		if cmd == chr(4):
			self.debugmsg("Ctrl-d sent!")
			return b''
		# print("cmd={}, resp={}".format(bcmd,resp))
		timeout = time() + 10
		while cmd != chr(3) and bcmd not in resp and (timeout - time() > 0):
		# while bcmd not in resp and (timeout - time() > 0):
			resp = self.read_cmd(size)
			if resp == b'\r\n=== ':
				break
			self.debugmsg("[d] got response %s" % resp)
		#print("cmd={}, resp={}".format(cmd,resp))
		return resp

	def read_cmd(self, size):
		resp=b''
		newline=False
		while True:
			try:
				r=self.ws.read(size, text_ok=True, size_match=False)
				# print("---{}---".format(r))
				# self.debugmsg("got %s %d" % (r, len(r)))
			except KeyboardInterrupt:
				raise KeyboardInterrupt
			except:
				#print("Timeout waiting for response!")
				return b''
			if r == b'>>> ' and newline:
				# print("breaking")
				break
			#print(newline, len(r), r)
			if r == b'\r\n=== ':
				#print("breaking ===")
				resp = r
				break
			if r[-2:] == b'\r\n':
				# print("newline true")
				newline=True
			else:
				# print("newline false")
				newline=False
			resp = resp + r
		# print("resp: ", resp)
		return resp

	def read_resp(self):
		data = self.ws.read(4)
		sig, code = struct.unpack("<2sH", data)
		assert sig == b"WB"
		return code


	def send_req(self, op, sz=0, fname=b""):
		rec = struct.pack(WEBREPL_REQ_S, b"WA", op, 0, 0, sz, len(fname), fname)
		self.debugmsg("[d] Sent request %r %d" % (rec, len(rec)))
		self.ws.write(rec)

	def set_binary(self):
		# Set websocket to send data marked as "binary"
		self.ws.ioctl(9, 2)

	def get_ver(self):
		if self.connected:
			self.send_req(WEBREPL_GET_VER)
			d = self.ws.read(3)
			d = struct.unpack("<BBB", d)
			return d

	def put_file(self, local_file, remote_file):
		sz = os.stat(local_file)[6]
		dest_fname = (remote_file).encode("utf-8")
		rec = struct.pack(WEBREPL_REQ_S, b"WA", WEBREPL_PUT_FILE, 0, 0, sz, len(dest_fname), dest_fname)
		self.debugmsg("[d] put file struct %r %d" % (rec, len(rec)))
		self.ws.write(rec[:10])
		self.ws.write(rec[10:])
		assert self.read_resp() == 0
		cnt = 0
		with open(local_file, "rb") as f:
			while True:
				if self.verbose:
					sys.stderr.write("[i] Sent %d of %d bytes\r" % (cnt, sz))
					sys.stderr.flush()
				buf = f.read(1024)
				if not buf:
					break
				self.ws.write(buf)
				cnt += len(buf)
		if self.verbose:
			sys.stderr.write("\n")
		assert self.read_resp() == 0

	def get_file_content(self, remote_file):
		content=b''
		src_fname = (remote_file).encode("utf-8")
		rec = struct.pack(WEBREPL_REQ_S, b"WA", WEBREPL_GET_FILE, 0, 0, 0, len(src_fname), src_fname)
		self.debugmsg("[d] get file content struct %r %d" % (rec, len(rec)))
		self.ws.write(rec)
		assert self.read_resp() == 0
		cnt = 0
		while True:
			self.ws.write(b"\0")
			(sz,) = struct.unpack("<H", self.ws.read(2))
			if sz == 0:
				break
			while sz:
				buf = self.ws.read(sz)
				if not buf:
					raise OSError()
				cnt += len(buf)
				content = content + buf
				sz -= len(buf)
				if self.verbose:
					sys.stderr.write("[i] Received %d bytes\r" % cnt)
					sys.stderr.flush()
		if self.verbose:
			sys.stderr.write("\n")
		assert self.read_resp() == 0
		return content

	def get_file(self, remote_file, local_file):
		src_fname = (remote_file).encode("utf-8")
		rec = struct.pack(WEBREPL_REQ_S, b"WA", WEBREPL_GET_FILE, 0, 0, 0, len(src_fname), src_fname)
		self.debugmsg("[d] get file struct %r %d" % (rec, len(rec)))
		self.ws.write(rec)
		assert self.read_resp() == 0
		with open(local_file, "wb") as f:
			cnt = 0
			while True:
				self.ws.write(b"\0")
				(sz,) = struct.unpack("<H", self.ws.read(2))
				if sz == 0:
					break
				while sz:
					buf = self.ws.read(sz)
					if not buf:
						raise OSError()
					cnt += len(buf)
					f.write(buf)
					sz -= len(buf)
					if self.verbose:
						sys.stderr.write("[i] Received %d bytes\r" % cnt)
						sys.stderr.flush()
		if self.verbose:
			sys.stderr.write("\n")
		assert self.read_resp() == 0


#################
# END WEBREPL
#################

# Local genhash function
# TODO: use string to define a function?
		
def genhash(file):
	file_hash = hashlib.sha256()
	try:
		with open(file, "rb") as handle:
			buf = handle.read(100)
			while buf:
				file_hash.update(buf)
				buf = handle.read(100)	
		return binascii.hexlify(file_hash.digest())
	except:
		return b'FileNotFound'


genhash_func = """
import uhashlib
import ubinascii
def genhash(file):
	file_hash = uhashlib.sha256()
	with open(file, "rb") as handle:
		buf = handle.read(100)
		while buf:
			file_hash.update(buf)
			buf = handle.read(100)	
	print(ubinascii.hexlify(file_hash.digest() ) )
"""

# exec(genhash_func)

parser = argparse.ArgumentParser(prog="mpyrepl")
parser.add_argument("-b", action="store_true", help="send extra breaks")
parser.add_argument("-v", action="store_true", help="verbose")
parser.add_argument("-vv", action="store_true", help="debug")
parser.add_argument("-c", action="store_true", help="tail console")
parser.add_argument("-e", metavar="module.py", help="execute module in repl, showing ouput")
parser.add_argument("-strict", action="store_true", help="strict checking")
parser.add_argument("-m", action="store_true", help="copy .mpy version of module if possible")
parser.add_argument("-f", action="store_true", help="force copy even if older")
parser.add_argument("-d", action="store_true", help="cleanup/delete .py versions when copying .mpy to remote")
parser.add_argument("-n", action="store_true", help="don't actually do anything, dry run")
parser.add_argument("-r", action="store_true", help="reboot node, do actions (if any) first")
parser.add_argument("nodename")
parser.add_argument("cmd", nargs="?", default="", choices=["ls", "put", "sync", "backup", "init", ""],)
parser.add_argument("args", nargs="*", default=[""], metavar="[dir | file1, file2]")

#print(argv)

# print(parser.parse_args(argv[1:]))
# exit()

# decorator to retry various functions
def retry(func):
	def wrapper_retry(*args, **kwargs):
		count = 0
		retries = 3
		while count < retries:
			try:
				func(*args, **kwargs)
				return True
			except KeyboardInterrupt:
				print("sendcommand: Ctrl-C ! Stopping")
				return False
			count += 1
	return wrapper_retry

class File:
	def __init__(self, path="", size=-1, exists=False, is_dir=False) -> None:
		self.path = path
		self.hash = ""
		self.size = size
		self.exists = exists
		self.date_modified = 0.0
		self.is_dir = is_dir


# Recursive function takes a .py file and looks for imported
# modules not native to micropython
# returns a full list of all imported modules as a list of .py files
# that can be used to update related files

# A short list of internal micropython modules I use
# TODO: Generate or use a complete list from ?? to check for these

skip = ("#", "umqtt.simple", "bluetooth", "ubinascii",
		"uhashlib", "random",
		"struct", "dht", "uasyncio", "asyncio", 
		"neopixel", "machine", "time", "network", 
		"ntptime", "ubinascii", "gc", "json",
		"webrepl")

def find_imports(filename) -> list:
	found = [filename]
	try:
		with open(filename) as file:
			line = file.readline()
			while line:
				if "import" in line or "from" in line:
					items = line.strip().split(" ")
					if (items[1] not in skip and "#" not in items[0]):
						if items[0] == "from" or items[0] == "import":
							nextfile = items[1] + ".py"
							#print("looking at: ", nextfile)
							found += find_imports(nextfile)
				line = file.readline()
	except FileNotFoundError:
		pass

	return found

def connect(host, password=None, timeout=70, debug=True, verbose=True) -> Webrepl:
	if password is None:
		password = os.environ.get("WRPWD")
		if password is None:
			password = getpass.getpass("Enter webrepl password: ")
	session = Webrepl()
	#print("after 1st Webrepl(), before session while loop")
	for i in range(5):
		try:
			start_time = time()
			print("Connecting to: {} (timeout={})".format(host, timeout))
			session = Webrepl(**{'host':host, 
					'password': password,
					'timeout':timeout,
					'debug': debug,
					'verbose': verbose})
			if session.connected:
				return session
		except KeyboardInterrupt:
			print("in connect: Ctrl-C!")
			exit()
		except:
			print("Connect timed out, retry={} in 10 seconds".format(i) )

		while time() - start_time < 11:
			sleep(1)
	return None
			
def tail_console(session) -> bool:
	user_exit = False
	
	while not user_exit:
		try:
			print(session.ws.read(100,text_ok=True, size_match=False).decode(), end='')				
		except KeyboardInterrupt:
			user_exit = True
		except Exception as error:
			print(error)
			break
	return user_exit

def send_break(session, xtra_breaks=False) -> bool:
	print("Sending break(s) ...")
	if xtra_breaks:
		for i in range(15):
			session.sendcmd(chr(3))
			sleep(1)
	else:
		session.sendcmd(chr(3))
		sleep(1)
	r = session.sendcmd('webrepl')
	#print("result: ", r)
	return b'module' in r

	# def sendcommand(self, cmd, src=None, dst=None, retries=3) -> bool:
	# 	self.result = ""
	# 	count = 0
	# 	while count < retries:
	# 		try:
	# 			#print(prefix, src, dst)
	# 			if src is None:
	# 				self.result = str(cmd())
	# 			else:
	# 				if dst is None:
	# 					self.result = str(cmd(src))
	# 				else:
	# 					self.result = str(cmd(src, dst))
	# 			return True
	# 		except KeyboardInterrupt:
	# 			self.stop = True
	# 			print("sendcommand: Ctrl-C ! Stopping")
	# 			return False
	# 		# except:
	# 		# 	print("Error: cmd={}, src={}, dst={} - retry#: {}".format(cmd, src, dst, retries))
	# 		# 	return False
	# 		count += 1
	# 	return False
	
	# def remote_mkdir(self, path) -> bool:
	# 	remote_dir = File(path)
	# 	self.remote_stat(remote_dir)
	# 	if remote_dir.exists and remote_dir.is_dir:
	# 		return True
	# 	self.sendcommand(self.session.sendcmd, 'uos.mkdir("{}")'.format(path) )
	# 	if "Error" in self.result:
	# 		print(self.result)
	# 		return False
	# 	return True
	
	# def local_mkdir(self, path) -> bool:
	# 	try:
	# 		os.mkdir(path)
	# 		return True
	# 	except FileExistsError:
	# 		return True
	# 	except:
	# 		return False

def remote_stat(session, file: File) -> bool:
	result = str(session.sendcmd('uos.stat("{}")'.format(file.path) ))
	if "Error" in result:
		#print(self.result)
		return False
	try:
		if "32768" in result.split(",")[0]:
			file.size = int( result.split(",")[6] )
			# adjust to match local machine (epoch 1970 add 946684800)
			file.date_modified = float( result.split(",")[7] ) + 946684800
			file.exists = True
		if "16384" in result.split(",")[0]:
			print("{} is a directory".format(file.path) )
			file.is_dir = True
			file.exists = True
		return True
	except:
		print("Error parsing results from stat()")
	return False

def local_stat(file: File) -> bool:
	try:
		stats = os.stat(file.path)
		# print("mode: ", stats.st_mode)
		if stats.st_mode == 33261 or stats.st_mode == 33188:
			file.size = int(stats.st_size)
			file.date_modified = stats.st_mtime
			file.exists = True
		if stats.st_mode == 16877:
			print("{} is a directory".format(file.path) )
			file.is_dir = True
		return True
	except FileNotFoundError:
		# print("File not found local: {}".format(file.path))
		file.exists = False
	except:
		print("Error parsing results from stat()")
	return False
	
	# def compare_file(self, src: File, dst: File) -> bool:
	# 	if os.path.exists(src.path):
	# 		self.local_stat(src)
	# 		self.remote_stat(dst)
	# 	elif os.path.exists(dst.path):
	# 		self.local_stat(dst)
	# 		self.remote_stat(src)
	# 	else:
	# 		return False
		
	# 	if src.size == dst.size:
	# 		return True
	# 	else:
	# 		return False

	# def local_listdir(self, src="") -> list:
	# 	if src == "":
	# 		src = "."
	# 	return os.listdir(src)

def remote_listdir(session, path="") -> list:
	try:
		result = str(session.sendcmd('uos.listdir("{}")'.format(path)))
		#print(result)
		slashed = result.replace("'",'"')
		#print(slashed)
		slashed = slashed.replace('b"uos.listdir("{}")\\r\\n'.format(path),'{"files": ')
		#print(slashed)
		slashed = slashed.replace('\\r\\n"','}')
		#print(slashed)
		files_json = slashed.replace("\\","")
		#print(files_json)
		return json.loads(files_json)['files']
	except:
		print("Error getting remote filelist!")
	return []
		
def show_remote_dir(session, path=""):
	print("Directory: {}".format(path) )
	for filename in remote_listdir(session, path):
		file = File(filename)
		remote_stat(session, file)
		print("{}  {}  {}".format(file.path, file.size, file.date_modified))

def put_file(session, source_name, dest_name="", dryrun=True, use_mpy=False, cleanup=False) -> File:
	error_copying = File("error_copying", exists=False)
	error_hashfile = File("error_hashfile", exists=False)

	# Do not use .mpy for boot and main or if not a .py file
	if source_name in MPY_EXLCUDES or ".py" not in source_name:
		use_mpy = False

	# Only use mpy if it's a .py file
	if use_mpy:
		# generate .mpy and make this the source file
		#print("using .mpy for {}".format(source_name))
		source_file = File(make_mpy(source_name))
		dest_file = File(source_file.path)
	else:
		# Use original file name as source
		#print("using {}".format(source_name))
		source_file = File(source_name)
		if dest_name == "":
			#print("source name:", source_name)
			dest_name = source_name.split("/")[-1:][0]
			#print("dest_name", dest_name)
		dest_file = File(dest_name)

	#print("after: ", source_name, dest_name)
	
	missing_source = File("missing_source", exists=False)
	if not local_stat(source_file):
		return missing_source

	# directory is handled by calling function
	if source_file.is_dir:
		return source_file

	dest_file.hash = hash_remote(session, dest_file.path)
	source_file.hash = hash_local(source_file.path)

	#print("hashes: src=", source_file.hash, "dst=", dest_file.hash)

	# Do not overwrite existing secrets!
	#print("desthash: ", dest_file.hash)
	if 'mysecrets' in source_name and 'Error' not in dest_file.hash:
		print("skip   : mysecrets already exists")
		return dest_file
	
	# Skip if hash same or copy it
	if source_file.hash == dest_file.hash:
		print("skip   : {}".format(source_file.path) )
	else:
		# Either copy it or say we will
		if dryrun:
			print("replace: {} ({})".format(source_file.path, source_file.size) )
		else:
			session.put_file(source_file.path, dest_file.path )
			new_hash = hash_remote(session, dest_file.path)

			if new_hash != source_file.hash:
				# print("local: ", remote_file.path, remote_file.size)
				# Stop here if copy fails
				print("Error copying {}".format(dest_file.path))
				return error_copying
			
			# Success!
			print("copied : {} ({} bytes)".format(dest_file.path, dest_file.size) )

	# Cleanup .py if .mpy was copied or exists
	if use_mpy:
		py_file = File(source_name)
		if remote_stat(session, py_file):
			if py_file.exists:
				if dryrun:
					print("remove : {}".format(source_name))
				else:
					try:
						result = session.sendcmd('uos.remove("{}")'.format(source_name))
						if b'Error' not in result:
							print("removed: {}".format(source_name) )
						else:
							print("error  : {} not removed!".format(source_name) )
					except:
						print("Error  : {} not removed!".format(source_name) )

	return dest_file

def make_mpy(source):
	filename = source.split("/")[-1:][0]
	output_name = filename.split(".")[0] + ".mpy"
	rc = subprocess.run("mpy-cross {} -o {}".format(source, output_name), shell=True)
	if rc.returncode > 0:
		print("Error ({}) generating {}".format(rc.returncode, output_name))
		return ""
	return output_name
		
def get_file(session, source_name, dryrun=True) -> File:
	source_file = File(source_name)
	dest_file = File(source_name)
	missing_remote = File("missing_remote", exists=False)
	error_copying = File("error_copying", exists=False)

	if not remote_stat(session, source_file):
		return missing_remote

	if source_file.is_dir:
		return source_file

	error_hashfile = File("error_hashfile", exists=False)

	source_file.hash = hash_remote(session, source_file.path)
	dest_file.hash = hash_local(dest_file.path)

	# print("hashes: src=", source_file.hash, "dst=", dest_file.hash)

	# If already exists and hashes match, skip
	# print(self.local_stat(local_file) )
	if source_file.hash == dest_file.hash:
		print("{} - confirmed same".format(source_file.path) )
		return source_file

	print("Copying {}".format(source_file.path))
	session.get_file(source_file.path, dest_file.path)
	local_stat(dest_file)
	# print("local: ", remote_file.path, remote_file.size)
	if dest_file.size == source_file.size:
		#print("copied {} ({} bytes)".format(remote_file.path, local_file.size) )
		return source_file
	
	print("Error copying {}".format(source_file.path))
	return error_copying

def backup(session, nodename, path="."):
	backup_dir = "{}/{}.{}".format(path, nodename, strftime("%Y%m%d") )
	try:
		os.mkdir(backup_dir)
	except FileExistsError:
		pass
	except:
		print("Could not create backup dir {}".format(backup_dir))
		return False

	try:
		os.chdir(backup_dir)
	except:
		print("Failed to switch to directory {}".format(backup_dir) )
		return False

	print("Backing up node: {} to {}".format(nodename, backup_dir))		
	print("Current dir:",os.getcwd())

	total_files = 0
	total_bytes = 0

	for file in remote_listdir(session):
		result = get_file(session, file)
		if result.is_dir:
			print("Skipping dir {}".format(file))
			continue
		if result.size == 0:
			print("Error copying {}".format(file))
			continue
		total_files += 1
		total_bytes += result.size

	print("backed up {} files ({} bytes)".format(total_files, total_bytes))

def reboot_node(session):
	result = session.sendcmd('reboot()')
	if b'REBOOTING' in result:
		print("Reboot confirmed!")
		return True
	else:
		print("Reboot failed!")
		return False

# hash_remote returns string with hash or:
# "FileNotFound" = genhash remote function returned no file found
# "HashError" = genhash was not created or had some other error
# If remote genhash function not there, try to upload it

def hash_remote(session, filename) -> str:
	error_hashfile = File("error_hashfile", exists=False)
	hash = session.sendcmd('genhash("{}")'.format(filename) )
	
	if hash and b'NameError' in hash:
		# If NameError, hash function not loaded, load and try again
		print("genhash() not found, sending ...")
		exec_remote_list(session, genhash_func.split("\n"))

		newhash = session.sendcmd('genhash("{}")'.format(filename) )
		#print("newhash: ", newhash)
		# If failed again, return empty hash
		if newhash and b'NameError' in newhash:
			print("genhash not found!")
			return "UndefinedError"
		hash = newhash

	if hash and b'ENOENT' in hash:
		return "FileNotFoundError"
	
	try:
		return hash.decode('UTF-8').split("\'")[1]
	except:
		return "HashDecodeError"

def hash_local(filename) -> str:
	hash = genhash(filename)
	try:
		return hash.decode('UTF-8')
	except:
		return ""

class FakeRepl:
	def __init__(self, nodename) -> None:
		self.connected = True
		self.host = nodename
		self.result = ""

	def sendcommand(self, cmd, src=None, dst=None, retries=3) -> bool:
		print("cmd: {}, src={}. dst={}".format(cmd, src, dst))
		self.result = cmd + " : results!"
		return True
	
	def send_break(self):
		print("Break!\n\n>>>\n")
		return True
	def reboot_node(self):
		print("reboot()\n1\n2\n3...")
	def console(self):
		print("11:11:11 nodename console logging ...")
	def backup(self):
		print("backup node!")
	def update(self, dst, src, dryrun=False):
		print("copy src={}, dst={}, dryrun={}".format(src,dst, dryrun))
	def disconnect(self):
		print("repl: disconnect session")
		pass

def exec_remote_list(repl, exec_list):
	repl.sendcmd(chr(5))
	for line in exec_list:
		result = repl.pastecmd(line.rstrip())
	repl.sendcmd(chr(4))
	repl.read_cmd(100)
	repl.read_cmd(100)

def exec_remote_file(repl, exec_module):
	with open(exec_module) as f:
		repl.sendcmd(chr(5))
		for line in f:
			#repl.sendcommand(repl.session.sendcmd, 'reboot()')
			result = repl.pastecmd(line.rstrip())
			# print(result)
		repl.sendcmd(chr(4))

def main():
	parsed = parser.parse_args(argv[1:])
	#print(parsed)

	nodename = parsed.nodename
	command = parsed.cmd
	args = parsed.args
	dryrun = parsed.n
	reboot = parsed.r
	xtra_breaks = parsed.b
	console = parsed.c
	verbose = parsed.v
	debug = parsed.vv
	strict = parsed.strict
	exec_module = parsed.e
	use_mpy = parsed.m
	cleanup_py = parsed.d

	# Exit with error if nothing to do
	if parsed.cmd == "" and not (console or reboot or exec_module):
		parser.error("No action specified for node")

	while command or reboot:

		# repl = FakeRepl(parsed.nodename)
		# timeout low for sending commands/reply
		repl = connect(nodename, timeout=20, debug=debug, verbose=verbose)

		if not repl:
			print("Connect failed!")
			break

		if not send_break(repl, xtra_breaks):
			print("Could not get REPL prompt ...")
			break

		print("Confirming hostname ...")
		hostname = str(repl.sendcmd('hostname'))

		if "NameError" in hostname:
			hostname = "Undefined"

		if strict:
			if nodename not in hostname:
				print('Error: hostname "{}" != nodename "{}"'.format(hostname,nodename) )
				break

		try:
			hostname = hostname.split("'")[1]
		except:
			hostname = "<Undefined>"
		
		print("Hostname:",hostname)

		# make sure we have uos for newer
		print("importing uos ...")
		result = str(repl.sendcmd('import uos'))
		if "Error" in result:
			print(result)
			print("Can't continue without uos")
			break
		
		# # only send genhash for command use
		# if command:
		# 	print("sending genhash ...")

		# 	# Define genhash function on remote
		# 	exec_remote_list(repl, genhash_func.split("\n"))
				
		# Exec module handling
		if exec_module:
			exec_remote_file(repl, exec_module)

		if command == "ls":
			if len(args) == 0:
				args = [""]
			for path in args:
				show_remote_dir(repl, path)

		if command == "sync":
			if hostname != "Undefined":
				args = ["boot.py", "main.py", "{}.py".format(hostname)]
				command = "put"
			else:
				print("sync: Error: check hostname - undefined!")

		if command == "put":
			all_files = []
			if len(args) > 0:
				for src in args:
					all_files += find_imports(src)
				for imported_file in set(all_files):
					put_file(repl, imported_file, dryrun=dryrun, use_mpy=use_mpy, cleanup=cleanup_py)
			else:
				parser.error("No files specified to put!")

		if command == "backup" and args[0]:
			backup(repl, nodename, args[0])

		break

	# Keep reboot at end of all commands
	if reboot:
		print("Sending reboot!")
		if reboot_node(repl):
			sleep(3)
			repl.disconnect()
			if console:
				print("Waiting for 15 seconds before attempting console ...")
				sleep(15)

	while console:
		# timeout higher for console output only once a minute
		repl = connect(nodename, timeout=65, debug=debug, verbose=verbose)
		
		if not repl:
			print("Connect failed!")
			break
		
		# If true, ctrl-c pressed
		if tail_console(repl):
			break
		repl.disconnect()
		print("Lost connection, reconnecting  to {} ...".format(nodename))

	print("Disconnecting ...\n")
	repl.disconnect()
	sleep(1)

if __name__ == "__main__":
    main()
