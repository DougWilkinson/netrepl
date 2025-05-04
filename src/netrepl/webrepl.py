import struct
import os
import sys
import socket
from time import time
import threading

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

	def recvexactly(self, sz, user_exit=None):
		res = b""
		while sz:
			#print("recvexactly: in while loop: user_exit:", user_exit)
			try:
				data = self.s.recv(sz)
			except socket.timeout:
				#print("device timeout during websocket read: user_exit:", user_exit)
				if user_exit is not None:
					#print("user_exit: ", user_exit)
					if user_exit.is_set():
						return res
				continue
			
			if not data:
				break
			res += data
			sz -= len(data)
		#print("rcvexactly", res)
		return res

	def debugmsg(self, msg):
		if self.debug:
			print(msg)

	def read(self, size, text_ok=False, size_match=True, user_exit=None):
		if not self.buf:
			while True:
				#print("in read loop")
				hdr = self.recvexactly(2, user_exit)
				assert len(hdr) == 2
				fl, sz = struct.unpack(">BB", hdr)
				if sz == 126:
					hdr = self.recvexactly(2, user_exit)
					assert len(hdr) == 2
					(sz,) = struct.unpack(">H", hdr)
				if fl == 0x82:
					break
				if text_ok and fl == 0x81:
					break
				self.debugmsg("[i] Got unexpected websocket record of type %x, skipping it" % fl)
				while sz:
					#print("in skip loop")
					skip = self.s.recv(sz)
					self.debugmsg("[i] Skip data: %s" % skip)
					sz -= len(skip)
			data = self.recvexactly(sz, user_exit)
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
		if self.timeout is not None and self.timeout > 0:
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
