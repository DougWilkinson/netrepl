#!/usr/bin/python3
# netrepl.py

import json
import re
import os
import socket
from time import time, sleep, strftime
import subprocess
import getpass
import logging
import threading
import pathlib

#load other modules
from file import File
from webrepl import Webrepl

# imports related to genhash
import hashlib
import binascii

# setup logging

# log_name = 'netrepl'
# logging.logfilelevel = logging.INFO
# logging.consolelevel = logging.INFO
# logger = logging.getLogger(log_name)
# logger.setLevel(logging.DEBUG)

# logfile = logging.FileHandler(log_name + ".log")
# logfile.setLevel(logging.logfilelevel)
# logfile.setFormatter( logging.Formatter('%(asctime)s : %(message)s', datefmt="%Y-%m-%dT%I:%M:%S%z"))

# logconsole = logging.StreamHandler()
# logconsole.setLevel(logging.consolelevel)
# logconsole.setFormatter( logging.Formatter('%(message)s', datefmt="%Y-%m-%dT%I:%M:%S%z"))

# logger.addHandler(logfile)
# logger.addHandler(logconsole)

# function for comparing generting hashes to compare files
# defined using string so we can also upload to device if not defined

genhash_func = """
import binascii, hashlib
def genhash(file):
	file_hash = hashlib.sha256()
	with open(file, "rb") as handle:
		buf = handle.read(100)
		while buf:
			file_hash.update(buf)
			buf = handle.read(100)	
	return binascii.hexlify(file_hash.digest() ).decode('UTF-8')
"""

# replaced below with exec()
def genhash():
	pass

# define this for use on this end
exec (genhash_func)

MPY_EXLCUDES = ("boot.py", 
				"natives.py",
				"main.py",
				"mysecrets.py")

# Recursive function takes a .py file and looks for imported
# modules not native to micropython
# returns a full list of all imported modules as a list of .py files
# that can be used to update related files

# A short list of internal micropython modules I use
# TODO: Generate or use a complete list from ?? to check for these

skip = ("#", 
		"array",
		"asyncio", 
		"bluetooth", 
		"dht", 
		"framebuf",
		"functools",
		"gc",
		"inspect",
		"io",
		"json",
		"machine", 
		"math",
		#"microdot",
		"neopixel", 
		"network", 
		"ntptime", 
		"platform", 
		"random",
		"re",
		"struct", 
		"sys",
		"time",
		"traceback",
		"types",
		"uasyncio", 
		"ubinascii", 
		"uhashlib", 
		"umqtt.simple", 
		"uos", 
		"ustruct", 
		"webrepl")



########################
## NetRepl handles most functions related to communication with the device
## connect, disconnect, get/put files, tail console, list_dir
########################

class NetRepl:
	def __init__(self, hostname, password=None, debug=False, verbose=False) -> None:
		self.hostname = hostname

		self.ams_path = pathlib.Path(os.environ.get("AMS_PATH") )
		self.node_path = pathlib.Path(os.environ.get("HOME") + "/" + hostname)

		self.logfile_path = self.node_path / (hostname + ".log")
		self.weblog_path = self.node_path / (hostname + ".weblog")

		if not self.node_path.exists():
			os.mkdir(self.node_path)

		if password is None:
			self.password = os.environ.get("WRPWD")
			if self.password is None:
				self.password = getpass.getpass("Enter webrepl password: ")
		else:
			self.password = password
		self.debug = debug
		self.verbose = verbose
		self.connected = False
		self.session = None

		self.logger = logging.getLogger(hostname)
		if self.logger.handlers:
			self.logger.handlers.clear()
		self.logger.setLevel(logging.DEBUG)

		# appended log file for archive
		self.logfile = logging.FileHandler(self.logfile_path, mode="a")
		self.logfile.setLevel(logging.INFO)
		self.logfile.setFormatter( logging.Formatter('%(asctime)s : %(message)s', datefmt="%Y-%m-%dT%I:%M:%S%z"))

		# temp file for tailing console log
		self.weblog = logging.FileHandler(self.weblog_path, mode="w")
		self.weblog.setLevel(logging.INFO)
		#self.logfile.setFormatter( logging.Formatter('%(asctime)s : %(message)s', datefmt="%Y-%m-%dT%I:%M:%S%z"))

		self.logconsole = logging.StreamHandler()
		self.logconsole.setLevel(logging.INFO)
		self.logconsole.setFormatter( logging.Formatter('%(message)s', datefmt="%Y-%m-%dT%I:%M:%S%z"))

		self.logger.addHandler(self.logfile)
		self.logger.addHandler(self.weblog)
		self.logger.addHandler(self.logconsole)

	def make_mpy(self, source):
		source_path = self.ams_path / source

		filename = source.split("/")[-1:][0]
		output_path = self.ams_path / (filename.split(".")[0] + ".mpy")
		rc = subprocess.run("mpy-cross {} -o {}".format(source_path, output_path), shell=True)
		if rc.returncode > 0:
			self.logger.info("Error ({}) generating {}".format(rc.returncode, output_path))
			return ""
		return output_path


	def local_stat(self, file: File) -> bool:
		try:
			stats = os.stat(file.path)
			# print("mode: ", stats.st_mode)
			if stats.st_mode == 33261 or stats.st_mode == 33188:
				file.size = int(stats.st_size)
				file.date_modified = stats.st_mtime
				file.exists = True
			if stats.st_mode == 16877:
				self.logprint("{} is a directory".format(file.path) )
				file.is_dir = True
			return True
		except FileNotFoundError:
			# print("File not found local: {}".format(file.path))
			file.exists = False
		except:
			self.logprint("Error parsing results from stat()")
		return False


	def logprint(self, message):
		self.logger.info("{}: {}".format(self.hostname, message))
		self.weblog.flush()
		self.logconsole.flush()

	def connect(self, timeout=30) -> bool:
		if self.connected:
			return True
		#print("after 1st Webrepl(), before session while loop")
		for attempt in range(5):
			try:
				start_time = time()
				self.logprint("connecting (timeout={}), try={}".format(timeout, attempt))
				self.session = Webrepl(**{'host':self.hostname, 
						'password': self.password,
						'timeout':timeout,
						'debug': self.debug,
						'verbose': self.verbose})
				if self.session.connected:
					self.connected = True
					self.logprint("connected!" )
					return True
			except KeyboardInterrupt:
				self.logprint("ctrl-C during connect" )
				return False
			except socket.gaierror as e:
				if e.errno == -2:
					self.logprint("host {} not found".format(self.hostname) )
					return False
			except OSError as e:
				if e.errno == 113:
					self.logprint("No route to {} found".format(self.hostname) )
					return False
			except Exception as e:
				self.logprint("connect timed out, retry in 10 seconds" )
				self.logprint(e)

				# wait 10 seconds if not connected
				while time() - start_time < 11:
					sleep(1)
			
		
		self.logprint("Connection failed")
		return False

	def disconnect(self) -> None:
		print("disconnect() started in netreplclass - self.connected: {}".format(self.connected))
		if self.connected:
			try:
				self.session.disconnect()
				self.logprint("disconnected")
			except:
				self.logprint("disconnect error!")

		self.connected = False

	def send_command(self, command):
		result = self.session.sendcmd(command)
		if b'MemoryError' in result:
			raise MemoryError
		if b'ImportError' in result:
			raise ImportError
		return result

	def tail_console(self, timeout=5, user_exit=None, action="") -> bool:
		if user_exit is None:
			user_exit = threading.Event()

		if action == "reboot":
			self.reboot_node()
		
		if action == "update":
			if not self.update():
				return False

		nextline = b''
		while not user_exit.is_set():
			# timeout higher for console output only once a minute
			if self.connect(timeout=timeout):
				in_error = False
				# with open(self.hostname + ".console", mode="a") as console_log:
				# 	with open(self.hostname + ".weblog", mode="w") as web_log:
				while not user_exit.is_set() and not in_error:
					try:
						nextline = self.session.ws.read(300,text_ok=True, size_match=False, user_exit=user_exit)				
						prefixed_line = nextline.replace(b'\n',b'\n> ').decode()
						if len(nextline) > 2:
							print(prefixed_line, end='')
							snextline = nextline.decode()
							self.logprint(re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', snextline) )
					except UnicodeDecodeError:
						print("\n! {}".format(nextline))
					except socket.timeout:
						self.logprint("device timeout during console tail")
						in_error = True
					except Exception as e:
						self.logprint("tail_console: unknown error: {}".format(e))
						in_error = True
							# console_log.flush()
							# web_log.flush()
				print("self.disconnect() in tail_console")
				self.disconnect()
		print("tail_console exiting")

	def send_break(self, xtra_breaks=False):
		
		if not self.connect():
			return False
				
		for i in range(10):
			self.send_command(chr(3))
			sleep(.2)

		self.logprint("break sent ...")
		
		return True
	
		# retries = 5
		# while retries > 0:
		# 	self.logprint("checking for repl - retries left ({})".format(retries) )
		# 	r = self.send_command('webrepl')
		# 	if b'module' in r:
		# 		self.logprint("repl accessed!")
		# 		return True
		# 	sleep(3)
		# 	retries -= 1
		
		# self.logprint("no REPL prompt")
		# return False


	def remote_stat(self, file: File) -> bool:
		result = str(self.send_command('uos.stat("{}")'.format(file.path) ))
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
				self.logprint("{} is a directory".format(file.path) )
				file.is_dir = True
				file.exists = True
			return True
		except:
			self.logprint("Error parsing results from stat({})".format(file.path))
		return False

	
	def remote_listdir(self, path="") -> list:
		try:
			result = str(self.send_command('uos.listdir("{}")'.format(path)))
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
			self.logprint("Error getting remote filelist!")
		return []
		
	def put_file(self, source_name, dryrun=True, use_mpy=False, force=False) -> File:
		error_copying = File("error_copying", exists=False)
		error_hashfile = File("error_hashfile", exists=False)

		if "/" in source_name:
			only_name = source_name.split("/")[-1:][0]
		else:
			only_name = source_name
		
		name_no_ext = only_name.split(".")[0]

		if ".py" in source_name and use_mpy:
			# generate .mpy and make this the source file
			#print("using .mpy for {}".format(source_name))
			source_file = File(self.make_mpy(source_name))
			dest_file = File(name_no_ext + ".mpy")
		else:
			# Use original file name as source
			#print("using {}".format(source_name))
			source_file = File(self.ams_path / source_name)
			#print("source name:", source_name)
			#print("dest_name", dest_name)
			dest_file = File(only_name)
		
		missing_source = File("missing_source", exists=False)
		if not self.local_stat(source_file):
			return missing_source

		# directory is handled by calling function
		if source_file.is_dir:
			return source_file

		dest_file.hash = self.remote_hash(dest_file.path)
		#print(source_name, dest_file.hash)
		source_file.hash = genhash(source_file.path)

		#print("hashes: src=", source_file.hash, "dst=", dest_file.hash)

		# Skip if hash same or copy it
		if source_file.hash == dest_file.hash:
			self.logprint("skip   : {}".format(source_file.path) )
		else:
			# Either copy it or say we will
			if dryrun:
				self.logprint("replace: {}".format(source_file.path ) )
			else:
				self.session.put_file(source_file.path, dest_file.path )
				new_hash = self.remote_hash(dest_file.path)

				if new_hash != source_file.hash:
					# print("local: ", remote_file.path, remote_file.size)
					# Stop here if copy fails
					self.logprint("Error copying {}".format(dest_file.path))
					return error_copying
				
				# Success!
				self.logprint("copied : {} ({} bytes)".format(dest_file.path, source_file.size) )

		# Cleanup .py if .mpy was copied or exists
		if use_mpy:
			if "/" in source_name:
				py_file = File(source_name.split("/")[-1:][0] )
			else:
				py_file = File(source_name)
			if self.remote_stat(py_file):
				if py_file.exists:
					if dryrun:
						self.logprint("remove : {}".format(py_file.path))
					else:
						self.remove_file(py_file.path)

		return dest_file

	def remove_file(self, filename):
		try:
			result = self.send_command('uos.remove("{}")'.format(filename))
			if b'Error' not in result:
				self.logprint("removed: {}".format(filename) )
			else:
				self.logprint("error  : {} not removed!".format(filename) )
		except:
			self.logprint("Error  : {} not removed!".format(filename) )

		
	def get_file(self, source_name, dryrun=True) -> File:
		source_file = File(source_name)
		dest_file = File(source_name)
		missing_remote = File("missing_remote", exists=False)
		error_copying = File("error_copying", exists=False)

		if not self.remote_stat(source_file):
			return missing_remote

		if source_file.is_dir:
			return source_file

		error_hashfile = File("error_hashfile", exists=False)

		source_file.hash = self.remote_hash(source_file.path)
		dest_file.hash = genhash(dest_file.path)

		# print("hashes: src=", source_file.hash, "dst=", dest_file.hash)

		# If already exists and hashes match, skip
		# print(self.local_stat(local_file) )
		if source_file.hash == dest_file.hash:
			self.logprint("{} - confirmed same".format(source_file.path) )
			return source_file

		if dryrun:
			self.logprint("Get    : {}".format(source_file.path))
			return source_file
		else:
			self.logprint("Copying: {}".format(source_file.path))
		self.session.get_file(source_file.path, dest_file.path)
		self.local_stat(dest_file)
		# print("local: ", remote_file.path, remote_file.size)
		if dest_file.size == source_file.size:
			#print("copied {} ({} bytes)".format(remote_file.path, local_file.size) )
			return source_file
		
		self.logprint("Error copying {}".format(source_file.path))
		return error_copying

	# return True if success
	def reboot_node(self) -> bool:

		self.logprint("reboot node started")

		if not self.send_break():
			return False
		
		# try:
		# 	if not self.send_break():
		# 		return False
		
		# 	self.logprint("sending reboot" )

		# 	result = self.send_command('reboot(1)')
		# 	self.logprint(result)
		# 	if b'REBOOTING' in result:
		# 		self.logprint("Reboot confirmed")
		# 		self.connected = False
		# 		return True

		# except MemoryError:
		# 	pass
		
		try:
			result = self.send_command('reboot(1)')
			self.logprint("ctrl-D sent, wait for reboot")
			sleep(10)
			self.connected = False
			return True
		except Exception as e:
			self.logprint("Disconnect error reported: {}".format(e) )

		return False
	# remote_hash returns string with hash or:
	# "FileNotFound" = genhash remote function returned no file found
	# "HashError" = genhash was not created or had some other error
	# If remote genhash function not there, try to upload it

	def remote_hash(self, filename) -> str:
		error_hashfile = File("error_hashfile", exists=False)
		#print("remote_hash({})".format(filename) )
		hash = self.send_command('genhash("{}")'.format(filename) )
		#print("hash: ", hash)
		if hash and b'ENOENT' in hash:
			return "FileNotFoundError"
		
		try:
			return hash.decode('UTF-8').split("'")[1]
		except:
			return "HashDecodeError"

	def exec_remote_list(self, exec_list):
		self.send_command(chr(5))
		for line in exec_list:
			result = self.session.pastecmd(line.rstrip())
		self.send_command(chr(4))
		self.session.read_cmd(100)
		self.session.read_cmd(100)

	# Take raw variable result and return value as str
	# b"espMAC\r\n'ecfabc27c82e'\r\n" --> 'ecfabc27c82e'
	def getvar(self, variable_name) -> str:
		result = str(self.send_command(variable_name) )
		if "NameError" in result:
			return ""
		if "'" in result:
			return result.split("'")[1]
		else:
			return ""

	def load_config(self, instance="run"):
		file_path = pathlib.Path(self.ams_path / self.remote_mac)
		try:
			full = {}
			with open(file_path) as file:
				raw = file.readline()
				while raw:
					kv = json.loads(raw)
					if instance and instance in kv:
							return kv[instance]
					full.update(kv)
					raw = file.readline()
			return full
		except:
			print("load_file: {} failed.".format(file_path) )
			return {}

	def setup(self) -> bool:
		self.logprint("setting up REPL")

		if not self.connect():
			return False
		
		self.send_break()

		# attempts = 2
		# while attempts > 0:
		# 	if not self.connect(timeout=20):
		# 		break
			
		# 	try:
		# 		if self.send_break():
		# 			attempts = 0
		# 		else:
		# 			return False
		# 	except MemoryError:
		# 		self.logprint("low memory failure - attempting reboot")
		# 		self.reboot_node()
		# 		attempts -= 1
		# 		if attempts == 0:
		# 			self.logprint("low memory recovery failed - stopping")
		# 			return False
		
		# Look for hostname on device
		self.remote_name = self.getvar('hostname')
		
		# look for mac address on device
		self.logprint("setup: importing stuff")
		try:
			self.send_command('from network import WLAN' )
			self.send_command('from ubinascii import hexlify' )
			self.send_command('import uos')
		except ImportError:
			self.logprint("setup: FATAL - import failed - stopping")
			return False

		self.send_command('espMAC = str(hexlify(WLAN().config("mac")).decode() )' )

		self.remote_mac = self.getvar('espMAC')
		if not self.remote_mac:
			self.logprint("setup: FATAL - no espMAC - stopping")
			return False
		print(self.remote_mac)

		# Get hostname from local macfile if we confirmed espMAC
		if self.remote_mac:
			self.logprint("setup: MAC address: {}".format(self.remote_mac))
			self.macfile_hostname = self.load_config()
			self.logprint("setup: mac file found - using hostname: {}".format(self.macfile_hostname))
		else:
			self.logprint("setup: FATAL - corrupt mac file or not found - stopping")
			return False

		# make sure we have uos
		self.logprint("setup: checking for uos")
		
		# If NameError, hash function not imported on device, load and try again
		self.logprint("setup: sending genhash")
		self.exec_remote_list(genhash_func.split("\n"))

		hash = self.send_command('genhash("{}")'.format('boot.py') )

		if hash and b'NameError' in hash:
			self.logprint("setup: FATAL genhash failed - stopping")
			return False
			
		self.logprint("setup: success!")
		return True
		

	def find_imports(self, filename) -> list:
			filename = filename.lower()
			self.logger.debug("looking for imports in: {}".format(filename))
			found = [filename]
			file_path = pathlib.Path(self.ams_path / filename )
			try:
				with open(file_path) as file:
					line = True
					while line:
						line = file.readline().lower()
						#debug and print("checking: {}".format(line))
						items = line.strip().split(" ")
						if len(items) > 1 and filename.split(".")[0] == items[1]:
							self.logger.debug("filename=import: {}".format(line))
							continue
						if  len(items) > 3 and filename.split(".")[0] == items[3]:
							self.logger.debug("filename=import: {}".format(line))
							continue
						if "import" in line or "from " in line:
							self.logger.debug("{}: import or from: {}".format(filename, line))
							if (items[1] not in skip and "#" not in items[0]):
								if items[0] == "from" or items[0] == "import":
									nextfile = items[1] + ".py"
									#print("looking at: ", nextfile)
									found += self.find_imports(nextfile)
			except FileNotFoundError:
				pass

			return found

	def put_files(self, files, dryrun=False, force=False, mpy_ok=True):
		all_files = []
		
		if len(files) > 0:
			for src in files:
				all_files += self.find_imports(src)

			#print(all_files)
			all_files_success = True
			for imported_file in set(all_files):

				if 'mysecrets' in imported_file:
					self.logprint("skip   : mysecrets already exists")
					continue
				
				mpy_ok = imported_file not in MPY_EXLCUDES and ".py" in imported_file

				if not self.put_file(imported_file, dryrun=dryrun, 
					use_mpy=mpy_ok, force=force):

					all_files_success = False

			return all_files_success
				
		else:
			self.logprint("No files specified to put!")
			return False

	def update(self):
		self.logprint("starting update ...")

		#self.reboot_node()

		if not self.setup():
			return False
				
		args = ["boot.py", "main.py", "{}.py".format(self.macfile_hostname), self.remote_mac]
		
		self.logprint("starting sync ...".format(self.hostname))
		
		result = self.put_files(args)
		
		if result:
			self.reboot_node()
			return True
	
		return False
