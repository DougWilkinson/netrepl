#!/usr/bin/python3
# netrepl.py

import json
import os
import socket
from time import time, sleep, strftime
import subprocess
import getpass
import logging

#load other modules
from file import File
from webrepl import Webrepl

# imports related to genhash
import hashlib
import binascii

# setup logging

log_name = 'netrepl'
logging.logfilelevel = logging.INFO
logging.consolelevel = logging.INFO
logger = logging.getLogger(log_name)
logger.setLevel(logging.DEBUG)

logfile = logging.FileHandler(log_name + ".log")
logfile.setLevel(logging.logfilelevel)
logfile.setFormatter( logging.Formatter('%(asctime)s : %(message)s', datefmt="%Y-%m-%dT%I:%M:%S%z"))

logconsole = logging.StreamHandler()
logconsole.setLevel(logging.consolelevel)
logconsole.setFormatter( logging.Formatter('%(message)s', datefmt="%Y-%m-%dT%I:%M:%S%z"))

logger.addHandler(logfile)
logger.addHandler(logconsole)

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

def local_stat(file: File) -> bool:
	try:
		stats = os.stat(file.path)
		# print("mode: ", stats.st_mode)
		if stats.st_mode == 33261 or stats.st_mode == 33188:
			file.size = int(stats.st_size)
			file.date_modified = stats.st_mtime
			file.exists = True
		if stats.st_mode == 16877:
			logger.info("{} is a directory".format(file.path) )
			file.is_dir = True
		return True
	except FileNotFoundError:
		# print("File not found local: {}".format(file.path))
		file.exists = False
	except:
		logger.info("Error parsing results from stat()")
	return False

def make_mpy(source):
	filename = source.split("/")[-1:][0]
	output_name = filename.split(".")[0] + ".mpy"
	rc = subprocess.run("mpy-cross {} -o {}".format(source, output_name), shell=True)
	if rc.returncode > 0:
		logger.info("Error ({}) generating {}".format(rc.returncode, output_name))
		return ""
	return output_name

########################
## NetRepl handles most functions related to communication with the device
## connect, disconnect, get/put files, tail console, list_dir
########################

class NetRepl:
	def __init__(self, hostname, password=None, debug=False, verbose=False) -> None:
		self.hostname = hostname
		if password is None:
			self.password = os.environ.get("WRPWD")
			if self.password is None:
				self.password = getpass.getpass("Enter webrepl password: ")
		self.debug = debug
		self.verbose = verbose
		self.connected = False
		self.session = None

	def logprint(self, message):
		logger.info("{}: {}".format(self.hostname, message))

	def connect(self, timeout=0) -> bool:
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
			except Exception as e:
				self.logprint("connect timed out, retry in 10 seconds" )
				self.logprint(e)
			
			# wait 10 seconds
			while time() - start_time < 11:
				sleep(1)
		
		self.logprint("Connect attempts failed, giving up")
		return False

	def disconnect(self) -> None:
		if self.connected:
			try:
				self.session.disconnect()
				self.logprint("disconnected")
			except:
				self.logprint("disconnect error!")

		self.connected = False

	def send_command(self, command):
		return self.session.sendcmd(command)

	def tail_console(self, timeout=0) -> bool:
		user_exit = False
		nextline = b''
		while not user_exit:
			# timeout higher for console output only once a minute
			if self.connect(timeout=timeout):
				in_error = False
				with open(self.hostname + ".console", mode="a") as console_log:
					while not user_exit and not in_error:
						try:
							nextline = self.session.ws.read(100,text_ok=True, size_match=False)				
							prefixed_line = nextline.replace(b'\n',b'\n> ').decode()
							
							print(prefixed_line, end='')
							console_log.write(nextline.decode())
						except UnicodeDecodeError:
							print("\n! {}".format(nextline))
						except socket.timeout:
							self.logprint("device timeout during console tail")
							in_error = True
							self.disconnect()							
						except Exception as error:
							self.logprint("unknown error handled during console tail")
							in_error = True
							self.disconnect()
						console_log.flush()

	def send_break(self, xtra_breaks=False) -> bool:
		self.logprint("Sending break(s) ...")
		for i in range(10):
			self.send_command(chr(3))
			sleep(.2)
		r = self.send_command('webrepl')
		#print("result: ", r)
		
		if b'module' in r:
			self.logprint("repl prompt accessed!")
			return True
		else:
			self.logprint("Could not get REPL prompt")
			return False


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

		if use_mpy:
			# generate .mpy and make this the source file
			#print("using .mpy for {}".format(source_name))
			source_file = File(make_mpy(source_name))
			dest_file = File(source_file.path)
		else:
			# Use original file name as source
			#print("using {}".format(source_name))
			source_file = File(source_name)
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

		dest_file.hash = self.remote_hash(dest_file.path)
		#print(source_name, dest_file.hash)
		source_file.hash = genhash(source_file.path)

		#print("hashes: src=", source_file.hash, "dst=", dest_file.hash)

		# Do not overwrite existing secrets!
		#print("desthash: ", dest_file.hash)
		#print(force, use_mpy, source_name, dest_file.hash)
		if not force and ('mysecrets' in source_name and 'Error' not in dest_file.hash):
			self.logprint("skip   : mysecrets already exists")
			return dest_file
		
		# Skip if hash same or copy it
		if source_file.hash == dest_file.hash:
			self.logprint("skip   : {}".format(source_file.path) )
		else:
			# Either copy it or say we will
			if dryrun:
				self.logprint("replace: {} ({})".format(source_file.path, source_file.size) )
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
		local_stat(dest_file)
		# print("local: ", remote_file.path, remote_file.size)
		if dest_file.size == source_file.size:
			#print("copied {} ({} bytes)".format(remote_file.path, local_file.size) )
			return source_file
		
		self.logprint("Error copying {}".format(source_file.path))
		return error_copying

	def reboot_node(self):
		result = self.send_command('reboot(1)')
		if b'REBOOTING' in result:
			self.logprint("{}: Reboot confirmed".format(self.hostname))
			return True
		else:
			self.logprint("{}: Reboot failed! Forcing machine reset".format(self.hostname) )
			try:
				result = self.send_command(chr(4))
			except:
				self.logprint("Disconnect error?")
			return False

	# remote_hash returns string with hash or:
	# "FileNotFound" = genhash remote function returned no file found
	# "HashError" = genhash was not created or had some other error
	# If remote genhash function not there, try to upload it

	def remote_hash(self, filename) -> str:
		error_hashfile = File("error_hashfile", exists=False)
		hash = self.send_command('genhash("{}")'.format(filename) )
		
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

		
