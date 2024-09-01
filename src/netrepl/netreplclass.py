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

#load other modules
from file import File
from webrepl import websocket, Webrepl

# imports related to genhash
import hashlib
import binascii

MPY_EXLCUDES = ("boot.py", 
				"natives.py",
				"main.py",
				"mysecrets.py")

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

def local_hash(filename) -> str:
	hash = genhash(filename)
	try:
		return hash.decode('UTF-8')
	except:
		return ""

def make_mpy(source):
	filename = source.split("/")[-1:][0]
	output_name = filename.split(".")[0] + ".mpy"
	rc = subprocess.run("mpy-cross {} -o {}".format(source, output_name), shell=True)
	if rc.returncode > 0:
		print("Error ({}) generating {}".format(rc.returncode, output_name))
		return ""
	return output_name

class NetRepl:
	def __init__(self, host, password=None, debug=False, verbose=False) -> None:
		self.host = host
		if password is None:
			self.password = os.environ.get("WRPWD")
			if self.password is None:
				self.password = getpass.getpass("Enter webrepl password: ")
		self.debug = debug
		self.verbose = verbose
		self.connected = False
		self.session = None

	def connect(self, timeout=70) -> bool:
		if self.connected:
			return True
		#print("after 1st Webrepl(), before session while loop")
		for attempt in range(5):
			try:
				start_time = time()
				print("Connecting to: {} (timeout={}), try={}".format(self.host, timeout, attempt))
				self.session = Webrepl(**{'host':self.host, 
						'password': self.password,
						'timeout':timeout,
						'debug': self.debug,
						'verbose': self.verbose})
				if self.session.connected:
					self.connected = True
					print("Connected!")
					return True
			except KeyboardInterrupt:
				print("in connect: Ctrl-C!")
			except Exception as e:
				print("Connect timed out, retry in 10 seconds" )
				print(e)
			while time() - start_time < 11:
				sleep(1)
		return False

	def disconnect(self) -> None:
		if self.connected:
			print("Disconnecting: {} ...".format(self.host))
			self.session.disconnect()
			self.connected = False

	def sendcmd(self, command):
		return self.session.sendcmd(command)

	def tail_console(self) -> bool:
		user_exit = False
		while not user_exit:
			# timeout higher for console output only once a minute
			if self.connect(timeout=70):
				in_error = False
				while not user_exit and not in_error:
					try:
						nextline = self.session.ws.read(100,text_ok=True, size_match=False)				
						print(nextline.decode(), end='')				
					except KeyboardInterrupt:
						user_exit = True
					except UnicodeDecodeError:
						print("\n! {}".format(nextline))	
					except Exception as error:
						print(error)
						print(nextline)
						in_error = True
						self.disconnect()

		print("\nStopping console ...".format(self.host))


	def send_break(self, xtra_breaks=False) -> bool:
		print("Sending break(s) ...")
		for i in range(3):
			self.session.sendcmd(chr(3))
			sleep(1)
		r = self.session.sendcmd('webrepl')
		#print("result: ", r)
		return b'module' in r

	def remote_stat(self, file: File) -> bool:
		result = str(self.session.sendcmd('uos.stat("{}")'.format(file.path) ))
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

	
	def remote_listdir(self, path="") -> list:
		try:
			result = str(self.session.sendcmd('uos.listdir("{}")'.format(path)))
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
		
# def show_remote_dir(session, path=""):
# 	print("Directory: {}".format(path) )
# 	for filename in remote_listdir(session, path):
# 		file = File(filename)
# 		remote_stat(session, file)
# 		print("{}  {}  {}".format(file.path, file.size, file.date_modified))

	def put_file(self, source_name, dest_name="", dryrun=True, use_mpy=False, cleanup=False, force=False) -> File:
		error_copying = File("error_copying", exists=False)
		error_hashfile = File("error_hashfile", exists=False)

		if "/" in source_name:
			only_name = source_name[-1:][0]
		else:
			only_name = source_name
		# Do not use .mpy for boot and main or if not a .py file
		if only_name in MPY_EXLCUDES or ".py" not in source_name:
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

		dest_file.hash = self.remote_hash(dest_file.path)
		source_file.hash = local_hash(source_file.path)

		#print("hashes: src=", source_file.hash, "dst=", dest_file.hash)

		# Do not overwrite existing secrets!
		#print("desthash: ", dest_file.hash)
		#print(force, use_mpy, source_name, dest_file.hash)
		if not force and ('mysecrets' in source_name and 'Error' not in dest_file.hash):
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
				self.session.put_file(source_file.path, dest_file.path )
				new_hash = self.remote_hash(dest_file.path)

				if new_hash != source_file.hash:
					# print("local: ", remote_file.path, remote_file.size)
					# Stop here if copy fails
					print("Error copying {}".format(dest_file.path))
					return error_copying
				
				# Success!
				print("copied : {} ({} bytes)".format(dest_file.path, source_file.size) )

		# Cleanup .py if .mpy was copied or exists
		if use_mpy:
			if "/" in source_name:
				py_file = File(source_name.split("/")[-1:][0] )
			else:
				py_file = File(source_name)
			if self.remote_stat(py_file):
				if py_file.exists:
					if dryrun:
						print("remove : {}".format(py_file.path))
					else:
						try:
							result = self.session.sendcmd('uos.remove("{}")'.format(py_file.path))
							if b'Error' not in result:
								print("removed: {}".format(py_file.path) )
							else:
								print("error  : {} not removed!".format(py_file.path) )
						except:
							print("Error  : {} not removed!".format(py_file.path) )

		return dest_file

		
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
		dest_file.hash = local_hash(dest_file.path)

		# print("hashes: src=", source_file.hash, "dst=", dest_file.hash)

		# If already exists and hashes match, skip
		# print(self.local_stat(local_file) )
		if source_file.hash == dest_file.hash:
			print("{} - confirmed same".format(source_file.path) )
			return source_file

		if dryrun:
			print("Get    : {}".format(source_file.path))
			return source_file
		else:
			print("Copying: {}".format(source_file.path))
		self.session.get_file(source_file.path, dest_file.path)
		local_stat(dest_file)
		# print("local: ", remote_file.path, remote_file.size)
		if dest_file.size == source_file.size:
			#print("copied {} ({} bytes)".format(remote_file.path, local_file.size) )
			return source_file
		
		print("Error copying {}".format(source_file.path))
		return error_copying

	def backup(self, nodename, path=".", dryrun=True):
		if nodename in path:
			backup_dir = path
		else:
			backup_dir = "{}/{}.{}".format(path, nodename, strftime("%Y%m%d") )
		
		if dryrun:
			print("Backup would copy files (dryrun):")
		else:
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
			if not dryrun:
				print("Failed to switch to directory {}".format(backup_dir) )
				return False

		print("Backing up node: {} to {}".format(nodename, backup_dir))		
		print("Current dir:",os.getcwd())

		total_files = 0
		total_bytes = 0

		for file in self.remote_listdir():
			result = self.get_file(file, dryrun=dryrun)
			if result.is_dir:
				print("Skipping dir {}".format(file))
				continue
			if result.size == 0:
				print("Error copying {}".format(file))
				continue
			total_files += 1
			total_bytes += result.size

		print("backed up {} files ({} bytes)".format(total_files, total_bytes))

	def reboot_node(self):
		result = self.session.sendcmd('reboot(1)')
		if b'REBOOTING' in result:
			print("Reboot confirmed!")
			return True
		else:
			print("Reboot failed!")
			return False

	# remote_hash returns string with hash or:
	# "FileNotFound" = genhash remote function returned no file found
	# "HashError" = genhash was not created or had some other error
	# If remote genhash function not there, try to upload it

	def remote_hash(self, filename) -> str:
		error_hashfile = File("error_hashfile", exists=False)
		hash = self.session.sendcmd('genhash("{}")'.format(filename) )
		
		if hash and b'NameError' in hash:
			# If NameError, hash function not loaded, load and try again
			print("genhash() not found, sending ...")
			self.exec_remote_list(genhash_func.split("\n"))

			newhash = self.session.sendcmd('genhash("{}")'.format(filename) )
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

	def exec_remote_list(self, exec_list):
		self.session.sendcmd(chr(5))
		for line in exec_list:
			result = self.session.pastecmd(line.rstrip())
		self.session.sendcmd(chr(4))
		self.session.read_cmd(100)
		self.session.read_cmd(100)

# class FakeRepl:
# 	def __init__(self, nodename) -> None:
# 		self.connected = True
# 		self.host = nodename
# 		self.result = ""

# 	def sendcommand(self, cmd, src=None, dst=None, retries=3) -> bool:
# 		print("cmd: {}, src={}. dst={}".format(cmd, src, dst))
# 		self.result = cmd + " : results!"
# 		return True
	
# 	def send_break(self):
# 		print("Break!\n\n>>>\n")
# 		return True
# 	def reboot_node(self):
# 		print("reboot()\n1\n2\n3...")
# 	def console(self):
# 		print("11:11:11 nodename console logging ...")
# 	def backup(self):
# 		print("backup node!")
# 	def update(self, dst, src, dryrun=False):
# 		print("copy src={}, dst={}, dryrun={}".format(src,dst, dryrun))
# 	def disconnect(self):
# 		print("repl: disconnect session")
# 		pass


# def exec_remote_file(repl, exec_module):
# 	with open(exec_module) as f:
# 		repl.sendcmd(chr(5))
# 		for line in f:
# 			#repl.sendcommand(repl.session.sendcmd, 'reboot()')
# 			result = repl.pastecmd(line.rstrip())
# 			# print(result)
# 		repl.sendcmd(chr(4))

