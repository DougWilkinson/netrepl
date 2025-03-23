#!/usr/bin/python3
# netrepl.py

from sys import argv
import os
from importlib import import_module
from time import time, sleep, strftime
import subprocess
import argparse
import getpass
from netreplclass import NetRepl, logger, genhash_func
import paho.mqtt.client as mqtt
import json
import multiprocessing

try:
	from mysecrets import mqtt_user, mqtt_pass
except:
	mqtt_user = ""
	mqtt_pass = ""

parser = argparse.ArgumentParser(prog="mpyrepl")
parser.add_argument("-b", action="store_true", help="send extra breaks")
parser.add_argument("-v", action="store_true", help="verbose")
parser.add_argument("-vv", action="store_true", help="debug")
parser.add_argument("-c", action="store_true", help="tail console")
parser.add_argument("-e", metavar="module.py", help="execute module in repl, showing ouput")
parser.add_argument("-strict", action="store_true", help="strict checking")
parser.add_argument("-m", action="store_true", help="copy .mpy version of module if possible")
parser.add_argument("-f", action="store_true", help="force copy")
parser.add_argument("-d", action="store_true", help="cleanup/delete .py versions when copying .mpy to remote")
parser.add_argument("-n", action="store_true", help="don't actually do anything, dry run")
parser.add_argument("-r", action="store_true", help="reboot node, do actions (if any) first")
parser.add_argument("-s", nargs=1, help="use mqtt server")
parser.add_argument("-mqtt", action="store_true", help="use nodelist from mqtt")
parser.add_argument("nodename")
# use for interactive
#parser.add_argument("nodename", nargs="*", default="uberdell")
parser.add_argument("cmd", nargs="?", default="", choices=["ls", "put", "remove", "sync", "backup", ""],)
parser.add_argument("args", nargs="*", default=[""], metavar="[dir | file1, file2]")

parsed = parser.parse_args(argv[1:])
#print(parsed)

nodename = parsed.nodename
command = parsed.cmd
args = parsed.args
dryrun = parsed.n
reboot = parsed.r
force = parsed.f
xtra_breaks = parsed.b
console = parsed.c
verbose = parsed.v
debug = parsed.vv
strict = parsed.strict
exec_module = parsed.e
use_mpy = parsed.m
cleanup_py = parsed.d
use_mqtt = parsed.mqtt
if parsed.s:
	mqtt_server = parsed.s[0]

if len(command) == 0 and not use_mqtt and not console and not reboot:
	parser.error("Nothing to do!")
#print(argv)

# files that should not be compiled
# include in put()
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

def find_imports(filename) -> list:
		filename = filename.lower()
		debug and print("looking for imports in: {}".format(filename))
		found = [filename]
		try:
			with open(filename) as file:
				line = True
				while line:
					line = file.readline().lower()
					#debug and print("checking: {}".format(line))
					items = line.strip().split(" ")
					if len(items) > 1 and filename.split(".")[0] == items[1]:
						debug and print("filename=import: {}".format(line))
						continue
					if  len(items) > 3 and filename.split(".")[0] == items[3]:
						debug and print("filename=import: {}".format(line))
						continue
					if "import" in line or "from " in line:
						debug and print("{}: import or from: {}".format(filename, line))
						if (items[1] not in skip and "#" not in items[0]):
							if items[0] == "from" or items[0] == "import":
								nextfile = items[1] + ".py"
								#print("looking at: ", nextfile)
								found += find_imports(nextfile)
		except FileNotFoundError:
			pass

		return found

mqtt_nodes = {}

def on_message(client, userdata, message):
	global mqtt_nodes
	mac_address = message.topic.split('/')[3]
	if mac_address not in mqtt_nodes:
		mqtt_nodes[mac_address] = {"mac": mac_address}
	if '/state' in message.topic:
		mqtt_nodes[mac_address]['state'] = message.payload.decode()
		return
	if '/attr' in message.topic:
		#print(message.topic, " = ",message.payload)
		mqtt_nodes[mac_address].update(json.loads(message.payload) )
	#print("in on_message received " ,hbvalue)
	#print("message qos=",message.qos)
	#print("message retain flag=",message.retain)
	#print("Updating heartbeat")

# function to load values from json file
def load_config(name, instance="run"):
	try:
		full = {}
		with open(name) as file:
			raw = file.readline()
			while raw:
				kv = json.loads(raw)
				if instance and instance in kv:
						return kv[instance]
				full.update(kv)
				raw = file.readline()
		return full
	except:
		print("load_file: {} failed.".format(name))
		return {}

def mqtt_sync(mqtt_query_server):
	global mqtt_nodes
	global nodename
	print("{} - querying for hosts ...".format(mqtt_query_server))

	client = mqtt.Client()
	client.username_pw_set(mqtt_user, password=mqtt_pass)
	client.connect(mqtt_query_server, 1883, 60)
	client.on_message=on_message
	client.subscribe('hass/sensor/esp/#')
	client.loop_start()
	
	sleep(5)
	client.disconnect()

	print("Found {} mqtt devices".format(len(mqtt_nodes) ) )
	
	processes = {}

	for mac, attrs in mqtt_nodes.items():
		mqtt_server = attrs.get('mysecrets', 'unknown')
		if mqtt_server != mqtt_query_server:
			continue
		if 'hostname' in attrs and 'ipv4' in attrs:
			hostname = attrs['hostname']
			state = attrs['state']
			nodename = hostname
			print("{} - {} - {} - {}".format(state, attrs['ipv4'], mac, hostname ), end="")
			
			if state == "online" or reboot:
				if mac not in processes:
					processes[mac] = multiprocessing.Process(target=main, args=(hostname,) )
					print(" - staged")
				#main(hostname)
			else:
				print(" - skipping")

	for mac, proc in processes.items():
		proc.start()

	in_process = True
	try:
		while in_process:
			# print("netrepl: Still alive ...")
			in_process = False
			for mac, proc in processes.items():
				if proc.is_alive():
					in_process = True
					break
			sleep(1)
		for mac, proc in processes.items():
			if proc.exitcode > 0:
				logger.info("{} : {}: failed".format(mac, mqtt_nodes[mac]['hostname']))
			else:
				logger.info("{} : {}: success".format(mac, mqtt_nodes[mac]['hostname']))
	except KeyboardInterrupt:
		logger.info("\nUser interrupted netrepl mqtt jobs ...")

def put_files(netrepl, files):
	#print(files)
	all_files = []
	
	if len(files) > 0:
		for src in files:
			all_files += find_imports(src)

		#print(all_files)
		for imported_file in set(all_files):

			if not force and 'mysecrets' in imported_file:
				netrepl.logprint("skip   : mysecrets already exists")
				continue
			
			mpy_ok = use_mpy and imported_file not in MPY_EXLCUDES and ".py" in imported_file

			netrepl.put_file(imported_file, dryrun=dryrun, 
				use_mpy=mpy_ok, force=force)
	else:
		parser.error("No files specified to put!")


# returns True if setup is good
# will raise error if memory issues
def setup(netrepl) -> bool:
	
	# Look for hostname on device
	netrepl.remote_name = netrepl.getvar('hostname')
	
	# look for mac address on device
	netrepl.send_command('from network import WLAN' )
	netrepl.send_command('from ubinascii import hexlify' )
	netrepl.send_command('espMAC = str(hexlify(WLAN().config("mac")).decode() )' )
	netrepl.remote_mac = netrepl.getvar('espMAC')

	# Get hostname from local macfile if we confirmed espMAC
	if netrepl.remote_mac:
		netrepl.logprint("Remote MAC address: {}".format(netrepl.remote_mac))
		netrepl.macfile_hostname = load_config(netrepl.remote_mac)
	else:
		netrepl.macfile_hostname = "unknown"
				
	netrepl.logprint('remote_hostname="{}", remote_mac="{}", macfile_hostname="{}"'.format(netrepl.remote_name, netrepl.remote_mac, netrepl.macfile_hostname) )

	# make sure we have uos
	netrepl.logprint("checking for uos ...")
	result = str(netrepl.send_command('import uos'))
	if "Error" in result:
		netrepl.logprint(result)
		netrepl.logprint("uos not imported - stopping")
		return False
	
	# If NameError, hash function not imported on device, load and try again
	netrepl.logprint("sending genhash() ...")
	netrepl.exec_remote_list(genhash_func.split("\n"))

	hash = netrepl.send_command('genhash("{}")'.format('boot.py') )

	if hash and b'NameError' in hash:
		netrepl.logprint("Unable to find/upload genhash()")
		return
		
	netrepl.logprint("setup success!")
	return True
	
def reboot_node(netrepl, reconnect=False):
	# try:
	# 	result = netrepl.send_command('reboot(0)')

	# 	if b'REBOOTING' in result:
	# 		netrepl.logprint("reboot confirmed")
	# 		return True
	# except MemoryError:
	# 	pass

	# netrepl.logprint("reboot failed - sending machine reset")

	# result = netrepl.send_command(chr(4))
	# return True

	netrepl.connected = False
	success = False
	
	try:
		result = netrepl.send_command('reboot(1)')
		if b'REBOOTING' in result:
			success = True
			netrepl.logprint("{}: Reboot confirmed".format(netrepl.hostname))
	except MemoryError:
		pass
	
	if not success:
		netrepl.logprint("{}: Reboot failed! Forcing machine reset".format(netrepl.hostname) )
		try:
			result = netrepl.send_command(chr(4))
		except:
			netrepl.logprint("Disconnect error?")

	# False = maybe reboot happened
	if not reconnect:
		return False
	
	return netrepl.connect(timeout=20)



def backup(netrepl, nodename, path=".", dryrun=True):
	if nodename in path:
		backup_dir = path
	else:
		backup_dir = "{}/{}.{}".format(path, nodename, strftime("%Y%m%d") )
	
	if dryrun:
		netrepl.logprint("Backup would copy files (dryrun):")
	else:
		try:
			os.mkdir(backup_dir)
		except FileExistsError:
			pass
		except:
			logger.error("Could not create backup dir {}".format(backup_dir))
			return False

	try:
		os.chdir(backup_dir)
	except:
		if not dryrun:
			netrepl.logprint("Failed to switch to directory {}".format(backup_dir) )
			return False

	netrepl.logprint("Backing up node: {} to {}".format(nodename, backup_dir))		
	netrepl.logprint("Current dir: {}".format(os.getcwd() ) )

	total_files = 0
	total_bytes = 0

	for file in netrepl.remote_listdir():
		result = netrepl.get_file(file, dryrun=dryrun)
		if result.is_dir:
			netrepl.logprint("Skipping dir {}".format(file))
			continue
		if result.size == 0:
			logger.error("Error copying {}".format(file))
			continue
		total_files += 1
		total_bytes += result.size

	netrepl.logprint("backed up {} files ({} bytes)".format(total_files, total_bytes))


	
def main(hostname):
	global args
	global console

	netrepl = NetRepl(hostname, debug=debug, verbose=verbose )

	while command or reboot:

		attempts = 2
		while attempts > 0:

			# timeout low for sending commands/netreply
			if not netrepl.connect(timeout=20):
				break
			
			try:
				# stop if we can't break repl
				if not netrepl.send_break(xtra_breaks):
					netrepl.logprint("send_break failed")
					break
				
				# stop if setup fails for any reason other than memory
				if not setup(netrepl):
					break
				
				attempts = 0

			except MemoryError:
				netrepl.logprint("low memory failure - attempting reboot")
				reboot_node(netrepl)
				attempts -= 1
				if attempts == 0:
					netrepl.logprint("low memory recovery failed - stopping")
		
		# change name if syncing and macfile name is valid and not same 
		if command == "sync" and netrepl.macfile_hostname != {} and netrepl.macfile_hostname != "unknown" and netrepl.macfile_hostname != hostname:
			print("Warning! Device: {} will be renamed to {}".format(hostname, netrepl.macfile_hostname))
			hostname = netrepl.macfile_hostname
			# change netrepl.host to new name in case a reboot/console is done
			netrepl.host = netrepl.macfile_hostname

		# Process commands here
		
		if command == "sync":
			if netrepl.macfile_hostname == "unknown":
				netrepl.logprint("{}: machost file not found, check before using sync".format(hostname) )
				break

			if not netrepl.remote_mac:
				netrepl.logprint("{}: remote mac address not found, check before using sync".format(hostname) )
				break
			
			args = ["boot.py", "main.py", "{}.py".format(hostname), netrepl.remote_mac]
			
			netrepl.logprint("{}: starting sync ...".format(hostname))
			put_files(netrepl, args)

		if command == "put":
			put_files(netrepl, args)

		if command == "remove":
			netrepl.remove_file(args[0])

		if command == "backup" and args[0]:
			netrepl.logprint("{}: starting backup ...".format(hostname))
			backup(netrepl, hostname, path=args[0], dryrun=dryrun)

		break

	# Keep reboot at end of all commands but before console

	if reboot:
		print("{}: sending reboot".format(hostname))
		if netrepl.connect():
			if reboot_node(netrepl): 
				# sleep(3)
				netrepl.disconnect()
			if console:
				print("{}: Waiting for console ...".format(hostname) )
				sleep(5)
		else:
			# if reboot fails, do not attempt console
			netrepl.logprint("{}: reboot failed")
			exit(1)

	if console:
		# timeout higher for console output only once a minute
		try:
			netrepl.tail_console(timeout=0)
		except KeyboardInterrupt:
			print("{}: stopping console ...".format(hostname) )

	netrepl.disconnect()
	sleep(1)
	exit(0)

if __name__ == "__main__":
	if use_mqtt:
		print("Using mqtt: {}".format(nodename) )
		mqtt_sync(nodename)
	else:
		main(nodename)
