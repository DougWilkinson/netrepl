#!/usr/bin/python3
# netrepl.py

from sys import argv
from importlib import import_module
from time import time, sleep, strftime
import subprocess
import argparse
import getpass
from netreplclass import NetRepl, logger
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
		"gc", 
		"json",
		"machine", 
		"math",
		"neopixel", 
		"network", 
		"ntptime", 
		"platform", 
		"random", 
		"struct", 
		"sys",
		"time", 
		"uasyncio", 
		"ubinascii", 
		"uhashlib", 
		"umqtt.simple", 
		"uos", 
		"ustruct", 
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

def put(repl, files):
	all_files = []
	if len(files) > 0:
		for src in files:
			all_files += find_imports(src)
		for imported_file in set(all_files):
			repl.put_file(imported_file, dryrun=dryrun, use_mpy=use_mpy, cleanup=cleanup_py, force=force)
	else:
		parser.error("No files specified to put!")

	
def main(hostname):
	global args
	global console

	repl = NetRepl(hostname, debug=debug, verbose=verbose )

	while command or reboot:

		# repl = FakeRepl(parsed.nodename)
		# timeout low for sending commands/reply
		if not repl.connect(timeout=20):
			break

		if not repl.send_break(xtra_breaks):
			break

		# If we can't setup repl environment, exit
		if not repl.setup():
			break
		
		# change name if syncing and macfile name is valid and not same 
		if command == "sync" and repl.macfile_hostname != {} and repl.macfile_hostname != "unknown" and repl.macfile_hostname != hostname:
			print("Warning! Device: {} will be renamed to {}".format(hostname, repl.macfile_hostname))
			hostname = repl.macfile_hostname
			# change repl.host to new name in case a reboot/console is done
			repl.host = repl.macfile_hostname

		# Process commands here
		
		if command == "sync":
			if repl.macfile_hostname == "unknown":
				logger.info("{}: machost file not found, check before using sync".format(hostname) )
				break

			if not repl.remote_mac:
				logger.info("{}: remote mac address not found, check before using sync".format(hostname) )
				break
			
			args = ["boot.py", "main.py", "{}.py".format(hostname), repl.remote_mac]
			
			logger.info("{}: starting sync ...".format(hostname))
			put(repl, args)

		if command == "put":
			put(repl, args)

		if command == "remove":
			repl.remove_file(args[0])

		if command == "backup" and args[0]:
			logger.info("{}: starting backup ...".format(hostname))
			repl.backup(hostname, path=args[0], dryrun=dryrun)

		break

	# Keep reboot at end of all commands but before console

	if reboot:
		print("{}: sending reboot".format(hostname))
		if repl.reboot_node():
			# sleep(3)
			repl.disconnect()
			if console:
				print("{}: Waiting for console ...".format(hostname) )
				sleep(5)
		else:
			# if reboot fails, do not attempt console
			logger.info("{}: reboot failed")
			exit(1)

	if console:
		# timeout higher for console output only once a minute
		try:
			if repl.connect(timeout=70):
				repl.tail_console()
			else:
				print("{}: connect failed!".format(hostname) )
				exit(2)
		except KeyboardInterrupt:
			print("{}: stopping console ...".format(hostname) )

	repl.disconnect()
	sleep(1)
	exit(0)

if __name__ == "__main__":
	if use_mqtt:
		print("Using mqtt: {}".format(nodename) )
		mqtt_sync(nodename)
	else:
		main(nodename)
