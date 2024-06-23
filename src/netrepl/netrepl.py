#!/usr/bin/python3
# netrepl.py

from sys import argv
from time import time, sleep, strftime
import subprocess
import argparse
import getpass
from netreplclass import NetRepl
import paho.mqtt.client as mqtt
import json

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
parser.add_argument("cmd", nargs="?", default="", choices=["ls", "put", "sync", "backup", ""],)
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

skip = ("#", "umqtt.simple", "bluetooth", "ubinascii",
		"uhashlib", "random", "ustruct", "framebuf", "array",
		"struct", "dht", "uasyncio", "asyncio", "math",
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

def mqtt_sync(mqtt_server):
	global mqtt_nodes
	global nodename
	print("Querying MQTT for hosts ...")

	client = mqtt.Client()
	client.username_pw_set(mqtt_user, password=mqtt_pass)
	client.connect(mqtt_server, 1883, 60)
	client.on_message=on_message
	client.subscribe('hass/sensor/esp/#')
	client.loop_start()

	sleep(5)
	client.disconnect()

	for mac, attrs in mqtt_nodes.items():
		if 'hostname' in attrs and 'ipv4' in attrs:
			hostname = attrs['hostname']
			state = attrs['state']
			nodename = hostname
			print("{} - {} - {}".format(state, attrs['ipv4'], hostname ), end="")
			if state == "online":		
				print(" -", args)
				main(hostname)
			else:
				print(" - skipping")

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

	repl = NetRepl(hostname, debug=debug, verbose=verbose )

	while command or reboot:

		# repl = FakeRepl(parsed.nodename)
		# timeout low for sending commands/reply
		if not repl.connect(timeout=20):
			print("Connect failed!")
			break

		if not repl.send_break(xtra_breaks):
			print("Could not get REPL prompt ...")
			break

		print("Confirming remote hostname ...")
		remote_name = str(repl.sendcmd('hostname'))

		if "NameError" in remote_name:
			remote_name = "Undefined"

		if strict:
			if hostname not in remote_name:
				print('Error: hostname "{}" != remote hostname "{}"'.format(hostname,remote_name) )
				break

		try:
			remote_name = remote_name.split("'")[1]
		except:
			remote_name = "Undefined"
		
		print("remote hostname:",remote_name)

		# make sure we have uos
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
				
		# # Exec module handling
		# if exec_module:
		# 	exec_remote_file(repl, exec_module)

		# if command == "ls":
		# 	if len(args) == 0:
		# 		args = [""]
		# 	for path in args:
		# 		show_remote_dir(repl, path)

		if command == "sync":
			if remote_name != "Undefined":
				args = ["boot.py", "main.py", "{}.py".format(hostname)]
				put(repl, args)
			else:
				print("sync: Error: check hostname - undefined!")

		if command == "put":
			put(repl, args)

		if command == "backup" and args[0]:
			repl.backup(hostname, path=args[0], dryrun=dryrun)

		break

	# Keep reboot at end of all commands
	if reboot:
		print("Sending reboot!")
		if repl.reboot_node():
			sleep(3)
			repl.disconnect()
			if console:
				print("Waiting for console ...")
				sleep(15)

	if console:
		# timeout higher for console output only once a minute
		if repl.connect(timeout=70):
			repl.tail_console()
		else:
			print("Connect failed!")

	repl.disconnect()
	sleep(1)

if __name__ == "__main__":
	if use_mqtt:
		print(nodename)
		mqtt_sync(nodename)
	else:
		main(nodename)
