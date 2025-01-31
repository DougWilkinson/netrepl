#!/usr/bin/python3
# mpwm.py

from sys import argv
import os
import re
import pathlib
from importlib import import_module
from time import time, sleep, strftime
import argparse
import getpass
from netreplclass import NetRepl, logger, genhash_func
import paho.mqtt.client as mqtt
import json
import multiprocessing
from microdot import Microdot
import asyncio
from mysecrets import mqtt_user, mqtt_pass, mqtt_servers, device_topic, device_config_path

mqtt_nodes = {}

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



regex = re.compile("^[0-9a-f]..........[0-9a-f]$")
config_files = [file for file in pathlib.Path(device_config_path).glob("*") if regex.match(file.name)]

mac2name = {}
name2mac = {}

for file in config_files:
	name = load_config(file)
	mac2name[file.name] = name
	name2mac[name] = file.name 

app = Microdot()

main_loop = asyncio.new_event_loop()

settings_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sensors:</title>
  <style>
    body {{
      font-family: New Courier;
      display: flex;
      flex-direction: column;
      align-items: left;
      margin-top: 20px;
    }}

	    table {{
      width: 100%;
      border-collapse: collapse;
    }}

    th, td {{
      border: 1px solid #ccc;
      padding: 1px;
      text-align: left;
    }}

    th {{
      background-color: #f4f4f4;
    }}
    .button {{
      background-color: #007bff;
      color: white;
      padding: 2px 2px;
      margin: 2px;
      border: none;
      border-radius: 5px;
      cursor: pointer;
      font-size: 11px;
    }}
    .button:hover {{
      background-color: #0056b3;
    }}
	#image-frame {{
      margin-top: 30px;
      width: 80%;
      max-width: 600px;
      height: 400px;
      border: 2px solid #ccc;
    }}
    iframe {{
      width: 100%;
      height: 100%;
      border: none;
    }}

  </style>
</head>
<body>
  <h1>Sensors Table</h1>
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>mac</th>
        <th>status</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>

  {}

    </tbody>
  </table>

  <script>
    function SelectDevice(url) {{
      window.location.href = url;
    }}
  </script>
  </body>
</html>
'''


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

class MqttQuery:
	def __init__(self, mqtt_query_server):
		global mqtt_nodes
		print("{} - query started ...".format(mqtt_query_server))

		self.server = mqtt_query_server
		self.client = mqtt.Client()
		self.client.username_pw_set(mqtt_user, password=mqtt_pass)
		self.client.connect(mqtt_query_server, 1883, 60)
		self.client.on_message=self.on_message
		self.client.subscribe('hass/sensor/esp/+/state')
		self.client.loop_start()
		self.nodes = {}

	def on_message(self, client, userdata, mqtt_message):
		global mqtt_nodes
		# device_id = "{}/{}".format(self.server, message.topic.split('/')[3] )
		device_id = "{}".format(mqtt_message.topic.split('/')[3] )
		topic = mqtt_message.topic
		message = mqtt_message.payload.decode()
		# if device_id in mqtt_nodes:
		# 	return

		if '/state' in topic:
			if device_id in self.nodes:
				mqtt_nodes[device_id] = self.nodes[device_id]
				mqtt_nodes[device_id]['status'] = "unknown"
				return
		
		if '/attr' in message.topic:

			mqtt_nodes[device_id] = message

		# 	#print(message.topic, " = ",message.payload)
		# 	mqtt_nodes[self.server][mac_address].update(json.loads(message.payload) )


for server in mqtt_servers:
	MqttQuery(server)

# def get_status(mqtt_nodes, node):
# 	for server in
# 	if node in mqtt_nodes:
# 		return mqtt_nodes[node].get('state', 'unknown')
# 	return 'unknown'

# @app.route('/')
# async def hello(request):
#     return build_menu(), 200, {'Content-Type': 'text/html'}

# build html list of nodes and buttons for sync, backup, reboot, etc
def build_menu():
	options = ""
	for node, mac in name2mac.items():
		status = mqtt_nodes.get(mac, 'unknown')
		button_def = '<tr> <td>{}</td> <td> {} </td> <td> {} </td> <td> <button class="button" onclick="SelectDevice(\'/action/{}\')">sync</button> </td> </tr>'.format(node, mac, status, node)
		#button_def = "            <p><a href='/res/{}'>{}</a>".format(res, res)
		options += button_def

	a = settings_page.format(options)
	print(a)
	return a

@app.route('/')
async def show_nodes(request):
	print("Found {} mqtt devices".format(len(mqtt_nodes) ) )
	
	# processes = {}

	# for server, nodes in mqtt_nodes.items():
	# 	for mac, attrs in nodes.items():
	# 		mqtt_server = attrs.get('mysecrets', 'unknown')
	# 		# if not match, don't use that entry?
	# 		# or only do online devices?
	# 		if mqtt_server != server:
	# 			continue
	# 		if 'hostname' in attrs and 'ipv4' in attrs:
	# 			hostname = attrs['hostname']
	# 			state = attrs['state']
	# 			nodename = hostname
	# 			print("{} - {} - {} - {}".format(state, attrs['ipv4'], mac, hostname ), end="")
				
	# 			if state == "online" or reboot:
	# 				if mac not in processes:
	# 					processes[mac] = multiprocessing.Process(target=main, args=(hostname,) )
	# 					print(" - staged")
	# 				#main(hostname)
	# 			else:
	# 				print(" - skipping")

	return build_menu(), 200, {'Content-Type': 'text/html'}



	# for mac, proc in processes.items():
	# 	proc.start()

	# in_process = True
	# try:
	# 	while in_process:
	# 		# print("netrepl: Still alive ...")
	# 		in_process = False
	# 		for mac, proc in processes.items():
	# 			if proc.is_alive():
	# 				in_process = True
	# 				break
	# 		sleep(1)
	# 	for mac, proc in processes.items():
	# 		if proc.exitcode > 0:
	# 			logger.info("{} : {}: failed".format(mac, mqtt_nodes[mac]['hostname']))
	# 		else:
	# 			logger.info("{} : {}: success".format(mac, mqtt_nodes[mac]['hostname']))
	# except KeyboardInterrupt:
	# 	logger.info("\nUser interrupted netrepl mqtt jobs ...")

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

def reboot_node(netrepl):
	# result = netrepl.send_command('reboot(1)')

	# if b'REBOOTING' in result:
	# 	logger.info("{}: Reboot confirmed".format(netrepl.hostname))
	# 	return True

	# logger.error("{}: Reboot failed! Forcing machine reset".format(netrepl.hostname) )

	# try:
	result = netrepl.send_command(chr(4))
	print(result)
	# return True
	# except:
	# logger.error("Disconnect error?")
	# return False



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

		# netrepl = FakeRepl(parsed.nodename)
		# timeout low for sending commands/netreply
		if not netrepl.connect(timeout=20):
			break

		if not netrepl.send_break(xtra_breaks):
			break

		# If we can't setup netrepl environment, exit
		if not setup(netrepl):
			break
		
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

main_loop.create_task(app.start_server(host='0.0.0.0', port=5001, debug=True))
app.run(debug=True, host='0.0.0.0', port=5001)
main_loop.run_forever()

