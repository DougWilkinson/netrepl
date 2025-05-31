# aconsole.py

from nicegui import ui, app, Client
from mysecrets import mqtt_servers, ams_path
import json
import multiprocessing
from microdot import Microdot
import asyncio
from netreplclass import NetRepl, genhash_func
import threading
import subprocess
import re
import time
import pathlib
from datetime import datetime
from ngmqttserver import NGMQTTServer, mqtt_nodes
import os

waitfor_continue = threading.Event()


attributes = {"freq": 80.0, 
			  "rgblight": 3, 
			  "mac": "ecfabc281b13", 
			  "flag": 3, 
			  "ledclock": 3, 
			  "device": 3, 
			  "core": 3, 
			  "hostname": "toyclock", 
			  "ipv4": "192.168.1.165", 
			  "toyclock": 3, 
			  "hass": 3, 
			  "main": 3, 
			  "mysecrets": ""}

esptool_modes = { 
	"esp32-s3mini": "esptool.py --port /dev/{} --chip esp32s3 --baud 460800 write_flash 0 {}",
	"esp32-s2fnr2mini": "esptool.py --port /dev/{} --chip esp32s2 --baud 460800 write_flash 0x1000 {}",
	"esp32-d0wd-v3": "esptool.py --port /dev/{} --chip esp32 --baud 460800 write_flash 0x1000 {}",
	"esp32-d0wdq6": "esptool.py --port /dev/{} --chip esp32 --baud 460800 write_flash 0x1000 {}",
	"erase_flash": "esptool.py --after no_reset --port /dev/{} erase_flash",
	"chip_id": "esptool.py --after no_reset --port /dev/{} chip_id",
	"chip_id_reset": "esptool.py --port /dev/{} chip_id",
	"esp32-s3dev": "esptool.py --port /dev/{} --chip esp32s3 --baud 460800 write_flash 0 {}" 
	}


style_sheet = '''
	<style>
	.ag-theme-balham {
		--ag-foreground-color: rgb(126, 46, 132);
		--ag-background-color: rgb(249, 245, 227);
		--ag-header-foreground-color: rgb(204, 245, 172);
		--ag-header-background-color: rgb(209, 64, 129);
		--ag-odd-row-background-color: rgb(0, 0, 0, 0.03);
		--ag-header-column-resize-handle-color: rgb(126, 46, 132);

		--ag-font-size: 26px;
		--ag-font-family: monospace;
	}
	</style>
	'''

rshell_commands = """cd {}
cp {} /pyboard
cp boot.py /pyboard
cp blinkled.py /pyboard
cp main.py /pyboard
cp hass.py /pyboard
cp msgqueue.py /pyboard
cp device.py /pyboard
cp webrepl_cfg.py /pyboard
cp core.py /pyboard
cp flag.py /pyboard
cp newsensor.py /pyboard
cp versions.py /pyboard
cp hassdocker/mysecrets.py /pyboard
repl ~ import machine ~ machine.reset() ~
"""

# Initialize MQTT servers based on mysecrets
servers = {}
for server in mqtt_servers:
	servers[server] = NGMQTTServer(server)

row_data = ["loading...","",""]

output = []

def call_check_output(command, thread_done):
	global output

	output.insert(0, (subprocess.check_output(command) ) )
	thread_done.set()

async def outsource_function(command):
	global output
	thread_done = asyncio.Event()

	process = threading.Thread(target=call_check_output, args=(command, thread_done))
	process.start()

	await thread_done.wait()

# function to call esptool with hard reset (default)
async def esptool_functions(port, action, log):
	global output

	if action == "reset":

		print("{}: starting esptool (reset_port)".format(port))

		log.push("resetting port on {}\n".format(port) )

		reset_args = esptool_modes["chip_id_reset"].format(port).split()

		print("before await outsource_function")
		await outsource_function(reset_args)

		print("after await outsource_function")
		result = output[0].decode()

		for line in result.split("\n"):
			log.push(line)

		# try:
		# 	subprocess.check_output(reset_args) 
		# 	log.push(" ")
		# 	log.push("port reset\n")

		# except subprocess.CalledProcessError as e:
		# 	print("Error: {}".format(e.output.decode()))
		# 	log.push("Error: {}".format(e.output.decode()))


# async def chip_id(port, log):

	if action in "install_chipid_flash_bootstrap":
		print("{}: starting (chip_id)".format(port))

		log.push("reading chip_id on {}\n".format(port) )

		if action == "bootstrap":
			log.push("reading chip_id {} (RESET)\n".format(port) )
			chip_id_args = esptool_modes["chip_id_reset"].format(port).split()
		else:
			log.push("reading chip_id on {}\n".format(port) )
			chip_id_args = esptool_modes["chip_id"].format(port).split()
		
		print("before await outsource_function")
		await outsource_function(chip_id_args)

		print("after await outsource_function")
		chip_id_output = output[0].decode()

	# try:
	# 	chip_id_output = subprocess.check_output(chip_id_args) 
	# 	for line in chip_id_output.decode().split("\n"):
	# 		log.push(line)
	# 	log.push(" ")
	
	# except subprocess.CalledProcessError as e:
	# 	print("Error: {}".format(e.output.decode()))
	# 	log.push("Error: {}".format(e.output.decode()))
	# 	return ("", "")
		
		mac_address = ""
		chip_type = ""

		for line in chip_id_output.split("\n"):
			if "MAC" in line:
				mac_colon=line.split(' ')[1]
				mac_address = re.sub(r':', '', mac_colon)
			if "Chip is" in line:
				chip_type = line.split(' ')[2].lower()
			if "Embedded PSRAM 2MB" in line:
				chip_type += "mini"
			if "Embedded PSRAM 8MB" in line:
				chip_type += "dev"
		
		if not chip_type or not mac_address:
			print("Error: could not determine chip_type or mac_address")
			log.push(" ")
			log.push("Error: could not determine chip_type or mac_address - stopping")
			log.push("----------------------------")
			return
		
		# chip_type: esp32s3mini, esp32s3dev, esp32, esps2mini
		#log.style("font-weight: bold;")

		log.push(" ")
		log.push("chip_type: {}".format(chip_type) )
		log.push("mac_address: {}".format(mac_address))
		log.push("----------------------------")

		print("chip_id: chip_type: {}, mac_address: {}".format(chip_type, mac_address))
		
		# wait for device
		time.sleep(1)

		#ls_output = subprocess.check_output("ls -al /dev/ttyACM1".split())
		#print("devices: {}".format(ls_output.decode() ) )

	# return (chip_type, mac_address)

# def erase_flash(port, log):

	if action in "install_erase":
		print("{}: starting (erase_flash)".format(port))

		log.push("erasing flash on {}\n".format(port) )
		log.push(" ")

		erase_args = esptool_modes["erase_flash"].format(port).split()

		await outsource_function(erase_args)
		
		erase_flash_output = output[0].decode()

		found_success = False
		for line in erase_flash_output.split("\n"):
			log.push(line)
			if "success" in line:
				log.push(" ")
				log.push("ERASE: Success!")
				log.push("----------------------------")
				found_success = True

		if not found_success:
			log.push(" ")
			log.push("Error: could not erase flash - stopping")
			log.push("----------------------------")
			return
		
		# try:
		# 	log.push(erase_args)
		# 	#erase_flash_output = b'simulate erase_flash Success'
		# 	erase_flash_output = subprocess.check_output(erase_args )
		# 	for line in erase_flash_output.decode().split("\n"):
		# 		if "Success" in line:
		# 			log.push(line)
		
		# except subprocess.CalledProcessError as e:
		# 	log.push("Error: {}".format(e.output.decode()))
		# 	return

	# esptool.py --port /dev/ttyACM2 --chip esp32s3 --baud 460800 write_flash 0 esp32s3/ESP32_GENERIC_S3-FLASH_4M-20250415-v1.25.0.bin

# def write_flash(port, chip_type, log):

	if action in "install_flash":		
		print("{}: starting (write_flash)".format(port))

		log.push("writing flash on {}\n".format(port))
		
		flash_file = "/home/doug/ha/flash/{}/latest.bin".format(chip_type)
		
		flash_args = esptool_modes[chip_type].format(port, flash_file).split()

		await outsource_function(flash_args)

		flash_output = output[0].decode()

		found_success = False

		for line in flash_output.split("\n"):
			log.push(line)
			if "Wrote" in line:
				log.push(" ")
				log.push(line)
				log.push("----------------------------")
				found_success = True

		if not found_success:
			log.push("Error: could not write flash")
			return

		# esp_error = True

		# while esp_error:
			
		# 	try:
		# 		write_flash_output = b'simulate write_flash - Wrote'
		# 		write_flash_output = subprocess.check_output(flash_args )
				
		# 		#log.push(flash_args )
		# 		for line in write_flash_output.decode().split("\n"):
		# 			if "Wrote" in line:
		# 				log.push(line)
		# 		#log.push(write_flash_output.decode())
		# 		esp_error = False
		# 	except subprocess.CalledProcessError as e:
		# 		log.push("Error: {}".format(e.output.decode()))
		# 		time.sleep(2)
		# 		log.push("\nretrying")
				
		# log.push("flash complete\n".format(port))

# def copy_bootstrap_files(port, mac_address, log):
	print("installing bootstrap files")

	if action in "install_bootstrap":

		print("{}: starting rshell (copy_bootstrap_files)".format(port))

		log.push(" ")
		log.push("RSHELL: creating/copying files to {}\n".format(port) )
		log.push(" ")

		# create new config file for port
		# or if it exists, use it (upgrading firmware, same hardware)

		node_config_file = "{}{}".format(ams_path, mac_address)

		if not os.path.exists(node_config_file):
			with open(node_config_file, mode="w") as f:
				f.write('{{ "run": "{}" }}\n'.format(mac_address) )

		# create file_copy_list with mac_address config file
		
		with open("file_copy_list", mode="w") as f:
			f.write('{}\n'.format(rshell_commands.format(ams_path, mac_address) ) )

		rshell_args = "rshell -p /dev/{} -f file_copy_list".format(port).split()
		#log.push(rshell_args)

		await outsource_function(rshell_args)

		rshell_output = output[0].decode()

		for line in rshell_output.split("\n"):
			log.push(line)


		# try:
		# 	#rshell_output = 'simulate rshell'
		# 	rshell_output = subprocess.check_output(rshell_args.split())
		# 	log.push("rshell commands completed\n")
		# 	log.push(rshell_output)

		# except subprocess.CalledProcessError as e:
		# 	log.push("Error: {}".format(e.output.decode()))
		# 	return

		log.push(" ")
		log.push("\n\ninit complete! \n")
		log.push("----------------------------")
		print('{}: init completed'.format(port))


###########################################
## ESPTOOL TABLE
###########################################

@ui.page('/esptool')
def esptool_table():
	print('esptool_table')

	row_data = ["Loading ...","",""]

	ui.add_body_html(style_sheet)

	# Called every 3 seconds to check for changes to the table data
	@ui.refreshable
	def update_rows():

		last_table = row_data.copy()
		#print(last_table)

		row_data.clear()

		for port in pathlib.Path('/dev').glob('tty[UA][SC][BM]*'):
			timestamp = datetime.fromtimestamp(port.stat()[7])
			row_data.append( {"port": "/dev/" + port.name , "connect_time": timestamp.strftime("%m/%d %H:%M:%S"), "name": "waiting ..." } )

		if last_table != row_data:
			grid.update()

	async def button_handler(button: ui.button):
		action = button.text

		rows = await grid.get_selected_rows()

		if not rows:
			return

		for row in rows:

			port = row['port'].split("/")[-1]

			print("/esptool/{}?action={}".format(port, action))
			
			ui.navigate.to("/esptool/{}?action={}".format(port, action), new_tab=True)


	with ui.button_group():
		install_button = ui.button("install", on_click=lambda e: button_handler(e.sender) )
		chipid_button = ui.button("chipid", on_click=lambda e: button_handler(e.sender) )
		erase_button = ui.button("erase", on_click=lambda e: button_handler(e.sender) ) 	
		flash_button = ui.button("flash", on_click=lambda e: button_handler(e.sender) ) 
		bootstrap_button = ui.button("bootstrap", on_click=lambda e: button_handler(e.sender) )
		reset_button = ui.button("reset", on_click=lambda e: button_handler(e.sender) )

	ui.timer(3, update_rows)

	column_data = [
			{'headerName': 'Port', 'field': 'port', 'width': 50, 'checkboxSelection': True},
			{'headerName': 'Connect time', 'field': 'connect_time', 'width': 50},
			{'headerName': 'Name', 'field': 'name', 'width': 50}
			]
	
			# {'headerName': 'Status', 'field': 'status', 'width': 80,
			# 			'cellClassRules': {
            # 			'bg-red-300': 'x == "offline"',
            # 			'bg-blue-300': 'x == "shutdown"',
			#             'bg-green-300': 'x == "online"'} },
	
	grid = ui.aggrid( {'columnDefs': column_data,
		'auto_size_columns': False,
		'rowData': row_data,
		'rowSelection': 'multiple',
   		} ).classes('h-[1500px]' )





###########################################
## ESPTOOL
###########################################

@ui.page('/esptool/{device}')
async def esptool(device, client: Client, action: str="", chip_type: str="", mac_address: str=""):
	print("{}: loading esptool page ({})".format(device, action))

	ui.page_title(device)

	with ui.button_group():
		install_button = ui.button("install", on_click=lambda: ui.navigate.to("/esptool/{}?action=install".format(device) ) )
		chipid_button = ui.button("chipid", on_click=lambda: ui.navigate.to("/esptool/{}?action=chipid".format(device) ) )
		erase_button = ui.button("erase", on_click=lambda: ui.navigate.to("/esptool/{}?action=erase".format(device) ) )	
		flash_button = ui.button("flash", on_click=lambda: ui.navigate.to("/esptool/{}?action=flash".format(device) ) )
		bootstrap_button = ui.button("bootstrap", on_click=lambda: ui.navigate.to("/esptool/{}?action=bootstrap".format(device) ) )
		reset_button = ui.button("reset", on_click=lambda: ui.navigate.to("/esptool/{}?action=reset".format(device) ) )

	log = ui.log(max_lines=50).classes('h-screen').style('white-space: pre-wrap')

	if action:
		await esptool_functions(device, action, log)

	# reset

	# if action in "reset":
	# 	print("esptool: resetting")
	# 	reset_result = reset_port(device, log)

	# # chip_id

	# if action in "install_chipid_flash_bootstrap":
	# 	chip_type, mac_address = chip_id(device, log)
	
	# # erase
		
	# if action in "install_erase":

	# 	with ui.dialog() as dialog, ui.card():
	# 		ui.label('Erase flash?')
	# 		with ui.row():
	# 			ui.button('Yes', on_click=lambda: dialog.submit('Yes'))
	# 			ui.button('No', on_click=lambda: dialog.submit('No'))

	# 	result = await dialog

	# 	if result == "Yes":
	# 		print("esptool: erasing flash")
	# 		erase_result = erase_flash(device, log)

	# # flash
			
	# if action in "install_flash":

	# 	with ui.dialog() as dialog, ui.card():
	# 		ui.label('Write flash?')
	# 		with ui.row():
	# 			ui.button('Yes', on_click=lambda: dialog.submit('Yes'))
	# 			ui.button('No', on_click=lambda: dialog.submit('No'))

	# 	result = await dialog

	# 	if result == "Yes":
	# 		print("esptool: writing flash")
	# 		write_flash_result = write_flash(device, chip_type, log)

	# # bootstrap
			
	# if action in "install_bootstrap":

	# 	# wait for user to confirm
	# 	# for s2 chips, need to reset manually before this step

	# 	with ui.dialog() as dialog, ui.card():
	# 		ui.label('Copy bootstrapfiles? (Reboot S2 devices now!)')
	# 		with ui.row():
	# 			ui.button('Yes', on_click=lambda: dialog.submit('Yes'))
	# 			ui.button('No', on_click=lambda: dialog.submit('No'))

	# 	result = await dialog

	# 	if result == "Yes":
	# 		print("esptool: copying bootstrap files")
	# 		bootstrap_result = copy_bootstrap_files(device, mac_address, log)


	await client.disconnected()
	print('{}: esptool page closed'.format(device))


###########################################
## CONSOLE
###########################################

@ui.page('/console/{action}')
async def console_page(action, client: Client):
	print("loading console page for {}".format(action))

	await ui.context.client.connected()

	print(app.storage.tab)

	rows = app.storage.tab['selected_nodes']

	#ui.page_title(hostname)

	# setup event to signal to netrepl that user closed window

	user_exit = threading.Event()
	
	#ui.button("Close", on_click=lambda: user_exit.set() )

	for row in rows:

		print(row)
		hostname = row['node']
		mac_address = row['mac']

		ui.label(hostname).classes('text-4xl').classes('font-bold')
		log = ui.log(max_lines=50).classes('h-auto').classes('text-2xl').classes('monospace')
		#log = ui.log(max_lines=20)

		# instantiate netrepl
		netrepl = NetRepl(hostname, nicegui_log=log, user_exit=user_exit, debug=False, verbose=False)

		# start console thread

		console_thread = threading.Thread(
			target=netrepl.tail_console, 
			kwargs={'action': action, 'mac_address': mac_address} )
		
		console_thread.start()
	
	await client.disconnected()

	# signal to netrepl that user closed window
	user_exit.set()

	print('{}: console page closed'.format(hostname))


###########################################
## MAIN TABLE
###########################################

@ui.page('/')
def mqtt_nodelist():
	print('home page opened - mqtt_nodelist')

	ui.add_body_html(style_sheet)
	# dark = ui.dark_mode()
	# dark.enable()

	# Called every 3 seconds to check for changes to the table data
	@ui.refreshable
	def update_rows():

		last_table = row_data.copy()
		#print(last_table)

		row_data.clear()

		for node in mqtt_nodes:
			#print("node: {}".format(node))
			hostname = mqtt_nodes[node].get('hostname', node)
			build = mqtt_nodes[node].get('platform', "")
			chip = "unknown"
			platform = ""

			if build:
				if "ESP32S3" in build:
					if "SPIRAM" in build:
						platform = "3d"
					else:
						platform = "3m"
				elif "ESP32S2" in build:
					platform = "2m"
				elif "ESP32" in build:
					platform = "32"

			# total_mem = mqtt_nodes[node].get('memory', 0)
			#print(f"{hostname}: {node} {total_mem} {chip} {build} {platform}")
			# if total_mem:

			# 	if total_mem > 1000000:
			# 		platform = "{}({:.0f}M) {}".format(chip, total_mem / 1000000, build)
			# 	else:
			# 		platform = "{}({:.0f}K) {}".format(chip, total_mem / 1000, build)

			last_restart = mqtt_nodes[node].get('last_restart', "")

			if last_restart:

				input_format = "%Y/%m/%d-T%H:%M:%S"
				target_datetime = datetime.strptime(last_restart, input_format)

				now = datetime.now()
				delta = now - target_datetime
				days_passed = delta.days
				hours_passed = delta.seconds // 3600

				time_str = target_datetime.strftime("%H:%M")

				uptime = "{}d".format(days_passed)

			mpy = mqtt_nodes[node].get('mpy', "?.??.0")[0:4]

			signal = mqtt_nodes[node].get('signal', 0)
			reboots = mqtt_nodes[node].get('reboots', 0)

			try:
				row_data.append( {"node": mqtt_nodes[node]['hostname'], 
						"mac": mqtt_nodes[node]['mac'], 
						"status": mqtt_nodes[node]['status'],
						"server": mqtt_nodes[node]['mysecrets'],
						"mpy": mpy,
						"signal": signal,
						"reboots": reboots,
						"uptime": uptime,
						"platform": platform
						} )
			except KeyError:
				pass
		#print(row_data)
		
		# for device in pathlib.Path('/dev').glob('tty[UA][SC][BM]*'):
		# 	timestamp = datetime.datetime.fromtimestamp(device.stat()[7])
		# 	row_data.append( {"node": "/dev/" + device.name , "mac": timestamp.strftime("%m/%d %H:%M:%S"), "status": "", "server": "" } )

		if last_table != row_data:
			grid.update()
			grid.run_grid_method('autoSizeAllColumns')

	async def esptool_handler(button: ui.button):
		print("esptool_handler")

		ui.navigate.to("/esptool", new_tab=True)

	# Called when a console related action button is clicked
	# reboot, update, console, mqttserver
	async def console(button: ui.button):
		action = button.text
		
		await ui.context.client.connected()

		rows = await grid.get_selected_rows()

		if not rows:
			return
		
		print(rows)
		
		app.storage.tab['selected_nodes'] = rows
		print(app.storage.tab)

		if action in "backup|update|reboot|console":
			ui.navigate.to("/console/{}".format(action), new_tab=True)
			return
		


		for row in rows:

			# if action in "update|reboot|console":
			# 	hostname = row['node']
			# 	# if "/dev" in hostname:
			# 	# 	ui.notify("Invalid option for /dev devices")
			# 	# 	return

			# 	print("/console/{}".format(action))
				
			# 	ui.navigate.to("/console/{}".format(action), new_tab=True)
			# 	#ui.navigate.to("/console/{}?action={}".format(hostname, action), new_tab=True)


			# if action == "install" or action == "esptool":
			# 	if "/dev" not in row['node']:
			# 		ui.notify("Invalid option: /dev devices only")
			# 		return
				
			# 	hostname = row['node'].split("/")[-1]

			# 	print("/esptool/{}?action={}".format(hostname, action) )

			# 	ui.navigate.to("/esptool/{}?action={}".format(hostname, action), new_tab=True)

			if action == "shutdown" and row['status'] == "offline":
				hostname = row['node']
				mac_address = row['mac']
				mqtt_client = servers[row['server']].client
				mqtt_client.publish("hass/sensor/esp/{}/state".format(mac_address), "shutdown")
				ui.notify("shutdown: {} ({})".format(hostname, mac_address))

			# remove mqtt config and sensor
			# homeassistant/sensor/esp/ecfabc281b13/config
				
			if action == "remove" and row['status'] != "online":
				hostname = row['node']
				mac_address = row['mac']
				mqtt_client = servers[row['server']].client
				mqtt_nodes.pop(mac_address)
				mqtt_client.publish("homeassistant/sensor/esp/{}/config".format(mac_address), "", retain=True)
				mqtt_client.publish("hass/sensor/esp/{}/state".format(mac_address), "", retain=True)
				mqtt_client.publish("hass/sensor/esp/{}/attrs".format(mac_address), "", retain=True)
				
				ui.notify("removed: {} ({})".format(hostname, mac_address))

	async def shutdown():
		rows = await grid.get_selected_rows()
		if rows:
			for row in rows:
				mqtt_client = servers[row['server']].client
				mqtt_client.publish(row['node'] + "/shutdown", "shutdown")

		else:
			ui.notify('No rows selected.')

	async def output_selected_rows():
		rows = await grid.get_selected_rows()
		if rows:
			for row in rows:
				ui.notify(row)
		else:
			ui.notify('No rows selected.')

	async def output_selected_row():
		row = await grid.get_selected_row()
		if row:
			ui.notify(row)
		else:
			ui.notify('No row selected!')

	with ui.button_group():
		#ui.link('console', "/console", new_tab=True)
		ui.button('console', on_click=lambda e: console(e.sender))
		ui.button('update', on_click=lambda e: console(e.sender))
		ui.button('reboot', on_click=lambda e: console(e.sender))
		ui.button('backup', on_click=lambda e: console(e.sender))
		ui.button('shutdown', on_click=lambda e: console(e.sender))
		ui.button('remove', on_click=lambda e: console(e.sender))
		ui.button('esptool', on_click=lambda e: esptool_handler(e.sender) )
		ui.button('resize', on_click=lambda e: grid.run_grid_method('autoSizeAllColumns') ) 

	ui.timer(3, update_rows)

	column_data = [
			{'headerName': 'Node', 'field': 'node', 'width': 15, 'checkboxSelection': True},
			{'headerName': 'Status', 'field': 'status', 'width': 10,
				# 'cellClassRules': {
				# 'bg-red-300': 'x == "offline"',
				# 'bg-blue-300': 'x == "shutdown"',
				# 'bg-green-300': 'x == "online"'} 
				},
			{'headerName': 'uptime', 'field': 'uptime', 'width': 4},
			{'headerName': 'db', 'field': 'signal', 'width': 4},
			{'headerName': 'RBs', 'field': 'reboots', 'width': 3},
			{'headerName': 'platform', 'field': 'platform', 'width': 15},
			{'headerName': 'Mac', 'field': 'mac', 'width': 15},
			{'headerName': 'Server', 'field': 'server', 'width': 6},
			{'headerName': 'mpy', 'field': 'mpy', 'width': 8},
		]
	
	grid = ui.aggrid( {'columnDefs': column_data,
		'autoSizeStrategy': 'fitCellContents',
		'rowData': row_data,
		'rowSelection': 'multiple',
	} ).classes('h-[1500px]' )

	#print(grid.options)


	ui.button('refresh', on_click=output_selected_row)

	def handle_cell_click(event):
		# Access event details like column and row data
		col = event.args['colId']
		row_index = event.args['rowIndex']
		row_data = grid.options['rowData'][row_index]
		
		ui.notify(f'Clicked column "{col}" in row {row_index} with data: {row_data}')

	grid.on('cellClicked', handle_cell_click)


@ui.page('/test')
async def test(client: Client):
	print('preparing')
	await client.connected()
	print('connected')

	log = ui.log(max_lines=5).classes('text-lg').classes('monospace')
	log.push("xl monospace")
	log = ui.log(max_lines=5).classes('text-1xl').classes('monospace')
	log.push("1xl monospace")
	log = ui.log(max_lines=5).classes('text-2xl').classes('monospace')
	log.push("2xl monospace")
	log = ui.log(max_lines=5).classes('text-3xl').classes('monospace')
	log.push("3xl monospace")

	# with ui.dialog() as dialog, ui.card():
	# 	ui.label('Are you sure?')
	# 	with ui.row():
	# 		ui.button('Yes', on_click=lambda: dialog.submit('Yes'))
	# 		ui.button('No', on_click=lambda: dialog.submit('No'))

	# result = await dialog
	# log.push(f'You chose {result}')

	#print("tabs: {}\n".format(app.storage.tab))
	#print("client: {}\n".format(app.storage.client))
	#print("user: {}\n".format(app.storage.user))
	#print("general: {}\n".format(app.storage.general))
	#print("browser: {}\n".format(app.storage.browser))
	await client.disconnected()
	print('disconnected')


"""
(ha) doug@uberdell:~/ha$ esptool.py --port /dev/ttyACM2 chip_id
esptool.py v4.8.1
Serial port /dev/ttyACM2
Connecting...
Detecting chip type... ESP32-S3
Chip is ESP32-S3 (QFN56) (revision v0.2)
Features: WiFi, BLE, Embedded Flash 4MB (XMC), Embedded PSRAM 2MB (AP_3v3)
Crystal is 40MHz
MAC: cc:ba:97:1d:37:f4
Uploading stub...
Running stub...
Stub running...
Warning: ESP32-S3 has no Chip ID. Reading MAC instead.
MAC: cc:ba:97:1d:37:f4
Hard resetting via RTS pin...
"""


if __name__ in {"__main__", "__mp_main__"}:
	ui.run()
