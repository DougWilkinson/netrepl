# aconsole.py

from nicegui import ui, app, Client

# used for pausing console output in /console
from types import SimpleNamespace
import httpx

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
from ngmqttserver import NGMQTTServer, mqtt_nodes, shutdown_node, remove_node
import os

device_password = os.environ.get("WRPWD")

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

		--ag-font-size: 18px;
		--ag-font-family: monospace;
	}
	</style>
	'''

rshell_commands = """cd {}
cp {}.boot /pyboard/{}
cp boot.py /pyboard
cp blinkled.py /pyboard
cp main.py /pyboard
cp hass.py /pyboard
cp msgqueue.py /pyboard
cp device.py /pyboard
cp webrepl_cfg.py /pyboard
cp core.py /pyboard
cp flag.py /pyboard
cp versions.py /pyboard
cp hassdocker/mysecrets.py /pyboard
repl ~ import machine ~ machine.reset() ~
"""


row_data = ["loading...","",""]

output = []

def local_time():
	return time.strftime("%Y/%m/%d-T%H:%M:%S",time.localtime())

def call_check_output(command, thread_done):
	global output

	for i in range(3):
		try:
			output.insert(0, (subprocess.check_output(command) ) )
			break
		except subprocess.CalledProcessError as e:
			print("retry: {}: ".format(i+1), command)
			output.insert(0, "error" )

	thread_done.set()

async def outsource_function(command):
	global output
	thread_done = asyncio.Event()

	print("outsource_function: command: {}".format(command))
	
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

		# for line in result.split("\n"):
		# 	log.push(line)

		if result == "error":
			log.push("error resetting port on {}\n".format(port) )
			return
		
		time.sleep(2)

	if action in "install_chipid_flash_bootstrap":
		print("{}: starting (chip_id)".format(port))

		# if action == "bootstrap":
		# 	log.push("reading chip_id {} (RESET)\n".format(port) )
		# 	chip_id_args = esptool_modes["chip_id_reset"].format(port).split()
		# else:
		# log.push("reading chip_id on {}\n".format(port) )
		chip_id_args = esptool_modes["chip_id_reset"].format(port).split()
		
		await outsource_function(chip_id_args)

		chip_id_output = output[0].decode()

		if chip_id_output == "error":
			log.push("error reading chip_id on: {}\n".format(port) )
			return
		
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
		time.sleep(2)

	if action in "install_erase":
		print("{}: starting (erase_flash)".format(port))

		log.push("erasing flash on {}\n".format(port) )
		log.push(" ")

		erase_args = esptool_modes["erase_flash"].format(port).split()

		await outsource_function(erase_args)
		
		erase_flash_output = output[0].decode()

		if erase_flash_output == "error":
			log.push("error flashing to port: {}\n".format(port) )
			return
		
		# found_success = False
		# for line in erase_flash_output.split("\n"):
		# 	log.push(line)
		# 	if "success" in line:
		# 		log.push(" ")

		log.push("ERASE: Success!")
				# log.push("----------------------------")
				# found_success = True

		# if not found_success:
		# 	log.push(" ")
		# 	log.push("Error: could not erase flash - stopping")
		# 	log.push("----------------------------")
		# 	return
		
	time.sleep(2)

	if action in "install_flash":		
		print("{}: starting (write_flash)".format(port))

		log.push("writing flash on {}\n".format(port))
		
		flash_file = "/home/doug/ha/flash/{}/latest.bin".format(chip_type)
		
		flash_args = esptool_modes[chip_type].format(port, flash_file).split()

		await outsource_function(flash_args)

		flash_output = output[0].decode()

		if flash_output == "error":
			log.push("error resetting port on {}\n".format(port) )
			return
		
		log.push("FLASH: Success!")

		# found_success = False

		# for line in flash_output.split("\n"):
		# 	log.push(line)
		# 	if "Wrote" in line:
		# 		log.push(" ")
		# 		log.push(line)
		# 		log.push("----------------------------")
		# 		found_success = True

		# if not found_success:
		# 	log.push("Error: could not write flash")
		# 	return

	time.sleep(2)

	if action in "install_bootstrap":

		print("{}: starting rshell (copy_bootstrap_files)".format(port))

		log.push(" ")
		log.push("RSHELL: creating/copying files to {}\n".format(port) )

		# create mac.boot file instead of existing mac config file
		# will boot with mac as hostname and shows up in browser

		with open(ams_path + "{}.boot".format(mac_address), mode="w") as f:
			f.write('{{ "run": "{}" }}\n'.format(mac_address) )

		with open("file_copy_list", mode="w") as f:
			f.write('{}\n'.format(rshell_commands.format(ams_path, mac_address, mac_address) ) )

		# await outsource_function("ls -al /dev/ttyACM*".split() )
		# print(output[0].decode())
		#print(os.listdir("/dev/"))

		rshell_args = "rshell -p /dev/{} -f file_copy_list".format(port).split()
		#log.push(rshell_args)

		await outsource_function(rshell_args)

		rshell_output = output[0].decode()

		if rshell_output == "error":
			log.push("error resetting port on {}\n".format(port) )
			return
		
		# for line in rshell_output.split("\n"):
		# 	log.push(line)

		# # cleanup tmp files
		# os.remove("{}{}.boot".format(ams_path, mac_address))

		# try:
		# 	#rshell_output = 'simulate rshell'
		# 	rshell_output = subprocess.check_output(rshell_args.split())
		# 	log.push("rshell commands completed\n")
		# 	log.push(rshell_output)

		# except subprocess.CalledProcessError as e:
		# 	log.push("Error: {}".format(e.output.decode()))
		# 	return

		# log.push(" ")
		log.push("\n\nbootstrap complete! \n")
		#log.push("----------------------------")
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
		'auto_size_columns': True,
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
## ESP32 proxy for SSE messages
###########################################
	


async def sse_proxy(hostname: str, queue: asyncio.Queue):
	# Authenticate with ESP32 (password only) and stream /tail_console into queue.

	print("sse_proxy: setting up: {}".format(hostname))

	login_url = f"http://{hostname}/"
	sse_url = f"http://{hostname}/tail_console"

	timeout = httpx.Timeout(connect=10, read=130, write=130, pool=130)
	
	while True:
		try:
			print("sse_proxy: connecting to: {}".format(hostname))
			await queue.put(f"[INFO] Starting proxy connection to: {hostname}")
			
			async with httpx.AsyncClient(timeout=timeout) as client:
				# 1) Authenticate with password only
				print("sse_proxy: authenticating to: {}".format(hostname))
				resp = await client.post(
					login_url,
					data={"password": device_password},
					follow_redirects=True,
				)
				if resp.status_code != 200:
					print("sse_proxy: login failed for: {}".format(hostname))
					await queue.put(f"[ERROR] Login failed for {hostname}: {resp.text}")
					return

				# 2) Connect to SSE with session cookie
				print("sse_proxy: starting sse stream to: {}".format(hostname))
				async with client.stream("GET", sse_url) as response:
					if response.status_code != 200:
						print("sse_proxy: SSE connection failed for: {}".format(hostname))
						await queue.put(f"[ERROR] SSE connection failed: {response.status_code}")
						return

					print("sse_proxy: handling responses for: {}".format(hostname))
					async for raw_line in response.aiter_lines():
						#print("raw_line: ", raw_line)
						if raw_line.startswith("data: "):
							msg = raw_line[6:]  # strip "data: "
							await queue.put(msg)
		
		except httpx.ReadTimeout:
			print("sse_proxy: read timeout for: {}".format(hostname))
			await queue.put(f"[ERROR] Read timeout")
			await asyncio.sleep(1)

		except Exception as e:
			print("sse_proxy: exception for: {}: {}".format(hostname, e))
			await queue.put(f"[ERROR] Lost connection to {hostname}: {e}")
			await asyncio.sleep(1)


state = SimpleNamespace( nodes={}, )

@ui.page('/console/{action}/{hostname}')
async def console_page(action, hostname, client: Client):
	print("{}: console: action: {}, hostname: {}".format(local_time(), action, hostname))

	await ui.context.client.connected()

	rows = app.storage.tab['selected_nodes']

	mac_address = None
	for row in rows:
		if 'node' in row and row['node'] == hostname:
			mac_address = row['mac']
			break

	if not mac_address:
		ui.notify("FATAL: no mac address for node {} in rows? Unexpected Error!".format(hostname))
		return

	# used to signal exit from console for classic netrepl
	user_exit = asyncio.Event()

	#ui.label(f"Console for {hostname}").classes("text-lg font-bold")
	
	# previous AI generated values
	#log_area = ui.log(max_lines=200).classes("w-full h-96")
	
	#log_area = ui.log(max_lines=500).classes('h-full').classes('text-2xl').classes('monospace')
	
	paused = {"value": False}
	buffer = []  # will hold lines while paused

	def toggle_pause():
		paused["value"] = not paused["value"]
		if paused["value"]:
			btn.text = hostname + " - PAUSED"
		else:
			btn.text = hostname + " - press to Pause"
			# flush buffered lines into log
			for line in buffer:
				log_area.push(line)
			buffer.clear()

	#btn = ui.button("Pause", on_click=toggle_pause).classes("mt-2")

	with ui.column().classes('h-screen w-full overflow-hidden'):
		# HEADER (fixed height)
		btn = ui.button(hostname + " - press to Pause", on_click=toggle_pause).classes(
			'p-4 bg-gray-200 w-full shrink-0' ).classes('text-3xl font-bold')

		# LOG (fills remaining space)
		log_area = ui.log().classes(
			'flex-1 w-full overflow-auto text-lg font-bold monospace'
		).style('padding-bottom: 1rem;')

		# FOOTER (fixed height at bottom)
		ui.label('').classes(
			'p-4 bg-gray-200 w-full shrink-0'
		)

	log_area.push("{}: [INFO] Starting: {}".format(local_time(), action))

	# check for webconfig support
	webconfig = int(mqtt_nodes[mac_address].get('webconfig', 0))

	if action == "update" or action == "reboot" or action == "backup":

		# instantiate netrepl
		netrepl = NetRepl(hostname, nicegui_log=log_area, user_exit=user_exit, debug=False, verbose=False)

		# start console thread
		console_thread = threading.Thread(
				target=netrepl.tail_console, 
				kwargs={'action': action, 'mac_address': mac_address, 'webconfig': webconfig} )
			
		console_thread.start()

		time_out = 60
		while time_out > 0 and console_thread.is_alive():
			await asyncio.sleep(1)
			time_out -= 1	

	# for webconfig devices only, console is done here and not in netrepl
	if webconfig > 1:
		print("console: webconfig console opened for: {}".format(hostname))

		# Start http console using webconfig
		ui.navigate.to("/console_start/{}".format(hostname), new_tab=True)

		q = asyncio.Queue()

		sse_task = asyncio.create_task(sse_proxy(hostname, q))
		print("console: sse_task started for: {}".format(hostname))

		async def reader():
			while True:
				line = await q.get()
				if paused["value"]:
					buffer.append(line)
					continue
				log_area.push(line)

		reader_task = asyncio.create_task(reader())
		print("console: reader_task started for: {}".format(hostname))

		await client.disconnected()
		
		print("console: client disconnected, cleaning up for: {}".format(hostname))
		sse_task.cancel()
		reader_task.cancel()

	print("console: Page closed for: {}".format(hostname))

# ####################################################
# # Connect to esp32 and start console window page
# ####################################################
	
# @ui.page("/console_start/{hostname}")
# async def console_start(hostname: str):

# 	ui.label(f"Console for {hostname}").classes("text-lg font-bold")
# 	log_area = ui.log(max_lines=200).classes("w-full h-96")

# 	paused = {"value": False}
# 	buffer = []  # will hold lines while paused

# 	def toggle_pause():
# 		paused["value"] = not paused["value"]
# 		if paused["value"]:
# 			btn.text = "Resume"
# 		else:
# 			btn.text = "Pause"
# 			# flush buffered lines into log
# 			for line in buffer:
# 				log_area.push(line)
# 			buffer.clear()

# 	btn = ui.button("Pause", on_click=toggle_pause).classes("mt-2")

# 	# if hostname not in state.nodes:
# 	# 	q = asyncio.Queue()
# 	# 	task = asyncio.create_task(sse_proxy(hostname, q))
# 	# 	state.nodes[hostname] = {"task": task, "queue": q}

# 	# q = state.nodes[hostname]["queue"]

# 	q = asyncio.Queue()
# 	sse_task = asyncio.create_task(sse_proxy(hostname, q))

# 	async def reader():
# 		while True:
# 			line = await q.get()
# 			log_area.push(line)

# 	reader_task = asyncio.create_task(reader())

# 	await client.disconnected()
# 	sse_task.cancel()
# 	reader_task.cancel()





###########################################
## MAIN TABLE
###########################################

@ui.page('/')
def mqtt_nodelist():
	print('home page opened - mqtt_nodelist')

	ui.add_head_html('<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">')

	ui.add_body_html(style_sheet)
	# dark = ui.dark_mode()
	# dark.enable()

	# Called every 3 seconds to check for changes to the table data
	@ui.refreshable
	def update_rows():

		last_table = row_data.copy()
		#print(last_table)

		row_data.clear()

		for mac, node in mqtt_nodes.items():
			#print("node: {}".format(node))
			hostname = node.get('hostname', "cubeclock")
			build = node.get('platform', "")
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

			# total_mem = node.get('memory', 0)
			#print(f"{hostname}: {node} {total_mem} {chip} {build} {platform}")
			# if total_mem:

			# 	if total_mem > 1000000:
			# 		platform = "{}({:.0f}M) {}".format(chip, total_mem / 1000000, build)
			# 	else:
			# 		platform = "{}({:.0f}K) {}".format(chip, total_mem / 1000, build)

			last_restart = node.get('last_restart', "")

			if last_restart:

				input_format = "%Y/%m/%d-T%H:%M:%S"
				target_datetime = datetime.strptime(last_restart, input_format)

				now = datetime.now()
				delta = now - target_datetime
				days_passed = delta.days
				hours_passed = delta.seconds // 3600

				time_str = target_datetime.strftime("%H:%M")

				uptime = "{}d".format(days_passed)

			mpy = node.get('mpy', "?.??.0")[0:4]

			signal = node.get('signal', 0)
			reboots = node.get('reboots', 0)

			try:
				server = node['mysecrets']
			except KeyError:
				try:
					server = node['server']
				except KeyError:
					server = "n/a"
			
			status = node.get('status', "unknown")

			row_data.append( {"node": hostname, 
					"mac": mac, 
					"status": status,
					"server": server,
					"mpy": mpy,
					"signal": signal,
					"reboots": reboots,
					"uptime": uptime,
					"platform": platform
					} )

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

		# if action in "backup|update|reboot|console":
		# 	ui.navigate.to("/console/{}".format(action), new_tab=True)
		# 	return

		for row in rows:
			
			if row['status'] == "online":
				if action == "update" or action == "reboot" or action == "backup" or action == "console":
					hostname = row['node']
					ui.navigate.to("/console/{}/{}".format(action, hostname), new_tab=True)

			if action == "shutdown" and row['status'] == "offline":
				hostname = row['node']
				mac_address = row['mac']
				shutdown_node(mac_address)
				ui.notify("shutdown: {} ({})".format(hostname, mac_address))

			# remove mqtt config and sensor
			# homeassistant/sensor/esp/ecfabc281b13/config
				
			if action == "remove" and row['status'] != "online":
				hostname = row['node']
				mac_address = row['mac']
				remove_node(mac_address)				
				ui.notify("removed: {} ({})".format(hostname, mac_address))

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
		ui.button('console', on_click=lambda e: console(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('update', on_click=lambda e: console(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('reboot', on_click=lambda e: console(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('backup', on_click=lambda e: console(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('shutdown', on_click=lambda e: console(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('remove', on_click=lambda e: console(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('esptool', on_click=lambda e: esptool_handler(e.sender) ).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('resize', on_click=lambda e: grid.run_grid_method('autoSizeAllColumns') ).style('font-size: 10px; width: 60px; height: 10px;')

	ui.timer(3, update_rows)


	def icon_renderer(params):
		"""Custom cell renderer to display an icon based on cell value."""
		if params.value == 'online':
			return '<i class="fa fa-check-circle text-green-500"></i>'
		
		if params.value == 'offline':
			return '<i class="fa fa-times-circle text-red-500"></i>'
		
		return '<i class="fa fa-times-circle text-blue-500"></i>'
		
	# column_defs = [
	# 	{'headerName': 'Status', 'field': 'status', 'cellRenderer': icon_renderer},
	# 	{'headerName': 'Name', 'field': 'name'},
	# ]

	column_data = [
			{'headerName': 'Node', 'field': 'node', 'width': 50, 'checkboxSelection': True},
			{'headerName': 'St', 'field': 'status', ':valueFormatter': '(params) => params.value === "online" ? "✅" : (params.value === "shutdown" ? "💤" : "❌")', 'width': 5,
				# 'cellClassRules': {
				# 'bg-red-300': 'x == "offline"',
				# 'bg-blue-300': 'x == "shutdown"',
				# 'bg-green-300': 'x == "online"'} 
				},
			{'headerName': 'up', 'field': 'uptime', 'width': 4},
			{'headerName': 'db', 'field': 'signal', 'width': 4},
			{'headerName': 'RBs', 'field': 'reboots', 'width': 4},
			#{'headerName': 'platform', 'field': 'platform', 'width': 15},
			#{'headerName': 'Mac', 'field': 'mac', 'width': 15},
			{'headerName': 'Server', 'field': 'server', 'width': 35},
			#{'headerName': 'mpy', 'field': 'mpy', 'width': 8},
		]
	
	grid = ui.aggrid( {'columnDefs': column_data,
		'autoSizeStrategy': 'fitCellContents',
		'rowData': row_data,
		'rowSelection': 'multiple',
		'rowHeight': 20,
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
	#ui.context.client.page_container.default_slot.children[0].props(':style-fn="o => ({ height: `calc(100vh - ${o}px)` })"')
	#ui.context.client.content.classes('h-full')
	#log = ui.log(max_lines=500).classes('text-lg').classes('monospace')

	log = ui.log(max_lines=5).classes('text-1xl').classes('monospace bold')
	log.push("1xl monospace")
	log = ui.log(max_lines=5).classes('text-2xl').classes('monospace')
	log.push("2xl monospace")
	log = ui.log(max_lines=5).classes('text-lg font-bold monospace')
	log.push("text-lg font-bold monospace")

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
