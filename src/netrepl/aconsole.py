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
from ngmqttserver import NGMQTTServer, mqtt_nodes, shutdown_node, remove_node, resubscribe_all
import os

def pflush(*args):
	print(*args, flush=True)
	
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
			pflush("retry: {}: ".format(i+1), command)
			output.insert(0, "error" )

	thread_done.set()

async def outsource_function(command, logger=None):
	global output
	thread_done = asyncio.Event()

	if logger:
		logger.push("outsource_function: command: {}".format(command))

	pflush("outsource_function: command: {}".format(command))
	
	process = threading.Thread(target=call_check_output, args=(command, thread_done))
	process.start()

	await thread_done.wait()

# function to call esptool with hard reset (default)
async def esptool_functions(port, action, log):
	global output

	if action == "reset":

		pflush("{}: starting esptool (reset_port)".format(port))

		log.push("resetting port on {}\n".format(port) )

		reset_args = esptool_modes["chip_id_reset"].format(port).split()

		pflush("before await outsource_function")
		await outsource_function(reset_args, logger=log)

		pflush("after await outsource_function")
		result = output[0].decode()

		# for line in result.split("\n"):
		# 	log.push(line)

		if result == "error":
			log.push("error resetting port on {}\n".format(port) )
			return
		
		time.sleep(2)

	if action in "install_chipid_flash_bootstrap":
		pflush("{}: starting (chip_id)".format(port))

		# if action == "bootstrap":
		# 	log.push("reading chip_id {} (RESET)\n".format(port) )
		# 	chip_id_args = esptool_modes["chip_id_reset"].format(port).split()
		# else:
		# log.push("reading chip_id on {}\n".format(port) )
		chip_id_args = esptool_modes["chip_id_reset"].format(port).split()
		
		await outsource_function(chip_id_args)

		chip_id_output = output[0]
		log.push("chip_id_output: {}".format(output))

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
			pflush("Error: could not determine chip_type or mac_address")
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

		pflush("chip_id: chip_type: {}, mac_address: {}".format(chip_type, mac_address))
		
		# wait for device
		time.sleep(2)

	if action in "install_erase":
		pflush("{}: starting (erase_flash)".format(port))

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
		pflush("{}: starting (write_flash)".format(port))

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

		pflush("{}: starting rshell (copy_bootstrap_files)".format(port))

		log.push(" ")
		log.push("RSHELL: creating/copying files to {}\n".format(port) )

		# create mac.boot file instead of existing mac config file
		# will boot with mac as hostname and shows up in browser

		with open(ams_path + "{}.boot".format(mac_address), mode="w") as f:
			f.write('{{ "run": "{}" }}\n'.format(mac_address) )

		with open("file_copy_list", mode="w") as f:
			f.write('{}\n'.format(rshell_commands.format(ams_path, mac_address, mac_address) ) )

		# await outsource_function("ls -al /dev/ttyACM*".split() )
		# pflush(output[0].decode())
		#pflush(os.listdir("/dev/"))

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
		pflush('{}: init completed'.format(port))


###########################################
## ESPTOOL TABLE
###########################################

@ui.page('/esptool')
def esptool_table():
	pflush('esptool_table')

	row_data = ["Loading ...","",""]

	ui.add_body_html(style_sheet)

	# Called every 3 seconds to check for changes to the table data
	@ui.refreshable
	def update_rows():

		last_table = row_data.copy()
		#pflush(last_table)

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

			pflush("/esptool/{}?action={}".format(port, action))
			
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
## LAUNCHPAD
###########################################

@ui.page('/launchpad/{mac_server}')
async def launchpad(mac_server, client: Client):
	mac_address = mac_server.split(".")[0]
	details = mqtt_nodes[mac_server]

	pflush("{}: loading launchpad".format(mac_address))

	ui.page_title(mac_address)

	with ui.button_group():
		if "ipv4" in details:
			open_config = ui.button(f"open: http://{details['ipv4']}", on_click=lambda: ui.navigate.to("http://{}".format(details['ipv4']) ) )
		if "hostname" in details:
			open_config = ui.button(f"open: http://{details['hostname']}", on_click=lambda: ui.navigate.to("http://{}".format(details['hostname']) ) )

	log = ui.log(max_lines=50).classes('h-screen').style('white-space: pre-wrap')



	keys_sorted = sorted(details.keys())

	for k in keys_sorted:
		v = details[k]
		log.push("{}: {}".format(k,v))



###########################################
## ESPTOOL
###########################################

@ui.page('/esptool/{device}')
async def esptool(device, client: Client, action: str="", chip_type: str="", mac_address: str=""):
	pflush("{}: loading esptool page ({})".format(device, action))

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
	# 	pflush("esptool: resetting")
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
	# 		pflush("esptool: erasing flash")
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
	# 		pflush("esptool: writing flash")
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
	# 		pflush("esptool: copying bootstrap files")
	# 		bootstrap_result = copy_bootstrap_files(device, mac_address, log)


	await client.disconnected()
	pflush('{}: esptool page closed'.format(device))




###########################################
## ESP32 proxy for SSE messages
###########################################
	


async def sse_proxy(hostname: str, queue: asyncio.Queue):
	# Authenticate with ESP32 (password only) and stream /tail_console into queue.

	pflush("sse_proxy: setting up: {}".format(hostname))

	login_url = f"http://{hostname}/"
	sse_url = f"http://{hostname}/tail_console"

	timeout = httpx.Timeout(connect=10, read=130, write=130, pool=130)
	
	while True:
		try:
			pflush("sse_proxy: connecting to: {}".format(hostname))
			await queue.put(f"[INFO] Starting proxy connection to: {hostname}")
			
			async with httpx.AsyncClient(timeout=timeout) as client:
				# 1) Authenticate with password only
				pflush("sse_proxy: authenticating to: {}".format(hostname))
				resp = await client.post(
					login_url,
					data={"password": device_password},
					follow_redirects=True,
				)
				if resp.status_code != 200:
					pflush("sse_proxy: login failed for: {}".format(hostname))
					await queue.put(f"[ERROR] Login failed for {hostname}: {resp.text}")
					return

				# 2) Connect to SSE with session cookie
				pflush("sse_proxy: starting sse stream to: {}".format(hostname))
				async with client.stream("GET", sse_url) as response:
					if response.status_code != 200:
						pflush("sse_proxy: SSE connection failed for: {}".format(hostname))
						await queue.put(f"[ERROR] SSE connection failed: {response.status_code}")
						return

					pflush("sse_proxy: handling responses for: {}".format(hostname))
					async for raw_line in response.aiter_lines():
						#pflush("raw_line: ", raw_line)
						if raw_line.startswith("data: "):
							msg = raw_line[6:]  # strip "data: "
							await queue.put(msg)
		
		except httpx.ReadTimeout:
			pflush("sse_proxy: read timeout for: {}".format(hostname))
			await queue.put(f"[ERROR] Read timeout")
			await asyncio.sleep(1)

		except Exception as e:
			pflush("sse_proxy: exception for: {}: {}".format(hostname, e))
			await queue.put(f"[ERROR] Lost connection to {hostname}: {e}")
			await asyncio.sleep(1)

async def generate_text(log_area):
	for i in range(100):
		log_area.push("This is line {}".format(i))
		await asyncio.sleep(.5)

# @ui.page('/update')
# async def update(client: Client):
	
# 	# wait for client 
# 	await ui.context.client.connected()

# 	# get list of selected rows
# 	rows = app.storage.tab['selected_nodes']

# 	with ui.column().classes('h-screen w-full overflow-hidden'):
# 		# HEADER (fixed height)
# 		ui.label(f'Updating started: {local_time()}').classes(
# 			'p-4 bg-gray-200 w-full shrink-0 text-3xl font-bold'
# 		)
# 		# space for logging for each node
# 		for row in rows:
# 			if row['status'] != "online":
# 				pflush("update: skipping offline node: {}".format(row['hostname']))
# 				continue
			
# 			log_area = ui.log().classes(
# 				'flex-1 w-full overflow-auto text-lg font-bold monospace'
# 			).style('padding-bottom: 1rem;')

# 			hostname = row['hostname']
# 			mac_address = row['mac'].split(".")[0]
# 			webconfig = row['webconfig']

# 			log_area.push(f"Updating: {hostname} - {mac_address}" )

# 			progress_bar = ui.linear_progress()


# 			# instantiate netrepl
# 			netrepl = NetRepl(hostname, nicegui_log=log_area, debug=False, verbose=False)

# 			# start console thread
# 			console_thread = threading.Thread(
# 				target=netrepl.update, 
# 				kwargs={'mac_address': mac_address, 'webconfig': webconfig, 'progress_bar': progress_bar} )
			
# 			console_thread.start()

# 		# FOOTER (fixed height at bottom)
# 		ui.label('').classes(
# 			'p-4 bg-gray-200 w-full shrink-0'
# 		)
	
# 		await client.disconnected()


# ChatGPT generated code with collapsable debug logs and name in front of progress bar
# @ui.page('/update')
# async def update(client: Client):

# 	# wait for client
# 	await ui.context.client.connected()

# 	rows = app.storage.tab['selected_nodes']

# 	with ui.column().classes('h-screen w-full overflow-hidden'):
# 		# HEADER
# 		ui.label(f'Updating started: {local_time()}').classes(
# 			'p-4 bg-gray-200 w-full shrink-0 text-3xl font-bold'
# 		)

# 		# NODE UPDATES
# 		for row in rows:
# 			if row['status'] != "online":
# 				pflush(f"update: skipping offline node: {row['hostname']}")
# 				continue

# 			hostname = row['hostname']
# 			mac_address = row['mac'].split('.')[0]
# 			webconfig = row['webconfig']

# 			# ---- container for one node ----
# 			with ui.column().classes('w-full p-2 border-b'):

# 				# header row: toggle + progress
# 				with ui.row().classes('w-full items-center gap-4'):
# 					toggle_btn = ui.button(
# 						f'{hostname} log',
# 						icon='expand_more'
# 					).props('flat')

# 					progress_bar = ui.linear_progress().classes('flex-1')

# 				# log area (hidden by default)
# 				log_area = ui.log().classes(
# 					'w-full overflow-auto text-sm font-mono bg-black text-green-400'
# 				).style(
# 					'padding: 0.75rem; max-height: 300px;'
# 				)
# 				log_area.set_visibility(False)

# 				# toggle behavior
# 				def make_toggle(log=log_area, btn=toggle_btn):
# 					def toggle():
# 						log.set_visibility(not log.visible)
# 						btn.props(
# 							'icon=expand_less' if log.visible else 'icon=expand_more'
# 						)
# 					return toggle

# 				toggle_btn.on('click', make_toggle())

# 				# initial message
# 				log_area.push(f'Updating: {hostname} - {mac_address}')

# 				# instantiate netrepl
# 				netrepl = NetRepl(
# 					hostname,
# 					nicegui_log=log_area,
# 					debug=False,
# 					verbose=False
# 				)

# 				# start update thread
# 				console_thread = threading.Thread(
# 					target=netrepl.update,
# 					kwargs={
# 						'mac_address': mac_address,
# 						'webconfig': webconfig,
# 						'progress_bar': progress_bar,
# 					},
# 					daemon=True,
# 				)
# 				console_thread.start()

# 		# FOOTER
# 		ui.label('').classes(
# 			'p-4 bg-gray-200 w-full shrink-0'
# 		)

# 		await client.disconnected()






async def reboot_nodes(rows):

	# NODE REBOOTS
	for each_row in rows:
		# if each_row['status'] != "online":
		# 	pflush(f"update: skipping offline node: {each_row['hostname']}")
		# 	continue

		hostname = each_row['hostname']
		pflush(f"reboot_node: {hostname}")

		login_url = f"http://{hostname}/"
		reboot_url = f"http://{hostname}/reboot"

		timeout = httpx.Timeout(connect=10, read=10, write=10, pool=10)
		
		try:
			async with httpx.AsyncClient(timeout=timeout) as client:
				# 1) Authenticate with password only
				pflush("reboot_node: authenticating to: {}".format(hostname))
				resp = await client.post(
					login_url,
					data={"password": device_password},
					follow_redirects=True,
				)
				if resp.status_code != 200:
					pflush("reboot_node: login failed for: {}".format(hostname))
					ui.notify(f'{hostname} - login failed', type='negative')
					return

				# 2) Reboot node
				pflush("reboot_node: sending reboot request to: {}".format(hostname))
				resp = await client.get(reboot_url)
				if resp.status_code != 200:
					pflush("reboot_node: failed for: {}".format(hostname))
					ui.notify(f'{hostname} - reboot request failed', type='negative')
					return

				pflush("reboot_node: rebooted: {}".format(hostname))
				ui.notify(f'{hostname} - reboot success!', type='positive')
		
		except Exception as e:
			pflush(f"reboot_node: {hostname}: exception: {e}")
			ui.notify(f'{hostname} - Exception! - {e}', type='warning')
			return









# ChatGPT generated code (denser and alignment fixed)
@ui.page('/update')
async def update(client: Client):

	await ui.context.client.connected()
	rows = app.storage.tab['selected_nodes']

	with ui.column().classes('h-screen w-full overflow-hidden gap-0 space-y-0'):
		# HEADER
		ui.label(f'Updating started: {local_time()}').classes(
			'px-4 py-2 bg-gray-200 w-full shrink-0 text-2xl font-bold'
		)

		# NODE UPDATES
		for row in rows:
			# if row['status'] != "online":
			# 	pflush(f"update: skipping offline node: {row['hostname']}")
			# 	continue

			hostname = row['hostname']
			mac_address = row['mac'].split('.')[0]
			webconfig = row['webconfig']

			# ---- per-node container (compact) ----
			# container that holds ALL rows
			with ui.column().classes('w-full gap-0 space-y-0'):

				# ONE NODE ROW (no column!)
				with ui.element('div').classes('w-full q-ma-none q-pa-none'):

					with ui.row().classes(
						'w-full items-center gap-0 q-ma-none q-pa-none q-mb-none'
					):
						toggle_btn = ui.button(
							hostname,
							icon='expand_more'
						).props(
							'flat dense no-caps'
						).classes(
							'text-left leading-tight q-ma-none q-pa-none q-mb-none'
						).style(
							'width: 14rem; min-height: 0;'
						)

						progress_bar = ui.linear_progress().props(
							'dense size=10px'
						).classes(
							'flex-1 q-ma-none q-mb-none'
						)

						status_button = ui.button(
							"--------",
						).props(
							'flat dense no-caps'
						).classes(
							'text-left leading-tight q-ma-none q-pa-none q-mb-none'
						).style(
							'width: 14rem; min-height: 0;'
						)

					log_area = ui.log().classes(
						'w-full hidden overflow-auto text-xs font-mono bg-black text-green-400 q-ma-none'
					).style(
						'padding: 0.25rem; max-height: 200px;'
					)
					log_area.set_visibility(False)

				# toggle handler (closure-safe)
				def make_toggle(log=log_area, btn=toggle_btn):
					def toggle():
						visible = not log.visible
						log.set_visibility(visible)
						btn.props(
							'icon=expand_less' if visible else 'icon=expand_more'
						)
					return toggle

				toggle_btn.on('click', make_toggle())

				# initial log line
				log_area.push(f'Updating: {hostname} - {mac_address}')

				# start update thread
				netrepl = NetRepl(
					hostname,
					nicegui_log=log_area,
					debug=False,
					verbose=False,
				)

				threading.Thread(
					target=netrepl.update,
					kwargs={
						'mac_address': mac_address,
						'webconfig': webconfig,
						'progress_bar': progress_bar,
						'status_button': status_button,
					},
					daemon=True,
				).start()

		# FOOTER
		ui.label('').classes('px-4 py-2 bg-gray-200 w-full shrink-0')

		await client.disconnected()









@ui.page('/cmd/{hostname}')
async def console_cmd(hostname: str, client: Client):

	cmd_url = f"http://{hostname}/cmd/"

	timeout = httpx.Timeout(connect=10, read=130, write=130, pool=130)
	

	async def on_send(cmd):
		pflush("on_send: cmd: {}".format(cmd))
		async with httpx.AsyncClient(timeout=timeout) as client:
			r = await client.get(cmd_url + cmd)
			pflush("on_send: response: {}".format(r.text))
			log_area.value += r.text + "\n"
		
	# hostname = hostkey.split(".")[0]
	# mac_address = hostkey.split(".")[1]
	
	ui.button("Send").on('click', lambda: on_send(cmd_to_send.text) )
	ui.input(label="Repl command", on_change=lambda e: cmd_to_send.set_text(e.value)  )
	cmd_to_send = ui.label()

	with ui.column().classes('h-screen w-full overflow-hidden'):

		# LOG (fills remaining space)
		#log_area = ui.log().style('white-space: pre-wrap !important; word-break: break-word !important;' )

		log_area = ui.textarea( value='').props('readonly autogrow').classes('flex-1 w-full font-mono text-lg')

		# FOOTER (fixed height at bottom)
		ui.label('').classes(
			'p-4 bg-gray-200 w-full shrink-0'
		)







state = {"nodename": "sse_task" }

@ui.page('/console/{action}/{hostkey}/{webconfig}')
async def console_page(action, hostkey, webconfig, client: Client):
	
	hostname = hostkey.split(".")[0]
	mac_address = hostkey.split(".")[1]
	webconfig = int(webconfig)

	pflush("{}: console: action: {}, hostname: {}, mac_address: {}".format(local_time(), action, hostname, mac_address))
	pflush(f"sse_tasks: {state}")

	await ui.context.client.connected()

	rows = app.storage.tab['selected_nodes']


	# for row in rows:
	# 	if 'node' in row and row['node'] == hostname:
	# 		mac_address = row['mac']
	# 		break

	# if not mac_address:
	# 	ui.notify("FATAL: no mac address for node {} in rows? Unexpected Error!".format(hostname))
	# 	return

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
	#webconfig = int(mqtt_nodes[mac_address].get('webconfig', 0))

	if (action == "console" and webconfig == 0) or action == "update" or action == "reboot" or action == "backup":

		# instantiate netrepl
		netrepl = NetRepl(hostname, nicegui_log=log_area, user_exit=user_exit, debug=False, verbose=False)

		# start console thread
		console_thread = threading.Thread(
				target=netrepl.tail_console, 
				kwargs={'action': action, 'mac_address': mac_address, 'webconfig': webconfig} )
			
		console_thread.start()

		# time_out = 60
		# while time_out > 0 and console_thread.is_alive():
		# 	await asyncio.sleep(1)
		# 	time_out -= 1

		await client.disconnected()
		user_exit.set()
		pflush("console: Page closed for: {}".format(hostname))

	# for webconfig devices only, console is done here and not in netrepl
	if webconfig > 1:
		pflush("console: webconfig console opened for: {}".format(hostname))

		# check for existing sse_task in state
		if state.get(hostname):
			pflush(f"console: existing sse_task found for: {hostname} - task: {state[hostname]}")
			state[hostname].cancel()
			state.pop(hostname)

		# Start http console using webconfig
		#ui.navigate.to("/console_start/{}".format(hostname), new_tab=True)

		q = asyncio.Queue()

		sse_task = asyncio.create_task(sse_proxy(hostname, q))
		pflush(f"console: sse_task started for: {hostname} - adding to state as task: {sse_task}")

		# add sse_task to state
		state[hostname] = sse_task

		async def reader():
			while True:
				line = await q.get()
				if paused["value"]:
					buffer.append(line)
					continue
				log_area.push(line)

		reader_task = asyncio.create_task(reader())
		pflush(f"console: reader_task started for: {hostname} as task: {reader_task}")

		await client.disconnected()
		
		pflush("console: client disconnected, cleaning up tasks for: {}".format(hostname))

		sse_task.cancel()
		await asyncio.sleep(3)
		if sse_task.cancelled():
			pflush(f"console: sse_task confirmed cancelled for: {hostname} - removing task: {sse_task} from state")
			state.pop(hostname)
		else:
			pflush(f"console: sse_task not cancelled for: {hostname} - task: {sse_task}")

		reader_task.cancel()

		await asyncio.sleep(3)
		if reader_task.cancelled():
			pflush(f"console: reader_task confirmed cancelled for: {hostname} - removing task: {reader_task} from state")
		else:
			pflush(f"console: reader_task not cancelled for: {hostname} - task: {reader_task}")

	pflush("console: Page closed for: {}".format(hostname))

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
	pflush('home page opened - mqtt_nodelist')

	#ui.add_head_html('<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">')

	ui.add_head_html('''
	<style>
	@keyframes blink {
	0%   { opacity: 1; }
	50%  { opacity: 0; }
	100% { opacity: 1; }
	}
	.status-blink {
	animation: blink 500ms infinite;
	}
	</style>
	''')


	ui.add_body_html(style_sheet)
	# dark = ui.dark_mode()
	# dark.enable()

	# Called every 3 seconds to check for changes to the table data
	@ui.refreshable
	def update_rows(update_grid=True):

		last_table = row_data.copy()
		#pflush(last_table)

		row_data.clear()

		name2mac_index = {}
		sorted_node_names = []

		for mac, node in mqtt_nodes.items():
			#pflush(f"mac: {mac}, node: {node}")

			if 'hostname' not in node:
				pflush(f"!!!!!!! hostname not in node: {node} mac {mac}")
				continue

			unique_name = node['hostname'] + "." + mac
			#pflush(f"unique_name: {unique_name}")
			if unique_name in sorted_node_names: 
				continue

			sorted_node_names.append(unique_name)
			name2mac_index[unique_name] = mac

		sorted_node_names.sort()

		#for mac, node in mqtt_nodes.items():
		for node_name in sorted_node_names:
			mac = name2mac_index[node_name]
			node = mqtt_nodes[mac]
			#pflush("node: {}".format(node))
			# hostname = node.get('hostname', "cubeclock")
			hostname = node.get('hostname', "")
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
			#pflush(f"{hostname}: {node} {total_mem} {chip} {build} {platform}")
			# if total_mem:

			# 	if total_mem > 1000000:
			# 		platform = "{}({:.0f}M) {}".format(chip, total_mem / 1000000, build)
			# 	else:
			# 		platform = "{}({:.0f}K) {}".format(chip, total_mem / 1000, build)

			last_restart = node.get('last_restart', "")

			uptime = "?"
			
			if last_restart:

				# only calculate days passed if it is a valid date
				# otherwise, a reboot just happened
				if '1999' in last_restart:
					uptime = "?"
				else:
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

			webconfig = node.get('webconfig', "")

			row_data.append( {"node": node_name,
					"hostname": hostname, 
					"mac": mac, 
					"status": status,
					"webconfig": webconfig,
					"server": server,
					"mpy": mpy,
					"signal": signal,
					"reboots": reboots,
					"uptime": uptime,
					"platform": platform
					} )

		#pflush(row_data)
		
		# for device in pathlib.Path('/dev').glob('tty[UA][SC][BM]*'):
		# 	timestamp = datetime.datetime.fromtimestamp(device.stat()[7])
		# 	row_data.append( {"node": "/dev/" + device.name , "mac": timestamp.strftime("%m/%d %H:%M:%S"), "status": "", "server": "" } )

		if update_grid and last_table != row_data:
			#pflush(f"updating grid - {row_data} ")
			#grid.update()
			ui.navigate.to("/")
			#grid.run_grid_method('autoSizeAllColumns')

	async def esptool_handler(button: ui.button):
		pflush("esptool_handler")

		ui.navigate.to("/esptool", new_tab=True)

	# Called when a console related action button is clicked
	# reboot, update, console, mqttserver
	async def main_button_handler(button: ui.button):
		pflush(f"main page button clicked: {button.text}")
		
		action = button.text
		
		await ui.context.client.connected()

		rows = await grid.get_selected_rows()

		if not rows:
			return
		
		pflush(rows)
		
		app.storage.tab.update({'selected_nodes': rows})
		pflush(app.storage.tab)
	
		if action == "update":
			ui.navigate.to("/update", new_tab=True)
			return

		if action == "reboot":
			await reboot_nodes(rows)
			return
		
		for row in rows:
			hostname = row['node']
			mac_address = hostname.split(".")[1]
			webconfig = str(row['webconfig'])
			if not webconfig:
				webconfig = "0"
			
			# if row['status'] == "online":
			if action == "update" or action == "reboot" or action == "backup" or action == "console":
				ui.navigate.to("/console/{}/{}/{}".format(action, hostname, webconfig), new_tab=True)
				pflush(f"Returned from navigate.to for: {hostname}")

			if action == "shutdown":

				shutdown_node(hostname)
				ui.notify("shutdown: {} ".format(hostname) )

			# remove mqtt config and sensor
			# homeassistant/sensor/esp/ecfabc281b13/config
				
			# hostname is hostname.mac_addr.server_name
			if action == "remove":
				remove_node(hostname)				
				ui.notify("removed: {}".format(hostname) )

	# async def output_selected_rows():
	# 	rows = await grid.get_selected_rows()
	# 	if rows:
	# 		for row in rows:
	# 			detail = mqtt_nodes[row['mac']]
	# 			ui.notify(detail)
	# 	else:
	# 		ui.notify('No rows selected.')


	# refresh mqtt node list completely
	async def output_selected_row():
		global mqtt_nodes
		mqtt_nodes.clear()
		resubscribe_all()


	def reload_nodes():
		exit(1)

	with ui.button_group():
		#ui.link('console', "/console", new_tab=True)
		ui.button('console', on_click=lambda e: main_button_handler(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('update', on_click=lambda e: main_button_handler(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('reboot', on_click=lambda e: main_button_handler(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('backup', on_click=lambda e: main_button_handler(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('shutdown', on_click=lambda e: main_button_handler(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
		ui.button('remove', on_click=lambda e: main_button_handler(e.sender)).style('font-size: 10px; width: 60px; height: 10px;')
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

	# 'hide': False, 'hide': True 
	# useful icons: ⚠️✅ ❌ ⚠️ ℹ️ ⛔ 🔴 🟢 🟡 🔵 ☑️ ⬜ ⬛ ✔ ✖ ❗ ❓⏰️

	column_data = [
		{'headerName': 'Hostname', 'field': 'hostname',
		'checkboxSelection': True, 'headerCheckboxSelection': True, 'width': 270},

		{'headerName': 'Node', 'field': 'node', 'width': 95, 'hide': True},

		{
			'headerName': 'St',
			'field': 'status',
			'width': 80,

			':valueFormatter': '''
				(params) =>
					params.value === "online"    ? "✅" :
					params.value === "wdt"       ? "⏰️" :
					params.value === "shutdown"  ? "💤" :
					params.value === "degraded"  ? "⚠️" :
					params.value === "offline"   ? "❌" :
					params.value === "critical"  ? "⛔" :
					"❓"
			''',

			'cellClassRules': {
				'status-blink': 'x === "degraded" || x === "offline" || x === "critical"'
			}
		},


		{'headerName': 'WC', 'field': 'webconfig', 'width': 95},
		{'headerName': 'up', 'field': 'uptime', 'width': 140},
		{'headerName': 'db', 'field': 'signal', 'width': 100},
		{'headerName': 'RB', 'field': 'reboots', 'width': 95},
		{'headerName': 'Server', 'field': 'server'} ]
	
	update_rows(update_grid=False)

	grid = ui.aggrid( {'columnDefs': column_data,
		#'autoSizeStrategy': 'fitCellContents',
		'rowData': row_data,
		'rowSelection': 'multiple',
		'rowHeight': 22,
	} ).classes('h-[1500px]' )

	ui.button('refresh', on_click=output_selected_row)

	def handle_cell_click(event):
		# event.args['data'] has the row data (even if sorted in the gui)
		# row_index is the row selected based on the gui order and may not match the grid.options['rowData']
		# so use the event.args data for handling this
		#pflush(event.args)
		col = event.args['colId']
		#row_index = event.args['rowIndex']
		#pflush(f"col: {col}, row: {row_index}")
		#row_data = grid.options['rowData'][row_index]
		#pflush(f'row_data: {row_data}')
		row_data = event.args['data']
		#detail = mqtt_nodes[row_data['mac']]
		mac_address = row_data['mac']
		ui.navigate.to(f"/launchpad/{mac_address}", new_tab=True)

		#ui.notify(detail)

	grid.on('cellClicked', handle_cell_click)


@ui.page('/test')
async def test(client: Client):
	pflush('preparing')
	await client.connected()
	pflush('connected')
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

	#pflush("tabs: {}\n".format(app.storage.tab))
	#pflush("client: {}\n".format(app.storage.client))
	#pflush("user: {}\n".format(app.storage.user))
	#pflush("general: {}\n".format(app.storage.general))
	#pflush("browser: {}\n".format(app.storage.browser))
	await client.disconnected()
	pflush('disconnected')


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
