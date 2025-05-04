# aconsole.py

from nicegui import ui, app, Client
import paho.mqtt.client as mqtt
import json
import multiprocessing
from microdot import Microdot
import asyncio
from mysecrets import mqtt_user, mqtt_pass, mqtt_servers, device_topic, device_config_path
from netreplclass import NetRepl, genhash_func
import threading
import subprocess
import re
import time

mqtt_nodes = {}

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

esptool_modes = { "esp32s3mini": "esptool.py --port /dev/{} --chip esp32s3 --baud 460800 write_flash 0 {}",
			   "erase_flash": "esptool.py --port /dev/{} erase_flash",
			   "chip_id": "esptool.py --port /dev/{} chip_id",
			   "esp32s3dev": "esptool.py --port /dev/{} --chip esp32s3 --baud 460800 write_flash 0 {}" }

class MQTTServer:
	def __init__(self, mqtt_query_server):
		print("{} - query started ...".format(mqtt_query_server))

		self.server = mqtt_query_server
		self.client = mqtt.Client()
		self.client.username_pw_set(mqtt_user, password=mqtt_pass)
		self.client.connect(mqtt_query_server, 1883, 60)
		self.client.on_message=self.on_message
		self.client.subscribe('hass/sensor/esp/+/state')
		self.client.subscribe('hass/sensor/esp/+/attrs')
		self.client.loop_start()

	def add_update_node(self, topic, message):
		global mqtt_nodes
		if type(topic) != str:
			return
		device_id = "{}".format(topic.split('/')[3] )
		if device_id not in mqtt_nodes:
			mqtt_nodes[device_id] = {}

		if "/attrs" in topic:

			message = json.loads(message)

			for k,v in message.items():
				mqtt_nodes[device_id][k] = v

		if "/state" in topic:
			mqtt_nodes[device_id]['status'] = message

	def on_message(self, client, userdata, mqtt_message):
		#print(client.host, mqtt_message.topic)
		# device_id = "{}/{}".format(self.server, message.topic.split('/')[3] )
		topic = mqtt_message.topic
		server = client.host
		
		message = mqtt_message.payload.decode()
		self.add_update_node( topic, message)

	# async def update_nodes():
	# 	global mqtt_nodes
	# 	while True:
	# 		for server in mqtt_servers:

servers = {}
for server in mqtt_servers:
	servers[server] = MQTTServer(server)

row_data = ["loading...","",""]

class ReadFile:
	def __init__(self, filename, log):
		self.filename = filename
		self.opened = False
		self.log = log
		self.handle = None

	def open(self):
		if self.handle:
			return True
		try:
			self.handle = open(self.filename)
			return True
		except:
			self.log.push("waiting for {}".format(self.filename))
			return False

		# self.buffer = []
		# last = ["..."]
		# next = "..."
		# while next:
		# 	next = self.handle.readline()
		# 	last.append(next)
		# 	if len(last) > 50:
		# 		last.pop(0)

	def readline(self):
		if not self.open():
			return
		next_lines = self.handle.readlines()
		for line in next_lines:
			if line:
				self.log.push(line)

@ui.page('/test')
async def test(client: Client):
	print('preparing')
	await client.connected()
	print('connected')
	log = ui.log(max_lines=500).classes('h-screen')
	log.push("Logging started ...")
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

def flash_module(device, log):
	print("{}: starting esptool (flash)".format(device))

	log.push("reading chip_id\n")

	chip_id_args = esptool_modes["chip_id"].format(device).split()

	chip_id_output = ""
	try:
		chip_id_output = subprocess.check_output(chip_id_args) 
		for line in chip_id_output.decode().split("\n"):
			log.push(line)
		log.push(" ")
	
	except subprocess.CalledProcessError as e:
		log.push("Error: {}".format(e.output.decode()))
		return
		
	mac_address = ""
	chip_type = ""

	for line in chip_id_output.decode().split("\n"):
		if "MAC" in line:
			mac_colon=line.split(' ')[1]
			mac_address = re.sub(r':', '', mac_colon)
		if "Chip is" in line:
			chip_type=line.split(' ')[2]
		if "Embedded PSRAM 2MB" in line:
			chip_type="esp32s3mini"
		if "Embedded PSRAM 8MB" in line:
			chip_type="esp32s3dev"
	
	if not chip_type or not mac_address:
		log.push("Error: could not determine chip_type or mac_address")
		return
	
	# chip_type: esp32s3mini, esp32s3dev, esp32, esps2mini
	#log.style("font-weight: bold;")
	log.push("chip_type: {}".format(chip_type) )
	log.push("mac_address: {}".format(mac_address))
	log.push(" ")

	log.push("{}: erasing flash\n".format(device) )
	log.push(" ")

	erase_args = esptool_modes["erase_flash"].format(device).split()

	try:
		erase_flash_output = subprocess.check_output(erase_args )
		#log.push(erase_args)
		for line in erase_flash_output.decode().split("\n"):
			if "Success" in line:
				log.push(line)
	
	except subprocess.CalledProcessError as e:
		log.push("Error: {}".format(e.output.decode()))
		return

	# esptool.py --port /dev/ttyACM2 --chip esp32s3 --baud 460800 write_flash 0 esp32s3/ESP32_GENERIC_S3-FLASH_4M-20250415-v1.25.0.bin

	log.push("writing flash\n".format(device))

	flash_file = "/home/doug/ha/flash/{}/latest.bin".format(chip_type)
	
	flash_args = esptool_modes[chip_type].format(device, flash_file).split()

	try:
		write_flash_output = b'simulate write_flash'
		write_flash_output = subprocess.check_output(flash_args )
		
		#log.push(flash_args )
		for line in write_flash_output.decode().split("\n"):
			if "Wrote" in line:
				log.push(line)
		#log.push(write_flash_output.decode())

	except subprocess.CalledProcessError as e:
		log.push("Error: {}".format(e.output.decode()))
		return

	log.push("flash complete\n".format(device))

	log.push("creating/copying files\n")

	with open("/home/doug/ams/{}".format(mac_address), mode="w") as f:
		f.write('{{ "run": "{}" }}\n'.format(mac_address) )

	files = """cd /home/doug/ams
cp {} /pyboard
cp boot.py /pyboard
cp esp*.py /pyboard
cp main.py /pyboard
cp hass.py /pyboard
cp msgqueue.py /pyboard
cp device.py /pyboard
cp webrepl_cfg.py /pyboard
cp core.py /pyboard
cp flag.py /pyboard
cp newsensor.py /pyboard
cp versions.py /pyboard
cp /home/doug/ams/hassdocker/mysecrets.py /pyboard
repl ~ import machine ~ machine.reset() ~
"""
	with open("file_copy_list", mode="w") as f:
		f.write('{}\n'.format(files.format(mac_address) ) )

	log.push(files.format(mac_address))

	log.push("starting rshell\n")

	rshell_args = "rshell -p /dev/{} -f file_copy_list".format(device).split()
	log.push(rshell_args)

	time.sleep(5)

	rshell_output = b'simulate rshell'
	try:
		rshell_output = subprocess.check_output(rshell_args )
		log.push(rshell_args)
		log.push(rshell_output.decode())
	
	except subprocess.CalledProcessError as e:
		log.push("Error: {}".format(e.output.decode()))
		return

	log.push("\n\ninit complete! \n")
	print('{}: init completed'.format(device))

@ui.page('/esptool/{device}')
async def tail_esptool(device, client: Client, action: str=""):
	print("{}: starting thread ({})".format(device, action))

	log = ui.log(max_lines=50).classes('h-screen').style('white-space: pre-wrap')

	esptool_thread = threading.Thread(
		target=flash_module, 
		args=(device, log) ) 

	esptool_thread.start()

	await client.disconnected()
	print('{}: esptool page closed'.format(device))


@ui.page('/console/{hostname}')
async def tail_console(hostname, client: Client, action: str=""):
	print("{}: starting console ({})".format(hostname, action))
	user_exit = threading.Event()
	ui.button("Close", on_click=lambda: user_exit.set() )
	netrepl = NetRepl(hostname, debug=False, verbose=False)
	console_thread = threading.Thread(
		target=netrepl.tail_console, 
		kwargs={'user_exit': user_exit, 
				'action': action} )
	
	console_thread.start()
	log = ui.log(max_lines=50).classes('h-screen')
	console = ReadFile(netrepl.weblog_path, log)
	ui.timer(1, console.readline)
	await client.disconnected()
	user_exit.set()
	print('{}: console page closed'.format(hostname))

@ui.page('/')
def page():

	ui.add_body_html('''
	<style>
	.ag-theme-balham {
		--ag-foreground-color: rgb(126, 46, 132);
		--ag-background-color: rgb(249, 245, 227);
		--ag-header-foreground-color: rgb(204, 245, 172);
		--ag-header-background-color: rgb(209, 64, 129);
		--ag-odd-row-background-color: rgb(0, 0, 0, 0.03);
		--ag-header-column-resize-handle-color: rgb(126, 46, 132);

		--ag-font-size: 20px;
		--ag-font-family: monospace;
	}
	</style>
	''')


	# Called every 3 seconds to check for changes to the table data
	@ui.refreshable
	def update_rows():
		last_table = row_data.copy()
		#print(last_table)
		row_data.clear()
		for node in mqtt_nodes:
			row_data.append( {"node": mqtt_nodes[node]['hostname'], "mac": mqtt_nodes[node]['mac'], "status": mqtt_nodes[node]['status'] } )
		#print(row_data)
		
		for device in pathlib.Path('/dev').glob('ttyACM*'):
			row_data.append( {"node": "/dev/" + device.name , "mac": "flash", "status": "" } )

		for device in pathlib.Path('/dev').glob('ttyUSB*'):
			row_data.append( {"node": "/dev/" + device.name , "mac": "flash", "status": "" } )

		if last_table != row_data:
			grid.update()

	async def reboot():
		row = await grid.get_selected_row()
		hostname = row['node']
		print("rebooting: ", hostname)
		ui.navigate.to("/console/{}?reboot=yes".format(hostname), new_tab=True)

	async def update():
		row = await grid.get_selected_row()
		hostname = row['node']
		print("updating: ", hostname)
		ui.navigate.to("/console/{}?update=yes".format(hostname), new_tab=True)

	async def console(button: ui.button):
		action = button.text
		rows = await grid.get_selected_rows()
		if not rows:
			return
		for row in rows:
			if action in "update|reboot|console":
				hostname = row['node']
				print("opening console for: ", hostname)
				ui.navigate.to("/console/{}?action={}".format(hostname, action), new_tab=True)
			if action == "flash":
				hostname = row['node'].split("/")[-1]
				print("flashing: ", hostname)
				ui.navigate.to("/esptool/{}?action={}".format(hostname, action), new_tab=True)

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
		ui.button('flash', on_click=lambda e: console(e.sender))

	ui.timer(3, update_rows)

	column_data = [
			{'headerName': 'Node', 'field': 'node', 'width': 50, 'checkboxSelection': True},
			{'headerName': 'Mac', 'field': 'mac', 'width': 50},
			{'headerName': 'Status', 'field': 'status', 'width': 80,
						'cellClassRules': {
            			'bg-red-300': 'x == "offline"',
            			'bg-blue-300': 'x == "shutdown"',
			            'bg-green-300': 'x == "online"'} },
		]
	
	grid = ui.aggrid( {'columnDefs': column_data,
		'auto_size_columns': False,
		'rowData': row_data,
		'rowSelection': 'multiple',
   		} ).classes('h-[1500px]' )

	ui.button('refresh', on_click=output_selected_row)

	def handle_cell_click(event):
		# Access event details like column and row data
		col = event.args['colId']
		row_index = event.args['rowIndex']
		row_data = grid.options['rowData'][row_index]
		
		ui.notify(f'Clicked column "{col}" in row {row_index} with data: {row_data}')

	grid.on('cellClicked', handle_cell_click)


ui.run()

files = []
import pathlib
a=pathlib.Path("/dev")
files = [f for f in a.glob("ttyA*") if f.is_file()]
