# ngmqttserver.py

import paho.mqtt.client as mqtt
from mysecrets import mqtt_user, mqtt_pass, mqtt_servers
import json
import time
mqtt_nodes = {}

class NGMQTTServer:
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

	def resubscribe_all(self):
		self.client.subscribe('hass/sensor/esp/+/state')
		self.client.subscribe('hass/sensor/esp/+/attrs')

	def add_update_node(self, topic, message):
		global mqtt_nodes

		if type(topic) != str:
			return

		try:
			device_id = "{}.{}".format(topic.split('/')[3], self.server)

			if not message:
				mqtt_nodes.pop(device_id, None)
				return

			if device_id not in mqtt_nodes:
				mqtt_nodes[device_id] = {}

			
			if "/attrs" in topic:

				message = json.loads(message)
				print("")
				print(topic, message)
				print(mqtt_nodes[device_id])

				# if "last_restart" not in mqtt_nodes[device_id] and "last_restart" in message:
				# 	print("{}: hostname: {}: mac: {} - new attributes added from server {}".format(self.server, message['hostname'], device_id, self.server))
				# 	if 'status' in mqtt_nodes[device_id]:
				# 		keep_status = mqtt_nodes[device_id]['status']
				# 	mqtt_nodes[device_id] = message
				# 	mqtt_nodes[device_id]['status'] = keep_status
				# 	return
				
				# if "last_restart" in message:
				# 	print("{}: hostname: {}: mac: {} - last_restart: {}".format(self.server, message['hostname'], device_id, message['last_restart']))
				# 	if message['last_restart'] > mqtt_nodes[device_id]['last_restart']:
				# 		print("{}: hostname: {}: mac: {} - old attributes replaced".format(self.server, message['hostname'], device_id))
				# 		if 'status' in mqtt_nodes[device_id]:
				# 			keep_status = mqtt_nodes[device_id]['status']
				# 		mqtt_nodes[device_id] = message
				# 		mqtt_nodes[device_id]['status'] = keep_status
				# 	return

				print("{}: hostname: {}: mac: {} - new attributes added from server {}".format(self.server, message['hostname'], device_id, self.server))
				mqtt_nodes[device_id].update(message)
				mqtt_nodes[device_id]['server'] = self.server
				if "last_restart" not in message:
					mqtt_nodes[device_id].pop("last_restart", None)
				
				
				# print("{}: Error: add_update_node - last_restart not in message".format(self.server) )

				# return

				# for k,v in message.items():
				# 	mqtt_nodes[device_id][k] = v

			if "/state" in topic:
				mqtt_nodes[device_id]['status'] = message
				print("{}: state for device: {} = {}".format(self.server, device_id, message))

		except:
			print("{}: error while processing topic: {}, message: {}".format(self.server, topic, message))

	def on_message(self, client, userdata, mqtt_message):
		#print(client.host, mqtt_message.topic)
		# device_id = "{}/{}".format(self.server, message.topic.split('/')[3] )
		topic = mqtt_message.topic
		server = client.host
		
		message = mqtt_message.payload.decode()
		self.add_update_node( topic, message)

# Initialize MQTT servers based on mysecrets
servers = {}
for server in mqtt_servers:
	servers[server] = NGMQTTServer(server)

def shutdown_node(host_key):
	mac_address = host_key.split('.')[1]
	server = host_key.split('.')[2]
	mqtt_client = servers[server].client

	print(f"shutting down: {host_key}")
	mqtt_client.publish( "hass/sensor/esp/{}/state".format(mac_address), "shutdown", retain=True)

	return

def remove_node(host_mac_server):
	host_name = host_mac_server.split('.')[0]
	mac_address = host_mac_server.split('.')[1]
	server = host_mac_server.split('.')[2]

	# for server in servers:
	mqtt_client = servers[server].client
	print("remove: server {} (node {})".format(server, mac_address))
	mqtt_client.publish( "hass/sensor/esp/{}/state".format(mac_address), "", retain=True)
	mqtt_client.publish( "hass/sensor/esp/{}/attrs".format(mac_address), "", retain=True)
	mqtt_client.publish( "hass/sensor/esp/{}/set".format(mac_address), "", retain=True)
	mqtt_client.publish( "homeassistant/sensor/esp/{}/config".format(mac_address), "", retain=True)
	mqtt_nodes.pop(mac_address, None)
	return

def resubscribe_all():
	for server in servers:
		servers[server].resubscribe_all()