# ngmqttserver.py

import paho.mqtt.client as mqtt
from mysecrets import mqtt_user, mqtt_pass, mqtt_servers
import json

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

	def add_update_node(self, topic, message):
		global mqtt_nodes

		if type(topic) != str:
			return

		try:
			device_id = "{}".format(topic.split('/')[3] )
			if device_id not in mqtt_nodes:
				mqtt_nodes[device_id] = {}

			if "/attrs" in topic:

				message = json.loads(message)

				for k,v in message.items():
					mqtt_nodes[device_id][k] = v

			if "/state" in topic:
				mqtt_nodes[device_id]['status'] = message

		except:
			print("error while processing topic: {}, message: {}".format(topic, message))

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

def shutdown_node(mac_address):
	for server in servers:
		mqtt_client = servers[server].client
		print("shutdown: server {} (node {})".format(server, mac_address))
		mqtt_client.publish( "hass/sensor/esp/{}/state".format(mac_address), "shutdown", retain=True)

	return

def remove_node(mac_address):
	for server in servers:
		mqtt_client = servers[server].client
		print("remove: server {} (node {})".format(server, mac_address))
		mqtt_client.publish( "hass/sensor/esp/{}/state".format(mac_address), "", retain=True)
		mqtt_client.publish( "hass/sensor/esp/{}/attrs".format(mac_address), "", retain=True)
		mqtt_client.publish( "hass/sensor/esp/{}/set".format(mac_address), "", retain=True)
		mqtt_client.publish( "homeassistant/sensor/esp/{}/config".format(mac_address), "", retain=True)

	return