# ngmqttserver.py

import paho.mqtt.client as mqtt
from mysecrets import mqtt_user, mqtt_pass
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
