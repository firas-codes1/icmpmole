from scapy.all import *
import joblib
import pandas as pd 
import time


model = joblib.load("ICMPflood_detector.pkl") #load ML model

machineIP="192.168.1.1" #can be anything even a list of trusted IPs

def Analyzer(pack,model,machineIP,start_time):
	if ICMP in pack:
		#proccess packet and filter IPs
		if pack[IP].src==machineIP:
			pack[IP].src=1

		else:
			pack[IP].src=0


		if pack[IP].dst==machineIP:
			pack[IP].dst=1
		else:
			pack[IP].dst=0



		pack={"Time":[time.time()-start_time],   #to make it similar to model data
		      "Source":[pack[IP].src],  
		      "Destination":[pack[IP].dst],  
		      "Protocol":[1], #protocol is ICMP! 
		      "Length":[len(pack)] #length of packet
		      }

		print(pack)


		df = pd.DataFrame(pack)


		try:
			prediction = model.predict(df.values)
		except:
			print("Error: model failed to analyze packet")
			pass

		if prediction==1:
			print("Malicious packet: ICMP flood")
		else:
			print("ICMP Packet safe")
			#print(pack)
			#print(df.values)

	else:
		pass


print("Waiting for packets...")
start_time = time.time()
sniff(filter="ip", store=False,
      prn=lambda pack:Analyzer(pack,model,machineIP,start_time))
