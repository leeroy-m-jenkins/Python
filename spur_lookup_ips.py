import json
import csv
import requests
import time
import sys

api_token = "u68d4602450934e_70fb7a7ad5f133fb21111c96a9ca01d34f2655142cd072d5ecd41c3e4e801d7d"
api_url = "https://api.spur.us/v2/context/"
selected_headers = ['IP','Country','State','Organization','Type','Operator','Anonymous','Infrastructure']

def clean_tunnel(t):
	anonymous = ""
	operator = ""
	typee = ""

	if "anonymous" in t:
		anonymous = t['anonymous']
	if "operator" in t:
		operator = t['operator']
	if "type" in t:
		typee = t['type']
	return [typee,operator,anonymous]

def clean_json(j):
	res = [j['ip'],j['location']['country']]
	infrastructure = ""
	state = ""

	if "state" in j['location']:
		state = j['location']['state']
	if "infrastructure" in j:
		infrastructure = j['infrastructure']

	res.append(state)
	res.append(j['as']['organization'])
	if "tunnels" not in j:
		res.extend(["","","",infrastructure])
		return 1,res
	else: 
		res_num = 1
		if len(j['tunnels']) > 1:
			res_res = []
			for t in j['tunnels']:
				temp = res
				temp.extend(clean_tunnel(t))
				temp.append(infrastructure)
				res_res.append(temp)
				res_num += 1
			return res_num,res_res
		else:
			res.extend(clean_tunnel(j['tunnels'][0]))
			res.append(infrastructure)
			return res_num,res

### change these ###
ip_file_path = 'D:\\Cases\\2022\\KISS\\okta_ips.csv'
raw_out_path = 'D:\\Cases\\2022\\KISS\\raw_out.csv'
parsed_out_path = 'D:\\Cases\\2022\\KISS\\ip_whois_parsed.csv'
### ############ ###

rp = open(raw_out_path,'w', newline='', encoding='utf-8')
pp = open(parsed_out_path,'w', newline='', encoding='utf-8')
fp = open(ip_file_path,'r')

csv_writer_raw = csv.writer(rp)
csv_writer_parsed = csv.writer(pp)

i = 0

print("[*] Reading input file")
ip_list = fp.readlines()
fp.close()

for ip in ip_list:
	try:
		request_url = api_url + ip.strip()
		print("[*] Looking up: " + ip.strip() + " (" + str(i + 1) + "/" + str(len(ip_list)) + ")")
		r = requests.get(request_url, headers={"Token":api_token})
		if r.status_code != 200:
			print("[-] Error with request! (" + str(r.status_code) + ")")
			continue
		if i == 0:
			header = r.json().keys()
			csv_writer_parsed.writerow(selected_headers)

		csv_writer_raw.writerow(r.json().values())
		j = r.json()
		results = clean_json(j)
		num_results = results[0]
		if num_results > 1:
			for k in range(1,num_results[0]):
				csv_writer_parsed.writerow(results[1][k - 1])
		else:
			csv_writer_parsed.writerow(results[1])
	except KeyboardInterrupt:
		sys.exit()
	except Exception as e:
		print("")
		print(e)
		print("Let Tyler know this error above")
		print("")
		time.sleep(1)
	i += 1
	if i % 10 == 0:
		time.sleep(1)
