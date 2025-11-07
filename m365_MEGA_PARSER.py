import json
import csv
import requests
import time
import sys
import os
import xlsxwriter

import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from pathlib import Path
from datetime import datetime

from azure.identity import InteractiveBrowserCredential
from azure.keyvault.secrets import SecretClient

client_id = "07b3a71e-64df-45e9-8da6-820fa906aa56"
tenant_id = "450137ba-4827-4538-ab9f-baed71730554"
vault_url = "https://kv-vulture-zlekr2lny2exy.vault.azure.net/"


api_token = ""

api_url = "https://api.spur.us/v2/context/"
selected_headers = ['IP','Country','State','Organization','Type','Operator','Anonymous','Infrastructure']
ual_headers = ['RecordType','CreationDate','UserIds','Operations','AuditData','ResultIndex','ResultCount','Identity','IsValid','ObjectState','SessionId','ApplicationId','ApplicationName','ObjectId','ClientIP','Country','State','ISP','Type','Operator','UserAgent']
		
towrite = []
fname = ""
uniq_ips = []

MAINWORKSHEETNAME = "UnifiedAuditLog"
UNIQIPWORKSHEETNAME = "Unique IPs"
WHOISWORKSHEETNAME = "whois"

def browseFiles():
	global fname
	fname = filedialog.askopenfilename(initialdir = "/", title = "Select a File", filetypes = (("all files","*.*"),("Comma Separated Variable", "*.csv")))
def confirm():
	answer = messagebox.askyesno("Overwrite file?","This output file exists.. Overwrite it?")
	return answer

def get_api_key():
	try:
		credential = InteractiveBrowserCredential(client_id=client_id,tenant_id=tenant_id)
		secret_client = SecretClient(vault_url=vault_url, credential=credential)
		return secret_client.get_secret("SPURAPIKEY")
	except:
		return "";

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
	try:
		res.append(j['as']['organization'])
	except:
		res.append("")
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

def browseFiles():
	global fname
	fname = filedialog.askopenfilename(initialdir = "/", title = "Select a File", filetypes = (("Comma Separated Variable", "*.csv"),("all files","*.*")))

def confirm():
	answer = messagebox.askyesno("Overwrite file?","This output file exists.. Overwrite it?")
	return answer

def tryappend_sessionid(jroot):
	if "AdditionalProperties" in jroot.keys():
		jroot = jroot["AdditionalProperties"]
	try:
		if "AADSessionId" in jroot.keys():
			return jroot["AADSessionId"]
		elif "DeviceProperties" in jroot.keys():
			for k in jroot["DeviceProperties"]:
				if k["Name"] == "SessionId":
					return k["Value"]
		elif "SessionId" in jroot.keys():
			return jroot["SessionId"]
		elif "UserSessionId" in jroot.keys():
			return jroot["UserSessionId"]
		elif "AppAccessContext" in jroot.keys():
			if "AADSessionId" in jroot["AppAccessContext"].keys():
				return jroot["AppAccessContext"]["AADSessionId"]
		else:
			return ""
	except Exception as e:
		print("Error with JSON")
		return ""
	return ""

def tryappend_clientip(p):
	if "AdditionalProperties" in p.keys():
		p = p["AdditionalProperties"]
	try:
		return p["ClientIP"]
	except:
		try:
			return p["ClientIPAddress"]
		except:
			return ""
		return ""
	return ""

def tryappend_applicationid(p):
	if "AdditionalProperties" in p.keys():
		p = p["AdditionalProperties"]
	try:
		return p["ApplicationId"]
	except:
		return ""
	return ""

def tryappend_objectid(p):
	if "AdditionalProperties" in p.keys():
		p = p["AdditionalProperties"]
	try:
		return p["ObjectId"]
	except:
		return ""
	return ""
def tryappend_useragent(p):
	if "UserAgent" in p.keys():
		return p["UserAgent"]
	if "AdditionalProperties" in p.keys():
		p = p["AdditionalProperties"]
	try:
		if "ExtendedProperties" in p.keys():
		    ep = p["ExtendedProperties"]
		    for n in ep:
		        if n["Name"] == "UserAgent":
		            return n["Value"]
	except:
	    return ""
	if "ClientInfoString" in p.keys():
		if ";" in p["ClientInfoString"]:
			return p["ClientInfoString"].split(';',1)[1]
	return ""

def build_application_kvpairs():
	return {
		"ff8d92dc-3d82-41d6-bcbd-b9174d163620": "PERFECTDATA SOFTWARE",
		"e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd": "eM Client",
		"62db40a4-2c7e-4373-a609-eda138798962": "Edison Mail",
		"a245e8c0-b53c-4b67-9b45-751d1dff8e6b": "Newsletter Software Supermailer",
		"4761b959-9780-4c2d-87a3-512b4638f767": "Rclone",
		"a43e5392-f48b-46a4-a0f1-098b5eeb4757": "CloudSponge",
		"858d7e42-35f0-44b7-9033-df309239a47f": "Zoominfo Login",
		"497ac034-5120-4c1a-929a-0351f5c09918": "ZoomInfo Communitiez Login",
		"caffae8c-0882-4c81-9a27-d1803af53a40": "SigParser",
		"77468577-4f6e-40e7-b745-11d3d0c28095": "Fastmail",
		"179d5108-412b-4c95-8e34-06786784ab39": "PostBox",
		"946c777c-bc85-489e-b034-392389ae23d6": "Spike",
		"8c59ead7-d703-4a27-9e55-c96a0054c8d2": "My Profile",
		"19db86c3-b2b9-44cc-b339-36da233a3be2": "My Signins",
		"7eadcef8-456d-4611-9480-4fff72b8b9e2": "Microsoft Account Controls V2",
		"ecd6b820-32c2-49b6-98a6-444530e5a77a": "Microsoft Edge",
		"f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34": "Microsoft Edge",
		"e9c51622-460d-4d3d-952d-966a5b1da34c": "Microsoft Edge",
		"5d661950-3475-41cd-a2c3-d671a3162bc1": "Microsoft Outlook",
		"e9b154d0-7658-433b-bb25-6b8e0a8a7c59": "Outlook Lite",
		"27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
		"b90d5b8f-5503-4153-b545-b31cecfaece2": "AADJ CSP",
		"dda27c27-f274-469f-8005-cce10f270009": "AADPasswordProtectionProxy",
		"90f610bf-206d-4950-b61d-37fa6fd1b224": "Aadrm Admin PowerShell",
		"a40d7d7d-59aa-447e-a655-679a4107e548": "Accounts Control UI",
		"23523755-3a2b-41ca-9315-f81f3f566a95": "ACOM Azure Website",
		"74658136-14ec-4630-ad9b-26e160ff0fc6": "ADIbizaUX",
		"69893ee3-dd10-4b1c-832d-4870354be3d8": "AEM-DualAuth",
		"92b61450-2139-4e4a-a0cc-898eced7a779": "Afdx Resource Provider",
		"be5f0473-6b57-40f8-b0a9-b3054b41b99e": "AI Builder Prod Non God Mode",
		"c6e44401-4d0a-4542-ab22-ecd4c90d28d7": "App Protection",
		"7ab7862c-4c57-491e-8a45-d52a7e023983": "App Service",
		"9449a792-6831-40e2-9097-29dbc6dd4753": "Arc Public Cloud – Networking",
		"aacceff9-8ec3-413c-83eb-cb131aaf55c6": "Arc Public Cloud – Servers",
		"d00b5d58-cae5-42ad-ae0a-5a2e6f7ee6c9": "Arc Token Service",
		"0cb7b9ec-5336-483b-bc31-b15b5788de71": "ASM Campaign Servicing",
		"2b8844d8-6c87-4fce-97a0-fbec9006e140": "AssistAPI",
		"e158eb19-34ac-4d1b-a930-ec92172f7a97": "Audit Search Api Service",
		"1b730954-1685-4b74-9bfd-dac224a7b894": "Azure Active Directory PowerShell",
		"7b7531ad-5926-4f2d-8a1d-38495ad33e17": "Azure Advanced Threat Protection",
		"bb55177b-a7d9-4939-a257-8ab53a3b2bc6": "Azure Arc Data Services",
		"a12e8ccb-0fcd-46f8-b6a1-b9df7a9d7231": "Azure Arc Data Services Billing",
		"2746ea77-4702-4b45-80ca-3c97e680e8b7": "Azure Data Explorer",
		"e9f49c6b-5ce5-44c8-925d-015017e9f7ad": "Azure Data Lake",
		"fd225045-a727-45dc-8caa-77c8eb1b9521": "Azure Diagnostics Resource Provider",
		"c8f5141d-83e0-4e9a-84d0-bb6677e26f64": "Azure Guest Container Update Manager",
		"835b2a73-6e10-4aa5-a979-21dfda45231c": "Azure Lab Services Portal",
		"c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
		"73c2949e-da2d-457a-9607-fcc665198967": "Azure Purview",
		"98785600-1bb7-4fb9-b9fa-19afe2c8a360": "Azure Security Insights",
		"022907d3-0f1b-48f7-badc-1ba6abab6d66": "Azure SQL Database",
		"37182072-3c9c-4f6a-a4b3-b3f91cacffce": "AzureSupportCenter",
		"8c420feb-03df-47cc-8a05-55df0cf3064b": "AzureUpdateCenter",
		"9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7": "Bing",
		"88c57617-94ff-4043-a396-8a85a8d38922": "Business Central to Common Data Service",
		"4c9fc70a-8d18-4528-9113-c6f1318c4d89": "CAP Package Deployer Service",
		"64a7b174-5779-4506-b54c-fbb0d80f1c9b": "CMAT",
		"f18b59c9-5926-4a65-8605-c23ec8c7e074": "console-m365d",
		"12ff570a-8284-47ed-adb3-fcc72b594c36": "Consumption Billing",
		"20a11fe0-faa8-4df5-baf2-f965f8f9972e": "ContactsInferencingEmailProcessor",
		"bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4": "CPIM Service",
		"e64aa8bc-8eb4-40e2-898b-cf261a25954f": "CRM Power BI Integration",
		"e3cf99e1-a6e5-4284-9f92-261c7713bc54": "Customer Experience Platform CDPA Provisioning PROD",
		"f5223e1a-4d50-4fda-9049-55d819fbb03e": "Customer Experience Platform CDPA Provisioning TIP",
		"944861d3-5975-4f8b-afd4-3422c0b1b6ce": "Customer Service Trial PVA",
		"6abc93dc-978e-48a3-8e54-458e593ed8cf": "Customer Service Trial PVA – readonly",
		"00000007-0000-0000-c000-000000000000": "Dataverse",
		"d6101214-691f-47d0-8ea3-dca752e62d71": "Dataverse Resource Provider",
		"3157152d-b5ae-4606-a145-6c660069bc5e": "Defender for IoT – Management",
		"de50c81f-5f80-4771-b66b-cebd28ccdfc1": "Device Management Client",
		"a8adde6c-aeb4-4fd6-9d8f-c2dfdecac60a": "Dynamics 365 collaboration with Microsoft Teams",
		"9e3b502c-b4a1-441d-98fd-28e482bf7e88": "Dynamics 365 Customer Insights – Consent",
		"b2b4502c-fedd-4748-8828-09e1eae11d6a": "Dynamics 365 Universal Resource Scheduling",
		"b7faa489-a4c8-4b39-bb0c-842c3de2de6a": "EASM API",
		"9a751391-6e9f-4199-ad8d-360712a1285c": "easmApiDev",
		"60c8bde5-3167-4f92-8fdb-059f6176dc0f": "Enterprise Roaming and Backup",
		"10214c11-ebd3-44e8-af2f-ebcb8a79c569": "EOP Admin API Web Service",
		"6201d19e-14fb-4472-a2d6-5634a5c97568": "Event Hub MSI App",
		"823c0a78-5de0-4445-a7f5-c2f42d7dc89b": "EventGrid Data API",
		"497effe9-df71-4043-a8bb-14cf78c4b63b": "Exchange Admin Center",
		"fe93bfe1-7947-460a-a5e0-7a5906b51360": "Exchange Online",
		"a3883eba-fbe9-48bd-9ed3-dca3e0e84250": "Exchange Online",
		"aa813f0e-407a-459d-93af-805f2bf10f33": "Exchange Online",
		"d396de1f-10d4-4023-aae2-5bb3d724ba9a": "Exchange Online",
		"82d8ab62-be52-a567-14ea-1616c4ee06c4": "Exchange Online",
		"34421fbe-f100-4e5b-9c46-2fea25aa7b88": "Exchange Online",
		"1150aefc-07de-4228-b2b2-042a536703c0": "Exchange Online",
		"f5eaa862-7f08-448c-9c4e-f4047d4d4521": "FindTime",
		"9758a0e2-7861-440f-b467-1823144e5b65": "FindTime",
		"b669c6ea-1adf-453f-b8bc-6d526592b419": "Focused Inbox",
		"b24835c0-6b13-41e7-822c-94c9effb98ee": "FrontendTransport",
		"707aa1ac-be0a-478d-9ce7-0d2765a5c1d6": "Funnel and Engagement Data Service",
		"5a8800f2-f31d-4654-9bed-f5b368c703f8": "Gatekeeper PPE App",
		"5bab4c7f-51c3-479b-a199-06b31afecc8f": "Gatekeeper Prod App",
		"75cba773-c367-4ba4-8d4f-65f91b68c384": "Grade Sync",
		"1690c5aa-925a-4d0e-836b-722c795bd0d0": "Group Configuration Processor",
		"c35cb2ba-f88b-4d15-aa9d-37bd443522e1": "GroupsRemoteApiRestClient",
		"d9b8ec3a-1e4e-4e08-b3c2-5baf00c0fcb0": "HxService",
		"e18cedde-9458-482f-9dd1-558c597ac42e": "Hybrid Connectivity RP",
		"d2a590e7-6906-4a45-8f41-cecfdca9bca1": "Hybrid RP Application",
		"a57aca87-cbc0-4f3c-8b9e-dc095fdc8978": "IAM Supportability",
		"f6e5c0c2-4746-4152-b162-91309d5556df": "IC3 Modern Effective Config",
		"481115cb-6d15-4cc0-8caf-f2fee7bfbd2b": "IC3 Modern Effective Config Worker",
		"4c1a3aed-b389-4824-99b0-514c07906851": "Intune DeviceCheckIn ConfidentialClient",
		"7e9f2fca-0cd8-4a6c-a1a0-7ffe48aec7c6": "Intune Remote Help",
		"189cf920-d3d8-4133-9145-23adcc6824fa": "IpLicensingService",
		"61c28d8b-814f-4a57-9c7f-8cd0580aead2": "Iris Provider EOP Web Service",
		"16aeb910-ce68-41d1-9ac3-9e1673ac9575": "IrisSelectionFrontDoor",
		"319f651f-7ddb-4fc6-9857-7aef9250bd05": "K8 Bridge",
		"cedebc57-38a2-4f0a-8472-dfcbba5b04c6": "M365 Compliance Drive",
		"be1918be-3fe3-4be9-b32b-b542fc27f02e": "M365 Compliance Drive Client",
		"4eaa7769-3cf1-458c-a693-e9827e39cc95": "M365 Lighthouse API",
		"d9d5c99e-b0b4-4bad-92cc-5a6eb5421985": "M365 Lighthouse Service",
		"a8f7a65c-f5ba-4859-b2d6-df772c264e9d": "make.powerapps.com",
		"66c6d0d1-f2e7-4a18-97a9-ed10f3347016": "Managed Service",
		"cc46c2aa-d508-409b-aeb7-df7cd1e07aaa": "MAPG",
		"f738ef14-47dc-4564-b53b-45069484ccc7": "Marketplace Api",
		"5b712e99-51a3-41ce-86ff-046e0081c5c0": "Marketplace SaaS v2",
		"20e940b3-4c77-4b0b-9a53-9e16a1b010a7": "MarketplaceAPI ISV",
		"d73f4b35-55c9-48c7-8b10-651f6f2acb2e": "MCAPI Authorization Prod",
		"bb3d68c2-d09e-4455-94a0-e323996dbaa3": "Medeina Service",
		"826870f9-9fbb-4f23-81b8-3a957080dfa2": "Medeina Service Dev",
		"c4de86e3-e322-4889-a781-968c76b6b325": "Medeina Service PPE",
		"944f0bd1-117b-4b1c-af26-804ed95e767e": "Media Analysis and Transformation Service",
		"0cd196ee-71bf-4fd6-a57c-b491ffd4fb1e": "Media Analysis and Transformation Service",
		"f448d7e5-e313-4f90-a3eb-5dbb3277e4b3": "Media Recording for Dynamics 365 Sales",
		"82f45fb0-18b4-4d68-8bed-9e44909e3890": "Meeting Migration Service",
		"f7a2a81e-ab33-4560-a3dd-6ddca3c5ec6d": "Membership View Service",
		"62916641-fc48-44ae-a2a3-163811f1c945": "Message Header Analyzer",
		"0e90d0b8-039a-4936-a6f4-d25dd510be5d": "Message Recall",
		"c9475445-9789-4fef-9ec5-cde4a9bcd446": "Messaging Bot API Application for GCC",
		"9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Microsfot Intune Company Portal",
		"80ccca67-54bd-44ab-8625-4b79c4dc7775": "Microsoft 365 Security and Compliance Center",
		"ee272b19-4411-433f-8f28-5c13cb6fd407": "Microsoft 365 Support Service",
		"510a5356-1745-4855-93a5-113ea589fb26": "Microsoft 365 Ticketing",
		"d32c68ad-72d2-4acb-a0c7-46bb2cf93873": "Microsoft Activity Feed Service",
		"91ad134d-5284-4adc-a896-d7fd24e9fa15": "Microsoft Alchemy Service",
		"0000000c-0000-0000-c000-000000000000": "Microsoft App Access Panel",
		"6f7e0f60-9401-4f5b-98e2-cf15bd5fd5e3": "Microsoft Application Command Service",
		"65d91a3d-ab74-42e6-8a2f-0add61688c74": "Microsoft Approval Management",
		"38049638-cc2c-4cde-abe4-4479d721ed44": "Microsoft Approval Management",
		"29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
		"4813382a-8fa7-425e-ab75-3b753aab3abb": "Microsoft Authenticator App",
		"cb1056e2-e479-49de-ae31-7812af012ed8": "Microsoft Azure Active Directory Connect",
		"de926fbf-e23b-41f9-ae15-c943a9cfa630": "Microsoft Azure Authorization Private Link Provider",
		"1dcb1bc7-c721-498e-b2fa-bcddcea44171": "Microsoft Azure Authorization Resource Provider",
		"04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
		"1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
		"1786c5ed-9644-47b2-8aa0-7201292175b6": "Microsoft Bing Default Search Engine",
		"cf36b471-5b44-428c-9ce7-313bf84528de": "Microsoft Bing Search",
		"2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8": "Microsoft Bing Search for Microsoft Edge",
		"19686ca6-5324-4571-a231-77e026b0e06f": "Microsoft Command Service",
		"a81d90ac-aa75-4cf8-b14c-58bf348528fe": "Microsoft Community v2",
		"3090ab82-f1c1-4cdf-af2c-5d7a6f3e2cc7": "Microsoft Defender for Cloud Apps",
		"8a0c2593-9cbc-4f86-a247-beb7aab00d83": "Microsoft Defender for Cloud Apps – Session Controls",
		"60ca1954-583c-4d1f-86de-39d835f3e452": "Microsoft Defender for Identity (formerly Radius Aad Syncer)",
		"18fbca16-2224-45f6-85b0-f7bf2b39b3f3": "Microsoft Docs",
		"d6037e40-282c-493d-8f63-f255e36c6ef4": "Microsoft Dynamics 365 Supply Chain Visibility",
		"00000015-0000-0000-c000-000000000000": "Microsoft Dynamics ERP",
		"703e2651-d3fc-48f5-942c-74274233dba8": "Microsoft Dynamics ERP Microservices CDS",
		"d7b530a4-7680-4c23-a8bf-c52c121d2e87": "Microsoft Edge Enterprise New Tab Page",
		"6253bca8-faf2-4587-8f2f-b056d80998a7": "Microsoft Edge Insider Addons Prod",
		"6bf85cfa-ac8a-4be5-b5de-425a0d0dc016": "Microsoft Entra AD Synchronization Service",
		"99b904fd-a1fe-455c-b86c-2f9fb1da7687": "Microsoft Exchange ForwardSync",
		"00000007-0000-0ff1-ce00-000000000000": "Microsoft Exchange Online Protection",
		"a0c73c16-a7e3-4564-9a95-2bdf47383716": "Microsoft Exchange Online Remote PowerShell",
		"51be292c-a17e-4f17-9a7e-4b661fb16dd2": "Microsoft Exchange ProtectedServiceHost",
		"fb78d390-0c51-40cd-8e17-fdbfab77341b": "Microsoft Exchange REST API Based Powershell",
		"47629505-c2b6-4a80-adb1-9b3a3d233b7b": "Microsoft Exchange Web Services",
		"57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0": "Microsoft Flow Mobile PROD-GCCH-CN",
		"c9a559d2-7aab-4f13-a6ed-e7e9c52aec87": "Microsoft Forms",
		"00000003-0000-0000-c000-000000000000": "Microsoft Graph",
		"9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Microsoft Intune Company Portal",
		"74bcdadc-2fdc-4bb3-8459-76d06952a0e9": "Microsoft Intune Web Company Portal",
		"fc0f3af4-6835-4174-b806-f7db311fd2f3": "Microsoft Intune Windows Agent",
		"d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
		"00000006-0000-0ff1-ce00-000000000000": "Microsoft Office 365 Portal",
		"67e3df25-268a-4324-a550-0de1c7f97287": "Microsoft Office Web Apps Service",
		"d176f6e7-38e5-40c9-8a78-3998aab820e7": "Microsoft Online Syndication Partner Portal",
		"93625bc8-bfe2-437a-97e0-3d0060024faa": "Microsoft password reset service",
		"66375f6b-983f-4c2c-9701-d680650f588f": "Microsoft Planner",
		"871c010f-5e61-4fb1-83ac-98610a7e9110": "Microsoft Power BI",
		"c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12": "Microsoft Power BI",
		"a672d62c-fc7b-4e81-a576-e60dc46e951d": "Microsoft Power Query for Excel",
		"fd642066-7bfc-4b65-9463-6a08841c12f0": "Microsoft Purview Platform",
		"9bc3ab49-b65d-410a-85ad-de819febfddc": "Microsoft SharePoint Online Management Shell",
		"28b567f6-162c-4f54-99a0-6887f387bbcc": "Microsoft Storefronts",
		"844cca35-0656-46ce-b636-13f48b0eecbd": "Microsoft Stream Mobile Native",
		"cf53fce8-def6-4aeb-8d30-b158e7b1cf83": "Microsoft Stream Portal",
		"98db8bd6-0cc0-4e67-9de5-f187f1cd1b41": "Microsoft Substrate Management",
		"fdf9885b-dd37-42bf-82e5-c3129ef5a302": "Microsoft Support",
		"5b534afd-fdc0-4b38-a77f-af25442e3149": "Microsoft Support Diagnostics",
		"1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
		"87749df4-7ccf-48f8-aa87-704bad0e0e16": "Microsoft Teams – Device Admin Agent",
		"78462efa-e271-409c-a90b-ce3fbd93538a": "Microsoft Teams Admin Gateway Service",
		"2ddfbe71-ed12-4123-b99b-d5fc8a062a79": "Microsoft Teams Admin Portal Service",
		"8e55a7b1-6766-4f0a-8610-ecacfe3d569a": "Microsoft Teams Copilot Bot",
		"1303f293-64bd-48ba-89b0-6bf538bc67f3": "Microsoft Teams IP Policy Service",
		"cc15fd57-2c6c-4117-a88c-83b1d56b4bbe": "Microsoft Teams Services",
		"5e3ce6c0-2b1f-4285-8d4b-75ee78787346": "Microsoft Teams Web Client",
		"22098786-6e16-43cc-a27d-191a01a1e3b5": "Microsoft To-Do client",
		"eb539595-3fe1-474e-9c1d-feb3625d1be5": "Microsoft Tunnel",
		"57336123-6e14-4acc-8dcf-287b6088aa28": "Microsoft Whiteboard Client",
		"95de633a-083e-42f5-b444-a4295d8e9314": "Microsoft Whiteboard Services",
		"ea2f600a-4980-45b7-89bf-d34da487bda1": "Microsoft.Azure.DomainRegistration",
		"ac9dc5fe-b644-4832-9d03-d9f1ab70c5f7": "Microsoft.ConnectedVMwarevSphere Resource Provider",
		"4962773b-9cdb-44cf-a8bf-237846a00ab7": "Microsoft.EventGrid",
		"80369ed6-5f11-4dd9-bef3-692475845e77": "Microsoft.EventHubs",
		"eec53b1f-b9a4-4479-acf5-6b247c6a49f2": "Microsoft.HybridCompute Agent Service",
		"0000001a-0000-0000-c000-000000000000": "MicrosoftAzureActiveAuthn",
		"aaf3f152-fe17-487b-b671-44d3f7bad293": "Mimir",
		"8adc51cc-7477-49a4-be4e-263946b4d561": "MIP Exchange Solutions – ODB",
		"192644fe-6aac-4786-8d93-775a056aa1de": "MIP Exchange Solutions – SPO",
		"2c220739-d44d-4bf7-ba5f-95cf9fb7f10c": "MIP Exchange Solutions – Teams",
		"e8e8fc40-94d5-4ed6-89f2-9e5ec6c1e11e": "MM_Reactions_PME_PROD",
		"75861f5e-a448-49d7-9c99-6b59bc88c6dc": "Modern Support Connector",
		"c9d36ed4-91b3-4c87-b8d7-68d92826c96c": "Modern Workplace Customer APIs",
		"2f5afa01-cdcb-4707-a62a-0803cc994c60": "MS-CE-CXG-MAC-AadShadowRoleWriter",
		"6682cfa5-2710-44c9-adb8-5ac9d76e394a": "MTS",
		"dfe74da8-9279-44ec-8fb2-2aed9e1c73d0": "O365 SkypeSpaces Ingestion Service",
		"4345a7b9-9a63-4910-a426-35363201d503": "O365 Suite UX",
		"72782ba9-4490-4f03-8d82-562370ea3566": "Office 365",
		"c94526fa-9f4b-4d30-99f5-849636e4552f": "Office 365 Client Insights Substrate Services Prod",
		"00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
		"00b41c95-dab0-4487-9791-b9d2c32c80f2": "Office 365 Management",
		"66a88757-258c-4c72-893c-3e8bed4d6899": "Office 365 Search Service",
		"00000003-0000-0ff1-ce00-000000000000": "Office 365 SharePoint Online",
		"94c63fef-13a3-47bc-8074-75af8c65887a": "Office Delve",
		"93d53678-613d-4013-afc1-62e9e444a0a5": "Office Online Add-in SSO",
		"2abdc806-e091-4495-9b10-b04d93c3f040": "Office Online Augmentation Loop SSO",
		"2abdc806-e091-4495-9b10-b04d93c3f040": "Office Online Client Microsoft Entra ID- Augmentation Loop",
		"b23dd4db-9142-4734-867f-3577f640ad0c": "Office Online Client Microsoft Entra ID- Loki",
		"17d5e35f-655b-4fb0-8ae6-86356e9a49f5": "Office Online Client Microsoft Entra ID- Maker",
		"b6e69c34-5f1f-4c34-8cdf-7fea120b8670": "Office Online Client MSA- Loki",
		"243c63a3-247d-41c5-9d83-7788c43f1c43": "Office Online Core SSO",
		"b23dd4db-9142-4734-867f-3577f640ad0c": "Office Online Loki SSO",
		"17d5e35f-655b-4fb0-8ae6-86356e9a49f5": "Office Online Maker SSO",
		"d7d7af51-cdcd-4a4c-9467-86e7dc5d2b90": "Office Online OWLNest",
		"3ce44149-e365-40e4-9bb4-8c0ecb710fe6": "Office Online Print SSO",
		"a9b49b65-0a12-430b-9540-c80b3332c127": "Office Online Search",
		"5a4eed13-c4c4-4b4c-9506-334ab200bf31": "Office Online Search SSO",
		"0ec893e0-5785-4de6-99da-4ed124e5296c": "Office UWP PWA",
		"4b233688-031c-404b-9a80-a4f3f2351f90": "Office.com",
		"89bee1f7-5e6e-4d8a-9f3d-ecd601259da7": "Office365 Shell WCSS-Client",
		"5f09333a-842c-47da-a157-57da27fcbca5": "Office365 Shell WCSS-Server",
		"0f698dd4-f011-4d23-a33e-b36416dcb1e6": "OfficeClientService",
		"4765445b-32c6-49b0-83e6-1d93765276ca": "OfficeHome",
		"4d5c2d63-cf83-4365-853c-925fd1a64357": "OfficeShredderWacClient",
		"bb893c22-978d-4cd4-a6f7-bb6cc0d6e6ce": "Olympus",
		"62256cef-54c0-4cb4-bcac-4c67989bdc40": "OMSOctopiPROD",
		"9199bf20-a13f-4107-85dc-02114787ef48": "One Outlook Web",
		"b26aadf8-566f-4478-926f-589f601d9c74": "OneDrive",
		"af124e86-4e96-495a-b70a-90f90ab96707": "OneDrive iOS App",
		"ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive Sync Engine",
		"ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive SyncEngine",
		"4f547b5f-c3f7-4d2c-a14f-0f8f1286d7d5": "OneDriveLTI",
		"d3ee6f25-becc-4659-9bc6-bbe6af7d18e6": "OneLTI",
		"2d4d3d8e-2be3-4bef-9f87-7875a61c29de": "OneNote",
		"87223343-80b1-4097-be13-2332ffa1d666": "Outlook Web App Widgets",
		"b39d63e7-7fa3-4b2b-94ea-ee256fdb8c2f": "Partner Customer Delegated Admin Migration",
		"a3475900-ccec-4a69-98f5-a65cd5dc5306": "Partner Customer Delegated Admin Offline Processor",
		"2832473f-ec63-45fb-976f-5d45a7d4bb91": "Partner Customer Delegated Administration",
		"34cabb34-90ae-4aca-b8c3-c457dbedf145": "PartnerCenterCustomerServiceAppProd",
		"bdd48c81-3a58-4ea9-849c-ebea7f6b6360": "Password Breach Authenticator",
		"35d54a08-36c9-4847-9018-93934c62740c": "PeoplePredictions",
		"1b489150-9b00-413a-83fd-6ef8f05b6e28": "Policy Processor",
		"7f67af8a-fedc-4b08-8b4e-37c4d127b6cf": "Power BI Desktop",
		"00000009-0000-0000-c000-000000000000": "Power BI Service",
		"065d9450-1e87-434e-ac2f-69af271549ed": "Power Platform Admin Center",
		"2b5e68f0-bdc2-45b0-920a-217d5cbbd505": "Power Platform Governance Services – TIRPS",
		"6b650392-d446-472e-a422-e47047790237": "Power Platform Insights and Recommendations Prod",
		"9d8f559b-5984-46a4-902a-ad4271e83efa": "Power Virtual Agents Service",
		"4e291c71-d680-4d0e-9640-0a3358e31177": "PowerApps",
		"3e62f81e-590b-425b-9531-cad6683656cf": "PowerApps – apps.powerapps.com",
		"c09dc6d6-3bff-482b-8e40-68b3ad65f3fa": "ProductsLifecycleApp",
		"9f6c88b7-0272-4581-a75a-ec0340824ed1": "PTSS",
		"9ec59623-ce40-4dc8-a635-ed0275b5d58a": "Purview Ecosystem",
		"22d27567-b3f0-4dc2-9ec2-46ed368ba538": "Reading Assignments",
		"6046742c-3aee-485e-a4ac-92ab7199db2e": "Report Message",
		"ae8e128e-080f-4086-b0e3-4c19301ada69": "Scheduling",
		"38df11dd-582e-4207-be6f-b214675f44a1": "SEAL All credentials",
		"c10f411a-874c-485c-9d66-6e0b34202c41": "SEAL SNI",
		"ffcb16e8-f789-467c-8ce9-f826a080d987": "SharedWithMe",
		"d326c1ce-6cc6-4de2-bebc-4591e5e13ef0": "SharePoint",
		"f05ff7c9-f75a-4acd-a3b5-f4b6a870245d": "SharePoint Android",
		"c58637bb-e2e1-4312-8a00-04b5ffcd3403": "SharePoint Online Client Extensibility",
		"08e18876-6177-487e-b8b5-cf950c1e598c": "SharePoint Online Web Client Extensibility",
		"b4bddae8-ab25-483e-8670-df09b9f1d0ea": "Signup",
		"66c23536-2118-49d3-bc66-54730b057680": "Skype Core Calling Service",
		"ef4c7f67-65bd-4506-8179-5ddcc5509aeb": "Skype For Business Entitlement",
		"00000004-0000-0ff1-ce00-000000000000": "Skype for Business Online",
		"61109738-7d2b-4a0b-9fe3-660b1ff83505": "SpoolsProvisioning",
		"163b648b-025e-455b-9937-a7f39a65d171": "SSO Extension Intune",
		"91ca2ca5-3b3e-41dd-ab65-809fa3dffffa": "Sticky Notes API",
		"13937bba-652e-4c46-b222-3003f4d1ff97": "Substrate Context Service",
		"a970bac6-63fe-4ec5-8884-8536862c42d4": "Substrate Search Settings Management Service",
		"26abc9a8-24f0-4b11-8234-e86ede698878": "SubstrateDirectoryEventProcessor",
		"905fcf26-4eb7-48a0-9ff0-8dcc7194b5ba": "Sway",
		"6bc3b958-689b-49f5-9006-36d165f30e00": "Teams CMD Services Artifacts",
		"0ef94e72-e4fc-4aa0-a8f4-ff27deb3e6eb": "Teams NRT DLP Ingestion Service",
		"7a274595-3618-4e6f-b54e-05bb353e0153": "Teams NRT DLP Service",
		"4cba1704-a0c1-45ee-9d41-fe75b4ef9190": "TeamsChatServiceApp",
		"31ba6d5c-2e14-40fb-bbcb-27dc8a1bfaf5": "TeamsLinkedInLiveApp",
		"3cf798a6-b0c5-4d5c-9645-b5273d471fc5": "teamsupgradeorchestrator-app",
		"97cb1f73-50df-47d1-8fb0-0271f2728514": "Transcript Ingestion",
		"2b61b865-d0bd-4c60-9efa-6fa934eefaac": "TrustedPublishersProxyService",
		"da9b70f6-5323-4ce6-ae5c-88dcc5082966": "Universal Print",
		"80331ee5-4436-4815-883e-93bc833a9a15": "Universal Print Connector",
		"417ae6eb-aac8-42c8-900c-0e50debba688": "Universal Print Enabled Printer",
		"dae89220-69ba-4957-a77a-47b78695e883": "Universal Print Native Client",
		"aad98258-6bb0-44ed-a095-21506dfb68fe": "Universal Print PS Module",
		"bf7b96b3-68e4-4fd9-b697-637f0f1e778c": "Universal Store Entitlements Service",
		"268761a2-03f3-40df-8a8b-c3db24145b6b": "Universal Store Native Client",
		"8338dec2-e1b3-48f7-8438-20c30a534458": "ViewPoint",
		"1762e607-063e-431a-a25a-f0f782acb73b": "Virtual Connector Provider",
		"2b479c68-8d9b-4e27-9d85-5d74803de734": "Virtual Visits App",
		"872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio – Legacy",
		"00000005-0000-0ff1-ce00-000000000000": "Viva Engage (formerly Yammer)",
		"3c896ded-22c5-450f-91f6-3d1ef0848f6e": "WeveEngine",
		"0af06dc6-e4b5-4f28-818e-e78e62d137a5": "Windows 365",
		"00000002-0000-0000-c000-000000000000": "Windows Azure Active Directory",
		"8edd93e1-2103-40b4-bd70-6e34e586362d": "Windows Azure Security Resource Provider",
		"797f4846-ba00-4fd7-ba43-dac1f8f63013": "Windows Azure Service Management API",
		"04436913-cf0d-4d2a-9cc6-2ffe7f1d3d1c": "Windows Notification Service",
		"26a7ee05-5602-4d76-a7ba-eae8b7b67941": "Windows Search",
		"38aa3b87-a06d-4817-b275-7a316988d93b": "Windows Sign In",
		"1b3c667f-cde3-4090-b60b-3d2abd0117f0": "Windows Spotlight",
		"45a330b1-b1ec-4cc1-9161-9f03992aa49f": "Windows Store for Business",
		"d5097d05-956f-4ae2-b6a2-eff25f5689b3": "Windows Update for Business Cloud Extensions PowerShell",
		"61ae9cd9-7bca-458c-affc-861e2f24ba3b": "Windows Update for Business Deployment Service",
		"a3b79187-70b2-4139-83f9-6016c58cd27b": "WindowsDefenderATP Portal",
		"a569458c-7f2b-45cb-bab9-b7dee514d112": "Yammer iPhone",
		"c1c74fed-04c9-4704-80dc-9f79a2e515cb": "Yammer Web",
		"e1ef36fd-b883-4dbf-97f0-9ece4b576fc6": "Yammer Web Embed",
		"7dd7250c-c317-4bc6-8528-8d27b02707ef": "ZTNA Data Acquisition – PROD",
		"3b80cd3f-61ca-49b0-8d0f-7b6760e08705": "ZTNA Policy Service Graph Client"
	}

def spur_uniq_ips(ip_list, spur_worksheet):
	i = 0
	global api_token
	for ip in ip_list:
		try:
			request_url = api_url + ip.strip()
			if len(ip.strip()) == 0:
				continue
			print("[*] Looking up: " + ip.strip() + " (" + str(i + 1) + "/" + str(len(ip_list)) + ")")
			r = requests.get(request_url, headers={"Token":api_token})
			if r.status_code != 200:
				print("[-] Error with request! (" + str(r.status_code) + ")")
				#csv_writer_error.writerow([ip.strip()])
				continue
			if i == 0:
				j = 0
				for header in selected_headers:
					spur_worksheet.write(0,j,header)
					j = j + 1					
			j = r.json()
			results = clean_json(j)
			num_results = results[0]
			if num_results > 1:
				results = results[1][1]
			for k in range(0,len(selected_headers) - 1):
				spur_worksheet.write(i+1,k,results[1][k])
		except KeyboardInterrupt:
			sys.exit()
		except Exception as e:
			print("")
			print(e)
			print("Let Tyler know this error above")
			#csv_writer_error.writerow([ip.strip()])
			print("")
			time.sleep(1)
		i += 1
		if i % 200 == 0:
			time.sleep(1)

def determine_if_write_formula(k):
	global ual_headers
	return ual_headers[k] == "Country" or ual_headers[k] == "State" or ual_headers[k] == "ISP" or ual_headers[k] == "Type" or ual_headers[k] == "Operator"

def parse_o365_csv(fname, ual_worksheet, uniq_ip_worksheet):
	global uniq_ips
	global towrite
	global application_lookup
	global datetimeformat
	with open(fname,"r",encoding="utf8") as csvfile:
		csvreader = csv.reader(csvfile)
		i = 0
		auditdata_row = -1
		operation_row = -1	
		clientip_row =  'O'
		for row in csvreader:
			try:
				i = i + 1
				wrow = row
				if i == 1:
					j = 0
					for r in row:
						if "AuditData" in r:
							auditdata_row = j
						if "Operation" in r:
							operation_row = j
						j = j + 1
					wrow.append("SessionId")
					wrow.append("ApplicationId")
					wrow.append("ApplicationName")
					wrow.append("ObjectId")
					wrow.append("ClientIP")
					wrow.append("Country") # 2
					wrow.append("State")   # 3 
					wrow.append("ISP")     # 4
					wrow.append("Type")    # 5
					wrow.append("Operator")# 6
					wrow.append("UserAgent")
					towrite.append(wrow)
					continue
				p = json.loads(row[auditdata_row])
				sessionid = tryappend_sessionid(p)
				appid = tryappend_applicationid(p)
				appname = ""
				objectid = tryappend_objectid(p)
				ip = tryappend_clientip(p)				

				if row[operation_row] == "UserLoggedIn":
					appid = tryappend_applicationid(p)
					if len(appid) > 0 and appid in application_lookup:
						appname = application_lookup[appid]

				wrow.append(tryappend_sessionid(p)) 												# SessionId
				wrow.append(appid)																	# ApplicationId
				wrow.append(appname)																# ApplicationName
				wrow.append(objectid)												    			# ObjectId
				wrow.append(ip)																		# ClientIP
				wrow.append(f'=VLOOKUP({clientip_row}{i},{WHOISWORKSHEETNAME}!$A$2:$H$1000,2,0)')	# Country
				wrow.append(f'=VLOOKUP({clientip_row}{i},{WHOISWORKSHEETNAME}!$A$2:$H$1000,3,0)')	# State
				wrow.append(f'=VLOOKUP({clientip_row}{i},{WHOISWORKSHEETNAME}!$A$2:$H$1000,4,0)')	# ISP
				wrow.append(f'=VLOOKUP({clientip_row}{i},{WHOISWORKSHEETNAME}!$A$2:$H$1000,5,0)')	# Type
				wrow.append(f'=VLOOKUP({clientip_row}{i},{WHOISWORKSHEETNAME}!$A$2:$H$1000,6,0)')	# Operator
				wrow.append(tryappend_useragent(p))													# UserAgent
		            
				towrite.append(wrow)
				if len(ip.strip()) > 0 and ip.strip() not in uniq_ips:
					uniq_ips.append(ip.strip())
			except Exception as e:
				print(str(e) + " on line: " + str(i))
	print("Successfully parsed " + str(i) + " rows")
	#write shiz
	i = 0
	for ip in uniq_ips:
		uniq_ip_worksheet.write(i,0,ip)
	num_ual_headers = len(towrite[0])
	j = 0
	for row in towrite:
		for k in range(0, num_ual_headers):
			if k == 1 and j > 0:
				dt = datetime.strptime(row[k],"%m/%d/%Y %I:%M:%S %p")
				ual_worksheet.write_datetime(j,k,dt,datetimeformat)
			elif k >= 15 and k <= 19 and j > 0:
				ual_worksheet.write_formula(j,k,row[k])
			else:
				ual_worksheet.write(j,k,row[k])
		j = j + 1
	ual_worksheet.freeze_panes(1,0)
	ual_worksheet.autofilter(0,0,j - 1, num_ual_headers - 1)



application_lookup = build_application_kvpairs()
time.sleep(1)
browseFiles()
pathobj = Path(fname)

if len(fname.strip()) == 0:
	print("No file chosen... exiting")
	exit()
print("Chosen file: " + fname)
outfilename = os.path.splitext(os.path.basename(fname))[0] + "_parsed.xlsx"
outfile = os.path.join(pathobj.parent,outfilename)
outfileobj = Path(outfile)
if outfileobj.exists():
	root = tk.Tk()
	root.withdraw()
	answer = confirm()
	if not answer:
		print("Not overwritting... exiting")
		exit()
	try:
		os.remove(outfile)
	except Exception as ee:
		print("An error occurred when clearing output file:",ee)
api_token_attempt = get_api_key()
if len(api_token_attempt.value.strip()) == 0:
	print("Failed to get a valid SPUR API KEY...exiting")
	exit()
api_token = api_token_attempt.value
xlxsoutfile = xlsxwriter.Workbook(outfile,{'constant_memory': True})
datetimeformat = xlxsoutfile.add_format({'num_format': 'mm/dd/yyyy hh:mm:ss'})

ual_record_worksheet = xlxsoutfile.add_worksheet(MAINWORKSHEETNAME)
uniq_ip_worksheet = xlxsoutfile.add_worksheet(UNIQIPWORKSHEETNAME)
spur_worksheet = xlxsoutfile.add_worksheet(WHOISWORKSHEETNAME)

parse_o365_csv(fname,ual_record_worksheet,uniq_ip_worksheet)
spur_uniq_ips(uniq_ips,spur_worksheet)
xlxsoutfile.close()
