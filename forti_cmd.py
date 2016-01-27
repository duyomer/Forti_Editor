#!/usr/bin/python

import sys
import socket
import re
import csv
import os
import paramiko as pm

sys.stderr = open('/dev/null')       # Silence silly warnings from paramiko
sys.stderr = sys.__stderr__

class AllowAllKeys(pm.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        return

#Authentication credentials
ip_addrs = '10.0.0.1'
username = 'admin'
password = 'qwe123'

#Global Variables
_addRuleFlag = 0

#Regex Variables
re1='((?:[a-z][a-z]+))'	# Word 1
re2='(:)'	# Any Single Character 1
re3='(\\s+)'	# White Space 1
re4='(\\d+)'	# Integer Number 1

#Check command line options
try:
  opt1 = sys.argv[1]
  #_arg1: add or file path
  _arg1 = sys.argv[2]
  #_arg2: Object file path
  _arg2 = sys.argv[3]
  #_arg3: object type
  _arg3 = sys.argv[4]
  #_arg4: object Address
  _arg4 = sys.argv[5]
except IndexError:
  print """Usage:
	forti_cmd.py --file <RULES_FILE_PATH> <OBJECTS_FILE_PATH>
	
	example:
		forti_cmd.py --file /tmp/Rules.csv /tmp/Objects.csv
       	"""
  sys.exit()

#Paramiko connection
client = pm.SSHClient()
client.load_system_host_keys()
client2 = pm.SSHClient()
client2.load_system_host_keys()

#Check TCP 22 connection 
def Check_SSH(IP):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(3)
  try:
    s.connect((IP,22))
    s.shutdown(2)
    return True
  except:
    print "%s SSH connection failed" % (IP)
    return False

def _ssh_Connect(device_ip, username, password, _Num):
  if Check_SSH(device_ip):
    try:
      if int(_Num) == 1:
         client.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
         client.set_missing_host_key_policy(AllowAllKeys())
         client.connect(device_ip,username = username, password = password)
      elif int(_Num) == 2:
         client2.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
         client2.set_missing_host_key_policy(AllowAllKeys())
         client2.connect(device_ip,username = username, password = password)
    except pm.AuthenticationException:
      print "%s Authentication failed" % (device_ip)

def _checkObejectExist(_objectName):
      _ssh_Connect(ip_addrs, username, password, 1)
      _flag = 0
      stdin, stdout, stderr = client.exec_command("show firewall address")
      for line in stdout.read().splitlines():
	if _objectName in line:
	    _flag = 0
    	    break
	else:
	    _flag = 1

      if _flag == 1:
          print "New Object found, trying to search %s in objects file..." % (_objectName)
          return _checkCsvObject(_arg2, _objectName)
      else:
	  return 0
      client.close()

def _getLastID():
      _ruleNum = 0
      _ssh_Connect(ip_addrs, username, password, 2)      
      stdin, stdout, stderr = client2.exec_command("get firewall policy | grep 'policyid:'")
      rg = re.compile(re1+re2+re3+re4,re.IGNORECASE|re.DOTALL)
      _noShit = max(stdout)
      m = rg.search(_noShit)
      if m:
          _ruleNum = m.group(4)
      return "%d" % (int(_ruleNum))
      client2.close()

def _deleteRule(_ruleNumber):
      _ssh_Connect(ip_addrs, username, password, 1)
      _ruleNum = 0
      stdin, stdout, stderr = client.exec_command("config firewall policy \n delete %s" % (_ruleNumber))
      print "Rule %s Deleted." % (_ruleNumber)
      client.close()

def _checkCsvObject(_csvobjectpath, _objectName):
    try:
      _flag = 0
      csvFile = csv.DictReader(open(_csvobjectpath, "rb"))
      
      for row in csvFile:
	_name = row['Object Name']
        if _name == _objectName:
	    _flag = 0
	    break
	else:
	    _flag = 1

      if _flag == 0:
          _type = row['Type']
          _subnet = row['Subnet']
          print "Object %s found, creating new object in db..." % (_objectName)
          _addObject(_name, _type, _subnet)
          print "Object %s created." % (_objectName)
	  return 0
      else:
	  print "The Object %s does not exist in objects file, please add and try again." % (_objectName)
	  return 1
    except pm.AuthenticationException:
      print stderr.read()

def _addObject(_objectName, _objectType, _objectAddress):
    try:
      _ssh_Connect(ip_addrs, username, password, 1)
      stdin,stdout,stderr = client.exec_command("config firewall address \n edit %s \n set type %s \n set subnet %s \n end" % (_objectName, _objectType, _objectAddress))
      _checkObejectExist(_objectName)
    except pm.AuthenticationException:
      print stderr.read()
    client.close()

def _addRule(_srcAddr, _dstAddr, _srcIntf, _dstIntf, _service, _schedule, _action, _trafficLog):
    try:
      _ssh_Connect(ip_addrs, username, password, 2)
      _ruleNum = int(_getLastID()) + 1
      stdin,stdout,stderr = client.exec_command("config firewall policy \n edit %s \n set srcaddr %s \n set dstaddr %s \n set srcintf %s \n set dstintf %s \n set service %s \n set schedule %s \n set action %s \n set nat %s \n end" % (_ruleNum, _srcAddr, _dstAddr, _srcIntf, _dstIntf, _service, _schedule, _action, _trafficLog))
      print "Rule %s Created." %(_ruleNum)
    except pm.AuthenticationException:
      print stderr.read()
    client2.close()

def _runCsvRules(filepath):
	csvFile = csv.DictReader(open(filepath, "rb"))
	for row in csvFile:
	  _sourceAddr = row['Source Address']
	  _destAddr = row['Destination Address']
	  _sourceIntf = row['Source Interface']
	  _destIntf = row['Destination Interface']
	  _servicePort = row['Service']
	  _scheduleTime = row['Schedule']
	  _actionType = row['Action']
	  _trafficLog = row['NAT']
	
	  _addRuleFlag = _checkObejectExist(_sourceAddr)
	  _addRuleFlag = _checkObejectExist(_destAddr)

	  if _addRuleFlag == 0:
	      _addRule(_sourceAddr, _destAddr, _sourceIntf, _destIntf, _servicePort, _scheduleTime, _actionType, _trafficLog)
	  else:
	      print "Rule not created"

if opt1 == "--add":
    _ssh_Connect(ip_addrs, username, password, 1)
    print("%s  %s  %s" % (_arg2, _arg3, _arg4))
    _addObject(_arg2, _arg3, _arg4)
elif opt1 == "--file":
    if int(_arg3) == 1:
        for num in range(1,6):
            _deleteRule(num)
    elif int(_arg3) == 2:
        _runCsvRules(_arg1)
