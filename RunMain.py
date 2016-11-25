#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2015-03-24
# @Author  : Robin (sintrb@gmail.com)
# @Version : 1.0

from PyDNSServer import DNSQueryHandler, DNSServer

import re
import sys
import thread
import os
import time

configs = {
	'192.168.1.100': {
		'baidu.com': 'allow',
		'360.com': 'deny',
		'qq.com': '192.168.0.100',
		'.*': 'deny',
	},
	'192.168.1.101': {
		'baidu.com': 'allow',
		'360.com': 'deny',
		'qq.com': '192.168.0.100',
		'.*': 'deny',
	}
}

class FilterHandler(DNSQueryHandler):
	def handle(self):
		data = self.request[0].strip()
		if data.startswith('DNSCFG/'):
			self.feedback(editConfig(data))
		else:
			self.process(data)

	def when_query(self, hostname, dns, rawdata, sock):
		src = self.client_address[0]
		ip = None
		if src in configs:
			ip = self.when_query_sub(hostname, dns, rawdata, sock, configs[src])
		if ip is None:
			ip = self.when_query_sub(hostname, dns, rawdata, sock, configs['*'])
		if ip is None:
			ip = self.queryip(hostname)
		print '%s\t%s -> %s'%(src, hostname, ip)
		if ip == 'deny':
			return
		return ip

	def when_query_sub(self, hostname, dns, rawdata, sock, cfg):
		for key, val in cfg.items():
			if key == hostname or re.match(key, hostname):
				if val == 'allow':
					return self.queryip(hostname)
				return val

def editConfig(data):
	'''
	echo 'DNSCFG/SET/www.sina.com/192.168.111.233/192.168.13.111' | nc 127.0.0.1 53 -u
	'''
	global configs
	print 'editConfig (before) = ', configs

	pieces = data.split('/')
	print pieces
	cmd = pieces[1]
	feed = 'FAIL'

	# DNSCFG/SET/www.sina.com/192.168.111.233/192.168.13.111
	if cmd == 'SET' and len(pieces) >= 5:
		src = pieces[4]
		if src not in configs :
			configs[src] = {}
		configs[src][pieces[2]] = pieces[3]
		feed = 'SUCC'

	# DNSCFG/DEL/*/192.168.13.111
	elif cmd == 'DEL' and len(pieces) >= 4:
		src = pieces[3]
		if src in configs :
			name = pieces[2]
			if name == '*' :
				del configs[src]
			else:
				del configs[src][name]
		feed = 'SUCC'

	print 'editConfig (after) = ', configs
	feedStr = feed + '/' + data
	return feedStr

def loadConfigs():
	''''
	config with dns.cfg
	'''
	global configs
	with open('dns.cfg') as f:
		for l in f:
			l = l.strip()
			if l.startswith('#') or not l:
				continue
			try:
				rs = re.findall('(\S+)\s+(\S+)\s+(\S+)',l)
				p = rs[0][0]
				m = rs[0][1]
				s = rs[0][2]
				print '  cfg: %s -> %s -> %s'%(p,m,s)
				if s not in configs :
					configs[s] = {}
				configs[s][p] = m
			except:
				print 'err line: %s'%l

	print 'configs = ', configs
	dumpConfigs();

def dumpConfigs():
	global configs
	print '-configs--------------------------------'
	for src, cfg in configs.items():
		print src, ':'
		for name, ip in cfg.items():
			print '  %s -> %s'%(name, ip)
	print '----------------------------------------'

def startDnsService():
	loadConfigs()
	host, port = '0.0.0.0', 53
	serv = DNSServer((host, port), DNSQueryHandlerClass=FilterHandler)
	print 'DNS Server running at %s:%s'%(host, port)
	serv.serve_forever()

from flask import Flask
from flask import request
web = Flask(__name__)

@web.route('/')
def hello_world():
    return 'Hello World, I\'m PyDnsServer !'

@web.route('/config')
def config():
 	data = request.args.get('data').encode('ascii')
	print 'config data = ', data
	return editConfig(data)

if __name__ == "__main__":
	configs = {'*': {}}

	if 'MAIN_PID' in os.environ :
		print 'MAIN_PID = ', os.environ['MAIN_PID']
		print 'starting dns service ...'
		thread.start_new(startDnsService, ())
	else:
		print 'waiting for subprocess ...'
		os.environ['MAIN_PID'] = str(os.getpid())

	time.sleep(1)
	web.debug = True
	web.run(host='0.0.0.0', port=9999)
