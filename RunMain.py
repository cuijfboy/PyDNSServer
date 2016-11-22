#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2015-03-24
# @Author  : Robin (sintrb@gmail.com)
# @Version : 1.0

from PyDNSServer import DNSQueryHandler, DNSServer

import re
import sys

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
	def when_query_sub(self, hostname, dns, rawdata, sock, cfg):
		for p, v in cfg.items():
			if p == hostname or re.match(p, hostname):
				if v == 'deny':
					return
				elif v == 'allow':
					ip = self.queryip(hostname)
				else:
					ip = v
				print '%s %s %s'%(self.client_address[0], hostname, ip)
				return ip

	def when_query(self, hostname, dns, rawdata, sock):
		src = self.client_address[0]
		if src in configs :
			ip = self.when_query_sub(hostname, dns, rawdata, sock, configs[src])
		if not ip :
			ip = self.when_query_sub(hostname, dns, rawdata, sock, configs['*'])
		return ip

	def handle(self):
		data = self.request[0].strip()
		if data.startswith('DNSCFG/'):
			self.config(data)
		else:
			self.process(data)

	def config(self, data):
		'''
		echo 'DNSCFG/SET/www.sina.com/192.168.111.233/192.168.13.111' | nc 127.0.0.1 53 -u
		'''
		pieces = data.split('/')
		print pieces
		cmd = pieces[1]
		feed = 'FAIL'

		# DNSCFG/SET/www.sina.com/192.168.111.233/192.168.13.111
		if cmd == 'SET' and len(pieces) >= 5:
			src = pieces[4]
			if src not in configs :
				configs[src] = []
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

		print 'configs = ', configs
		print feed + '/' + data
		# self.feedback(feed + '/' + data)

if __name__ == "__main__":
	configs = {'*': {}}
	# config with dns.cfg
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
				print '%s -> %s -> %s'%(p,m,s)
				if s not in configs :
					configs[s] = {}
				configs[s][p] = m
				# configs[s].append((p,m))
			except:
				print 'err line: %s'%l
	print 'configs =  ', configs
	host, port = '0.0.0.0', len(sys.argv) >= 2 and int(sys.argv[1]) or 53
	serv = DNSServer((host, port), DNSQueryHandlerClass=FilterHandler)
	print 'DNS Server running at %s:%s'%(host, port)
	serv.serve_forever()
