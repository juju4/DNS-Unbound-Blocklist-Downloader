#!/usr/bin/python

import urllib2
import re
import argparse
import subprocess, shlex

#blocklist information

blocklists = {
	'abuse.ch Feodo Tracker (Domain)': {
		'id': 'abusefeododomain',
		'url':  'https://feodotracker.abuse.ch/blocklist/?download=domainblocklist',
		'regex' : '',
		'file' : 'feodo.domain',
	},
		'abuse.ch Zeus Tracker (Domain)': {
		'id': 'abusezeusdomain',
		'url':  'https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
		'regex' : '',
		'file' : 'zeus.domain',
	},
	'abuse.ch Palevo Tracker (Domain)': {
		'id': 'abusepalevodomain',
		'url':  'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist',
		'regex' : '',
		'file' : 'palevo.domain',
	},
	'malwaredomains.com Domain List': {
		'id': 'malwaredomainsdomain',
		'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
		'regex': '',
		'file' : 'malwaredomains.domain',
	},
	'PhishTank': {
		'id': 'phishtank',
		'url': 'http://data.phishtank.com/data/online-valid.csv',
		'regex': '/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/',
		'file' : 'phishtank.domain',
	},
	'MVPS': {
		'id': 'mvps',
		'url': 'http://winhelp2002.mvps.org/hosts.txt',
		'regex': '',
		'file' : 'mvps.domain',
	},
	'pgl.yoyo.org': {
		'id': 'pgl.yoyo.org',
		'url': 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext',
		'regex': '',
		'file' : 'pgl.yoyo.org.domain',
	},
	'Hosts File Project': {
		'id': 'hostsfileproject',
		'url': 'http://hostsfile.mine.nu/Hosts',
		'regex': '',
		'file' : 'hfp.domain',
	},
	'The Cameleon Project': {
		'id': 'cameleonproject',
		'url': 'http://sysctl.org/cameleon/hosts',
		'regex': '',
		'file' : 'cameleon.domain',
	},
## down
#	'AdAway mobile ads': {
#		'id': 'adaway',
#		'url': 'http://adaway.sufficientlysecure.org/hosts.txt',
#		'regex': '',
#		'file' : 'adaway.domain',
#	},
	'hpHosts ad-tracking servers': {
		'id': 'hphosts',
		'url': 'http://hosts-file.net/download/hosts.txt',
		'regex': '',
		'file' : 'hphosts.domain',
	},
	'Someone Who Cares': {
		'id': 'someonewhocares',
		'url': 'http://someonewhocares.org/hosts/hosts',
		'regex': '',
		'file' : 'someonewhocares.domain',
	}
}

## exception list for blocked tld: remove any local-data configuration else conflict in unbound
#blockedTLDs = [ ]
blockedTLDs = [ 
    re.compile('\.science$'),
    re.compile('\.biz$'),
    re.compile('\.link$'),
    re.compile('\.gq$')
  ]

def downloadAndProcessBlocklist(url, regex, filename):
	req = urllib2.Request(url)
	req.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)')

	contents = ''

	#download blocklist
	try:
		response = urllib2.urlopen(req)
		contents = response.read()
				
		#process blocklists
		if regex != '':
			match = re.findall(regex, contents)
			print match
			contents = match
	except urllib2.URLError as e:
		if hasattr(e, 'reason'):
			print 'We failed to reach a server.'
			print 'Reason: ', e.reason
		elif hasattr(e, 'code'):
			print 'The server couldn\'t fulfill the request.'
			print 'Error code: ', e.code
		else:
			print 'unknown error'

	return str(contents)
	

# main
IPV4_ADDR = '127.0.0.1'
IPV6_ADDR = '::1'

#sensible defaults
location = '/etc/unbound/conf.d/'
filename = '80local-blocking-data.conf'
output = ""

parser = argparse.ArgumentParser(description='IP blocklist downloader and importer for pf and ip tables')
parser.add_argument('-l', '--blocklist_location',help='location to store blocklists', required=False)
parser.add_argument('-f', '--filename',help='filename of blocklist', required=False)
parser.add_argument('-n', '--blocklist_names',help='specify names of blocklists to download', required=False, type=lambda s: [str(item) for item in s.split(',')])
parser.add_argument('-r', '--restart',help='restart unbound', required=False, action="store_true")
parser.add_argument('-c', '--restartcache',help='restart unbound and preserve cache (slower)', required=False, action="store_true")

args = parser.parse_args()

if args.blocklist_location != None:
	location = args.blocklist_location

for key, value in sorted(blocklists.items()):

	#download all blocklists of the given type
	if args.blocklist_names == None:
		print('downloading '+key)
		output = output + downloadAndProcessBlocklist(value['url'], value['regex'], value['file'])
	else:
		#download specified blocklists
		if value['id'] in args.blocklist_names:
			print('downloading '+key)
			output = output + downloadAndProcessBlocklist(value['url'], value['regex'], value['file'])

#remove comments, duplicates and process
output = re.sub(r'(?m)^\#.*\n?', '', output)
output = re.sub(r'(?m)(.*)#.*\n?', '$1', output)
listOutput = re.findall('(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', output)	
listOutput = list(set(listOutput))
listOutput = [x for x in listOutput if x != "127.0.0.1"]
## unbound will complain if blacklisting a domain when zone already is
listOutput = [x for x in listOutput if not any(regex.search(x) for regex in blockedTLDs) ]

#write to file
try:
	with open(location+filename, 'w') as f:
		
		## one-line header so file can be validated on its own against unbound-checkconf
		f.write('server:\n')
		for item in listOutput:
			
			f.write('  local-data: \"')
			f.write("%s" % item)
			f.write(' A ' + IPV4_ADDR + '\"')
			f.write('\n')
			
			f.write('  local-data: \"')
			f.write("%s" % item)
			f.write(' AAAA ' + IPV6_ADDR + '\"')
			f.write('\n')
			
		f.write('\n')
		f.close()
except IOError as e:
	print e.reason
	
#reload unbound configuration and preserve cache
if args.restartcache:
    subprocess.check_call(shlex.split('unbound-control dump_cache > /tmp/cache'))
    subprocess.check_call(shlex.split('unbound-control reload'))
    subprocess.check_call(shlex.split('unbound-control load_cache < /tmp/cache'))
elif args.restart:
    subprocess.check_call(shlex.split('unbound-control reload'))


