#!/usr/bin/env python3

import subprocess
import os
import time
import json
import logging
import uuid

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def do_command(cmd):
	try:
		output = subprocess.getoutput(cmd)
		return output
	except AttributeError:
		return ''

def being_updated(flag):
	if flag:
		os.system('touch /etc/waggle/updating')
	else:
		os.system('rm /etc/waggle/updating')

def get_version(repo, base_path='/usr/lib/waggle/'):
	script_path = '/scripts/get_version'
	if os.path.isfile(base_path+repo+script_path):
		return do_command(base_path+repo+script_path)
	else:
		return 'error: no path exist'

def get_node_id(path='/etc/waggle/node_id'):
	if os.path.isfile(path):
		return do_command('cat ' + path)
	else:
		return 'error: no path exist'

def get_node_model(path='/usr/lib/waggle/core/scripts/'):
	script_name = 'detect_odroid_model.sh'
	if os.path.isfile(path+script_name):
		ret = do_command(path+script_name)
		try:
			ret = ret.split('=')[1]
		except:
			pass
		return ret

def collect_info():
	meta = {}
	meta['node_id'] = get_node_id()
	meta['node_model'] = get_node_model()

	repo_list = os.listdir('/usr/lib/waggle/')
	try:
		repo_list.remove('SSL')
	except:
		pass

	for repo in repo_list:
		ver = get_version(repo)
		if 'error' not in ver:
			meta[repo+'_ver'] = ver
		elif '' in ver:
			meta[repo+'_ver'] = 'unknown'
	return meta

def get_update_info(node_id, meta, beehive_url='http://beehive1.mcs.anl.gov/update/'):
	meta_json = ''
	if isinstance(meta, dict) or isinstance(meta, list):
		meta_json = json.dumps(meta)
	elif isinstance(meta, str):
		meta_json = meta
	else:
		raise ValueError("unsupported type")

	cmd = 'curl -s --connect-timeout 10 --retry 5 --retry-delay 10 -H "Content-Type: application/json" -X POST -d %s %s%s' % (meta_json, beehive_url, node_id)
	ret = do_command(cmd)
	return ret

def download(url, path='/tmp/'):
	path = path + str(uuid.uuid4())
	os.system('mkdir -p %s' % path)
	path += '/' + os.path.basename(url)
	os.system('wget -q -O %s %s' % (path, url))
	return path


def perform_update(repo, update_url, base_path='/usr/lib/waggle/'):
	being_updated(True)

	# Download the patch
	path = download(update_url)
	logging.info(path)

	# Run the patch

	being_updated(False)

if __name__ == '__main__':
	base_sleep_duration = 60 # 1 min
	logging.info("waggle-update service initiated...")

	while True:
		# Get meta information of the node
		info = collect_info()

		# Request update info
		try:
			update_check = get_update_info(info['node_id'], info)
		except Exception as e:
			update_check = ''
			logging.error("Failed to get update info: %s" % str(e))

		# for test
		update_check = json.dumps({'core_ver': 'v2.1.1', 'core_ver_url':'https://raw.githubusercontent.com/waggle-sensor/waggle/master/README.md'})

		# Check if update is needed
		update_list = []
		if update_check:
			try:
				update_check = json.loads(update_check)

				repo_list = [repo for repo in info if '_ver' in repo]
				for repo in repo_list:
					if repo in update_check:
						# TODO: check which is newer
						if info[repo] != update_check[repo]:
							if repo + '_url' in update_check:
								update_list.append((repo, update_check[repo + '_url']))
							else:
								logging.error("%s patch url does not exist" % repo)
						else:
							# The software is up to date
							pass
					else:
						logging.error("%s update info missing" % repo)
			except Exception as e:
				logging.error("Failed to parse response %s: %s" % (update_check, str(e)))
		else:
			logging.error("No response from server")

		# Perform updates
		if update_list != []:
			for repo, url in update_list:
				perform_update(repo.replace('_ver', ''), url)

		time.sleep(base_sleep_duration)