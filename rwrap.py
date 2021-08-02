#!/usr/bin/python3
'''rpspice - a Proxmox PVE SPICE wrapper for remote-viewer

Uses SSH tunneling to connect to SPICE-enabled VMs, which are
running inside Proxmox PVE.
Requirements: virt-viewer (provides remote-viewer), python3,
              python3-crypto, subprocess, tempfile

Credits:
--------
Initial shell script:
https://forum.proxmox.com/threads/remote-spice-access-without-using-web-manager.16561/page-3#post-238210

'''
# -*- coding: utf-8 -*-
# now  with GPG-signed commits

import os
import getpass
import subprocess
import tempfile
from argparse import ArgumentParser
import requests

'''
TODO:
* Add node selection
* Fix API port selection bug (?)
* Rewrite docstrings
'''

# CONSTANTS
DEBUG = False

def main():
    '''Main worker

    '''
    # Get the arguments object
    arguments = parse_arguments()

    # Determine if the cluster web interface
    # is running on default 8006 port,
    # or default SSL port (443)
    pve_port = determine_port(arguments.fqdn)

    # 1) PVE API URL
    # https://<arguments.fqdn>:[port]/api2/json/
    pve_api_url = 'https://' + arguments.fqdn + ':' + pve_port + '/api2/json/'

    # 2) Get credential parameters
    (pve_cookie, pve_header) = get_pve_cookies(api_url=pve_api_url,
                                               username=arguments.username,
                                               password=arguments.password)
    # 3) Get VM status dictionary
    # If VM name is provided, use it, else use VM ID
    vminfo = get_node_info(api_url=pve_api_url,
                           pve_cookie=pve_cookie,
                           vmname=arguments.vmname,
                           vmid=arguments.vmid)

    # 4) Get SPICE parameters
    pve_spice_url = pve_api_url + 'nodes/' + vminfo['node'] +\
                    '/' + vminfo['type'] + '/' + vminfo['id'] +\
                    '/spiceproxy'

    pve_spice = get_spice_info(pve_spice_url=pve_spice_url,
                               pve_cookie=pve_cookie,
                               pve_header=pve_header,)


    json_data = pve_spice.json()['data']
    if DEBUG:
        print(json_data['password'])



    # 5) Generate connection file
    connection_file_name = generate_rc_file(json_data['title'], json_data['host'],
                                            json_data['ca'],json_data['tls-port'],
                                            json_data['password'], json_data['proxy'],
                                            json_data['host-subject'])

    # 6) Starting remove-viewer subprocess
    with open(os.devnull, 'w') as devnull:
        try:

            output = subprocess.run(['remote-viewer', connection_file_name],
                                    stdout=devnull, stderr=devnull)
            output.check_returncode()

        except subprocess.CalledProcessError:
            print("Error: remove-viewer subprocess terminated")


def parse_arguments():
    '''Argument parser for Proxmox API

    Minimal set of arguments: username, password, cluster address
    and node name or ID
    '''
    arg_parser = ArgumentParser()

    arg_parser.add_argument("-u", '--user', dest='username', required=True,
                            help="Proxmox PVE username (example: johndoe@pve)")

    arg_parser.add_argument("-c", "--cluster", dest='fqdn', required=True,
                            help="Proxmox cluster FQDN (example: foo.example.com)")

    arg_parser.add_argument("-p", "--password", dest='password', required=False,
                            help="User password in clear text")

    # VM ID/name selection
    vmid_group = arg_parser.add_mutually_exclusive_group(required=True)
    vmid_group.add_argument("-n", '--name', dest='vmname', help="VM name in PVE cluster")
    vmid_group.add_argument("-i", '--id', dest='vmid', help="VM ID in PVE cluster")

    # We parse here to determine if user had entered password
    arg_output = arg_parser.parse_args()

    # If -p is not specified, ask for password safely
    if not arg_output.password:
        arg_output.password = getpass.getpass()

    return arg_output

def determine_port(fqdn):
    '''Determines Proxmox VE port

    Test if Proxmox VE web API is running on
    the default HTTPS port (443), if not, falls
    back to the PVE default port (8006)

    Arguments:
        fqdn {string} -- FQDN of a Proxmox VE cluster.

    Returns:
        string -- Valid port (443 or 8006)
    '''
    try:
        request = requests.get('https://' + fqdn + ':443')
        request.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return '8006'
    else:
        return '443'

def get_pve_cookies(api_url, username, password):
    '''Gets credential tokens

    Uses Proxmox API call to get Authentication Cookie
    and CSRF prevention token. That data is then used
    to make authentificated API calls.

    Arguments:
        api_url {string} -- URL of the Proxmox VE cluster API
        username {string} -- Proxmox VE user name
        password {string} -- User password

    Returns:
        tuple -- Returns tuple of dictionaries
                    in format ({'PVEAuthCookie':'<data>'},{'CSRFPreventionToken':'<data>'})

    Raises:
        ConnectionError -- Raises connection error if the cluster's
                            answer is anything except 200 OK
    '''

    # Sending ticket request
    payload = {'username':username, 'password':password}
    pve_ticket_response = requests.post(url=api_url + 'access/ticket',
                                        data=payload)
    # Checking server response
    if not pve_ticket_response.ok:
        raise ConnectionError('PVE proxy returned HTTP code ' +
                              str(pve_ticket_response.status_code))

    pve_cookie = {
        'PVEAuthCookie': pve_ticket_response.json()['data']['ticket'],
    }

    pve_header = {
        'CSRFPreventionToken': pve_ticket_response.json()['data']['CSRFPreventionToken'],
    }

    # Returns a tuple of dictionariese
    return pve_cookie, pve_header


def get_node_info(api_url, pve_cookie, vmname=None, vmid=None):
    '''Generates Proxmox VM info

    Uses Proxmox PVE API call to determine VM parameters
    Searches by VM ID or name, raises exception if both
    are empty or VM with ID/name not found in cluster.

    Arguments:
        url {strind} -- Proxmox cluster API URL
        pve_header {dictionary} -- Authentication: CSRF prevention token
        pve_cookie {dictionary} -- Authentication: PVEAuth cookie

    Keyword Arguments:
        vmname {string} -- optional VM name (default: {None})
        vmid {string} -- optional VM ID (default: {None})

    Returns:
        dictionary -- VM parameters, such as name, type, id, etc.

    Raises:
        ValueError -- when either ID or name are not provided.
        BaseException -- when search for VM is unsuccessfull.
    '''
    # If no values provided:
    if not vmname and not vmid:
        raise ValueError("Neither Name nor ID provided")

    vminfo = dict({})

    # https://<arguments.fqdn>:[port]/api2/json/cluster/resources
    url = api_url + 'cluster/resources'

    pve_resource = requests.get(url, cookies=pve_cookie).json()['data']

    # Search for the VM data
    for item in pve_resource:

        # VM's only
        if item['type'] == 'lxc' or item['type'] == 'qemu':
            # if either name or id matches:
            # may cause collisions?
            true_id = item['id'].split('/')[1] # lxc|qemu/xxx -> xxx
            if item['name'] == vmname or true_id == vmid:
                vminfo['name'] = item['name']
                vminfo['type'] = item['type']
                vminfo['id'] = true_id
                vminfo['node'] = item['node']
    if not vminfo:
        # Not name nor id found
        raise BaseException("VM not found in cluster")
    return vminfo

def get_spice_info(pve_spice_url, pve_cookie, pve_header):
    '''Gets VM information

    '''
    pve_spice = requests.post(pve_spice_url, headers=pve_header, cookies=pve_cookie)

    if not pve_spice.ok:
        raise ConnectionError('Could not get SPICE params, got answer {status}'.format(
            status=pve_spice.status_code))
    return pve_spice

def generate_rc_file(title, host, cert, port,
                     password, proxy, subject):
    '''Makes connection file for remote-viewer

    Generates and returns file name of a temporary
    remote-viewer connection file.

    Arguments:
        node_name {string} -- A name of a node, which runs selected VM
        node_fqdn {string} -- Fully Qualified Domain Name of a node
        ca_file_name {string} -- A name of generated CA file
        port {string} -- Port of a SPICE interface in a node
        password (string) -- Password, ecnrypted for remote-viewer

    Returns:
        string -- Connection file name
    '''
    # Creating a list for remote-viewer settings
    conn_param = []
    # Filling in parameters...
    # Common settings
    conn_param.append('[virt-viewer]' + '\n')
    conn_param.append('type=spice' + '\n')
    conn_param.append('toggle-fullscreen=Shift+F11' + '\n')
    conn_param.append('title=' + title + '\n')
    conn_param.append('tls-port=' + str(port) + '\n')
    conn_param.append('host=' + host + '\n')
    conn_param.append('ca=' + cert + '\n')
    conn_param.append('host-subject=' + subject + '\n')
    conn_param.append('password=' + password + '\n')
    conn_param.append('proxy=' + proxy + '\n')
    conn_param.append('release-cursor=Ctrl+Alt+R' + '\n')
    conn_param.append('delete-this-file=1' + '\n')

    # Generating connection file
    with open(tempfile.NamedTemporaryFile
              (dir=os.path.expanduser("~"),
               suffix='.conf').name, 'w') as connection_file:

        connection_file.writelines(conn_param)

    return connection_file.name

if __name__ == '__main__':
    main()
