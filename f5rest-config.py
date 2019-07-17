"""
f5rest.py, Regis Donovan 

This is a script to use the REST API for F5 LTM to query the LTM for
a list of virtual servers and information about them - default pool,
what nodes are in the pool if it exists, what profiles and irules 
are applied to the virtual server.  

What it's doing, basically, is making a bunch of simple web calls with 
'basic auth' authentication and the server replies with a big chunk of
json data.  The python 'json' library takes in json and turns it into
python-friendly data types.  You could actually do all this from the 
unix command line if you were particularly masochistic, using commands like
curl -k -u uname:passwd -H "Content-Type: application/json" -X GET https://ltm-ip.example.com/mgmt/tm/ltm/
(the -k flag says 'ignore it if the ssl cert is self-signed')

The way I got all the sample output to demonostrate the schema in the 
functions below was to run commands like that using the google chrome
"postman" chrome app, which is great for displaying json output.


"""
import sys
import socket
from optparse import OptionParser
sys.path.append(r'/home/rdonov01/python-other-libs/requests-2.4.3')
import requests
import json
import string

#sys.path.append(r'/home/rdonov01/bin/')
#import myf5restlib
#from myf5restlib import *

#pprint is likely only used when i'm doing things with this interactively
from pprint import pprint

# this is in here to stop the program from printing ssl warnings
# triggered by self-signed device.
requests.packages.urllib3.disable_warnings()

username = 'admin'


def parse_commandline_options():

# get the command line arguments for device and community string
  global hostname
  global password

  parser = OptionParser()
  parser.add_option("-l", "--ltm", dest="arg_ltm", help = "LTM IP", metavar="LTM IP ADDRESS")
  parser.add_option("-p", "--passwordfile", dest="arg_passwordfile", help = "File containing Admin password", metavar="ADMIN PASSWORD FILE")

  (options, args) = parser.parse_args()

  if options.arg_ltm and options.arg_passwordfile:
    hostname = options.arg_ltm
    pwfile = options.arg_passwordfile
    password = 'NULL'
    try: 
      fhand = open(pwfile)
    except: 
      print 'error opening file ', pwfile
      exit()
    for line in fhand:
      mystring = line.strip()
      if mystring.startswith('#'):
        continue
      else:
        password = mystring
        break
    if password == 'NULL':
      print ('%s file does not contain uncommented password line?' % options.arg_passwordfile)
      sys.exit()

    
    if not is_ipV4(hostname):
      print ("%s is not a valid IP address?  aton != ntoa?" % device_ip)
      sys.exit()
  else: 
    print "missing arguments? I see options", options
    print "and args", args,"\n\n"
    parser.print_help()
    sys.exit()

  return ()


###########################
###########################

"""

This is a set of functions using the REST API for F5 LTM to query the
LTM for a list of virtual servers and information about them - default
pool, what nodes are in the pool if it exists, what profiles and
irules are applied to the virtual server.

What it's doing, basically, is making a bunch of simple web calls with
'basic auth' authentication and the server replies with a big chunk of
json data.  The python 'json' library takes in json and turns it into
python-friendly data types.  You could actually do all this from the
unix command line if you were particularly masochistic, using commands
like curl -k -u uname:passwd -H "Content-Type: application/json" -X
GET https://ltm-ip.example.com/mgmt/tm/ltm/ (the -k flag says 'ignore
it if the ssl cert is self-signed')

The way I got all the sample output to demonostrate the schema in the 
functions below was to run commands like that using the google chrome
"postman" chrome app, which is great for displaying json output.


"""
import sys
import socket
sys.path.append(r'/home/rdonov01/python-other-libs/requests-2.4.3')

import json
import requests
import string
#pprint is likely only used when i'm doing things with this interactively
from pprint import pprint

# this is in here to stop the program from printing ssl warnings
# triggered by self-signed device.
requests.packages.urllib3.disable_warnings()

def is_ipV4(addrstring):
  """ checks that a dotted decomial IP address string can be correctly
      parsed by the OS's inet_pton - quick way to verify formatting

      takes addrstring which is "10.64.1.1" or something like it.
  """
  try:
    socket.inet_aton(addrstring)
    ip = True
  except socket.error:
    print 'ERROR: not a valid IP address string?'
    ip = False
    return(ip)
  try:
    socket.inet_ntoa(socket.inet_aton(addrstring))
  except:
    print 'ERROR: not a valid IP address string?'
    ip = False
    return(ip)
  if socket.inet_ntoa(socket.inet_aton(addrstring)) != addrstring:
    print 'ERROR: IP formatting error aton != ntoa?'
    ip = False
  return (ip)




def de_unicode(input):
  """ json output ends up as unicode strings some/all of the time
  this turns them into strings. 
  """
  if isinstance(input, dict):
    foo=dict()
    for key,value in input.iteritems():
      foo[de_unicode(key)] = de_unicode(value)
    return foo
  elif isinstance(input, list):
    foo = []
    for element in input:
      foo.append(de_unicode(element))
    return foo
  elif isinstance(input, unicode):
    return input.encode('utf-8')
  else:
    return input


def localhost_to_hostname(mylink):
  """ links returned by REST API point to localhost.  Fix it so it
      points to the hostname.  uses global variable hostname
  """
  global hostname

  if 'localhost' in mylink:
    return string.replace(mylink, 'localhost', hostname)
  else:
    return False


def get_f5json(my_url):
  """ assumes global f5rest_session has already been set up, gets json output of a url
  """
  global f5rest_session
  response = f5rest_session.get(my_url)
  if response.status_code < 400:
#    print "url ", my_url," gets status code ", response.status_code
#    print "json output is:"
#    pprint(response.json())
    return(de_unicode(response.json()))
  else:
#    print "returning false"
    return(False)

def trim_url(mylink):
  """ trims url of the form "https://localhost/mgmt/tm/ltm/pool/~Common~emptypool/members?ver=11.5.3"
      to just "ltm/pool/~Common~emptypool/members"
  """
  x = mylink.split('?')[0]
  return (string.replace(x,'https://localhost/mgmt/tm/',''))


def get_virts():
  """ gets json of virtual servers.  schema follows
  #         {
  #             "kind": "tm:ltm:virtual:virtualstate",
  #             "name": "vs-dev-01.uit.College.edu-8443",
  #             "partition": "PARTITION1",
  #             "fullPath": "/PARTITION1/vs-dev-01.uit.College.edu-8443",
  #             "generation": 1,
  #             "selfLink": "https://localhost/mgmt/tm/ltm/virtual/~PARTITION1~vs-dev-01.uit.College.edu-8443?ver=11.5.3",
  #             "addressStatus": "yes",
  #             "autoLasthop": "default",
  #             "cmpEnabled": "yes",
  #             "connectionLimit": 0,
  #             "destination": "/PARTITION1/10.64.112.244:8443",
  #             "enabled": true,
  #             "gtmScore": 0,
  #             "ipProtocol": "tcp",
  #             "mask": "255.255.255.255",
  #             "mirror": "disabled",
  #             "mobileAppTunnel": "disabled",
  #             "nat64": "disabled",
  #             "pool": "/PARTITION1/vs-dev-01.uit.College.edu-8443",
  #             "rateLimit": "disabled",
  #             "rateLimitDstMask": 0,
  #             "rateLimitMode": "object",
  #             "rateLimitSrcMask": 0,
  #             "source": "0.0.0.0/0",
  #             "sourceAddressTranslation": {
  #                 "type": "automap"
  #             },
  #             "sourcePort": "preserve",
  #             "synCookieStatus": "not-activated",
  #             "translateAddress": "enabled",
  #             "translatePort": "enabled",
  #             "vlansEnabled": true,
  #             "vsIndex": 100,
  #             "vlans": [
  #                 "/Common/TABNDCPublic"
  #             ],
  #             "policiesReference": {
  #                 "link": "https://localhost/mgmt/tm/ltm/virtual/~PARTITION1~vs-dev-01.uit.College.edu-8443/policies?ver=11.5.3",
  #                 "isSubcollection": true
  #             },
  #             "profilesReference": {
  #                 "link": "https://localhost/mgmt/tm/ltm/virtual/~PARTITION1~vs-dev-01.uit.College.edu-8443/profiles?ver=11.5.3",
  #                 "isSubcollection": true
  #             }
  #         },##        , (more as needed for additional virtual servers)
  #
  #    ]
  #}
  """
  global f5rest_url
#  print "in get_virts, getting ", f5rest_url
  return (get_f5json(f5rest_url + 'ltm/virtual'))



def get_pools():
  """ gets json of pools.  schema follows
  #{
  #    "kind": "tm:ltm:pool:poolcollectionstate",
  #    "selfLink": "https://localhost/mgmt/tm/ltm/pool?ver=11.5.3",
  #    "items": [
  #        {
  #            "kind": "tm:ltm:pool:poolstate",
  #            "name": "mypoolname",
  #            "partition": "mypartition",
  #            "fullPath": "/mypartition/mypoolname",
  #            "generation": 1,
  #            "selfLink": "https://localhost/mgmt/tm/ltm/pool/~mypartition~mypoolname?ver=11.5.3",
  #            "allowNat": "yes",
  #            "allowSnat": "yes",
  #            "ignorePersistedWeight": "disabled",
  #            "ipTosToClient": "pass-through",
  #            "ipTosToServer": "pass-through",
  #            "linkQosToClient": "pass-through",
  #            "linkQosToServer": "pass-through",
  #            "loadBalancingMode": "round-robin",
  #            "minActiveMembers": 0,
  #            "minUpMembers": 0,
  #            "minUpMembersAction": "failover",
  #            "minUpMembersChecking": "disabled",
  #            "monitor": "/Common/gateway_icmp ",
  #            "queueDepthLimit": 0,
  #            "queueOnConnectionLimit": "disabled",
  #            "queueTimeLimit": 0,
  #            "reselectTries": 0,
  #            "slowRampTime": 10,
  #            "membersReference": {
  #                "link": "url-for-rest-request-for-pool-members",
  #                "isSubcollection": true
  #            }
  #        }
  ##      ,(repeated as needed for additional pools)
  #    ]
  #}
  """
  global f5rest_url
  return (get_f5json(f5rest_url + 'ltm/pool'))

def get_poolmembers(mypoolstring):
  """ Get json of pool members.  Schema follows.
  # {
  #     "kind": "tm:ltm:pool:members:memberscollectionstate",
  #     "selfLink": "https://localhost/mgmt/tm/ltm/pool/~PARTITION1~PARTITION1testpool/members?ver=11.5.3",
  #     "items": [
  #         {
  #             "kind": "tm:ltm:pool:members:membersstate",
  #             "name": "192.168.155.156:80",
  #             "partition": "PARTITION1",
  #             "fullPath": "/PARTITION1/192.168.155.156:80",
  #             "generation": 1,
  #             "selfLink": "https://localhost/mgmt/tm/ltm/pool/~PARTITION1~PARTITION1testpool/members/~PARTITION1~192.168.155.156:80?ver=11.5.3",
  #             "address": "192.168.155.156",
  #             "connectionLimit": 0,
  #             "dynamicRatio": 1,
  #             "inheritProfile": "enabled",
  #             "logging": "disabled",
  #             "monitor": "default",
  #             "priorityGroup": 0,
  #             "rateLimit": "disabled",
  #             "ratio": 1,
  #             "session": "user-enabled",
  #             "state": "unchecked"
  #         }
  #         , (additional as needed)
  #     ]
  # }
  """
  global f5rest_url
  return (get_f5json(f5rest_url + mypoolstring + '/members/'))


def get_nodes():
  """ Get json of all nodes.  Schema follows for sample 10.0.0.1 node
  # {
  #     "kind": "tm:ltm:node:nodecollectionstate",
  #     "selfLink": "https://localhost/mgmt/tm/ltm/node?ver=11.5.3",
  #     "items": [
  #         {
  #             "kind": "tm:ltm:node:nodestate",
  #             "name": "10.0.0.1",
  #             "partition": "Common",
  #             "fullPath": "/Common/10.0.0.1",
  #             "generation": 288,
  #             "selfLink": "https://localhost/mgmt/tm/ltm/node/~Common~10.0.0.1?ver=11.5.3",
  #             "address": "10.0.0.1",
  #             "connectionLimit": 0,
  #             "dynamicRatio": 1,
  #             "logging": "disabled",
  #             "monitor": "default",
  #             "rateLimit": "disabled",
  #             "ratio": 1,
  #             "session": "user-enabled",
  #             "state": "unchecked"
  #         }
  #         ,(repeated as needed for additional nodes)
  # 
  #     ]
  # }
  """
  global f5rest_url
  return (get_f5json(f5rest_url + 'ltm/node'))


def list_poolmembers(mypoolstring):
  """ takes a link descriptor for a pool (ltm/pool/~Common~emptypool/members) and 
      grabs the list of members from it, counts and prints the 'name' field of each.
      schema follows:
  # {
  #     "kind": "tm:ltm:pool:members:membersstate",
  #     "name": "192.168.155.156:80",
  #     "partition": "PARTITION1",
  #     "fullPath": "/PARTITION1/192.168.155.156:80",
  #     "generation": 1,
  #     "selfLink": "https://localhost/mgmt/tm/ltm/pool/~PARTITION1~PARTITION1testpool/members/~PARTITION1~192.168.155.156:80?ver=11.5.3",
  #     "address": "192.168.155.156",
  #     "connectionLimit": 0,
  #     "dynamicRatio": 1,
  #     "inheritProfile": "enabled",
  #     "logging": "disabled",
  #     "monitor": "default",
  #     "priorityGroup": 0,
  #     "rateLimit": "disabled",
  #     "ratio": 1,
  #     "session": "user-enabled",
  #     "state": "unchecked"
  # }

  """
  global f5rest_url
  print "pool", string.replace(string.replace(mypoolstring,'ltm/pool/',''),'~','/')
  memberjson = get_poolmembers(mypoolstring)
  membercount = len(memberjson['items'])
  if membercount == 0:
    print "pool has no members"
  else:
    print "   pool has %d member(s)" % membercount
    for x in memberjson['items']:
      print '\t',x['name']

def get_profiles(profileurl):
  """ Get json of profiles for a given virtual server.  Expecting a string
  that contains the whole URL except w localhost instead of hostname.
  Schema follows with examples of http profile and clientside ssl profile.
  # {
  #     "kind": "tm:ltm:virtual:profiles:profilescollectionstate",
  #     "selfLink": "https://localhost/mgmt/tm/ltm/virtual/~Common~myvirtualserver/profiles",
  #     "items": [
  #         {
  #             "kind": "tm:ltm:virtual:profiles:profilesstate",
  #             "name": "http",
  #             "partition": "Common",
  #             "fullPath": "/Common/http",
  #             "generation": 344,
  #             "selfLink": "https://localhost/mgmt/tm/ltm/virtual/~Common~newbogus-https/profiles/~Common~http?ver=11.5.3",
  #             "context": "all"
  #         },
  #        {
  #            "kind": "tm:ltm:virtual:profiles:profilesstate",
  #            "name": "testprofile",
  #            "partition": "Common",
  #            "fullPath": "/Common/testprofile",
  #            "generation": 344,
  #            "selfLink": "https://localhost/mgmt/tm/ltm/virtual/~Common~newbogus-https/profiles/~Common~testprofile?ver=11.5.3",
  #            "context": "clientside"
  #        }
  # }
  """
  return (get_f5json(localhost_to_hostname(profileurl)))

def list_profiles(profilejson):
  """ expecting big json chunk containing all profiles applied to the virtual server.
  returns a string listing profile names
  """
  listofprofiles = ''
  for nextprofile in profilejson['items']:
    if listofprofiles == '' :
      listofprofiles = nextprofile['name']
    else:
      listofprofiles = listofprofiles + "; " + nextprofile['name']

  return(listofprofiles)

def get_cert(clientprofile):
  """ expecting a string showing where the client ssl profile from the profile
  'fullPath' item, swapping ~ in for / in the string and appending that to
  f5rest_url + "ltm/profile/client-ssl/"
  """
  global f5rest_url
  fullurl = f5rest_url + "ltm/profile/client-ssl/" + clientprofile.replace("/", "~")
  return (get_f5json(fullurl))
  


def get_certlist():
  """ runs https://hostname/mgmt/tm/sys/crypto/cert
  json items entries look like this:
  # {'apiRawValues': {'certificateKeySize': '2048',
  #                   'expiration': 'Oct 16 23:59:59 2017 GMT',
  #                   'publicKeyType': 'RSA'},
  #  'city': 'Somerville',
  #  'commonName': 'www.example.com',
  #  'country': 'US',
  #  'fullPath': '/Common/example_com.crt',
  #  'generation': 1,
  #  'kind': 'tm:sys:crypto:cert:certstate',
  #  'name': 'example_com.crt',
  #  'organization': 'College University,street=169 Main Street',
  #  'ou': 'College Technology Services',
  #  'partition': 'Common',
  #  'selfLink':
  #                   'https://localhost/mgmt/tm/sys/crypto/cert/~Common~example_com.crt?ver=11.5.3',
  #  'state': 'Massachusetts,postalCode=02144',
  #  'subjectAlternativeName': 'DNS:example.com, DNS:www.example.com'}

  """
  global f5rest_url
  return (get_f5json(f5rest_url + 'sys/crypto/cert'))


###########################
###########################


if __name__ == "__main__":

  global hostname
  global password
  global f5rest_url
  
  parse_commandline_options()
  f5rest_url = 'https://%s/mgmt/tm/' % hostname


  # set up the actual http session.
  f5rest_session = requests.session()
  f5rest_session.auth = (username, password)
  f5rest_session.verify = False
  f5rest_session.headers.update({'Content-Type': 'application/json'}) 

  # get list of all pools
  # pooljson = get_pools()

  # this sets up a list of the links to the pools
  # poollinks = []

  # for x in pooljson['items']:
  #   poollinks.append(trim_url(x['selfLink']))



  #get list of all virtual servers
  vsjson = get_virts()

  for myvirtualserver in vsjson['items']:
    print "---------"
    vsname = ""
    vsrules = ""
    vsdest = ""
    vsmask = ""
    vsprofiles = ""
    try:
      vsname = myvirtualserver['name']
    except:
      vsname = "no name"

    try:
      vsdest = myvirtualserver['destination']
      vsmask = myvirtualserver['mask']
    except:
      vsdest = 'no destination'
      vsmask = ''

    try:
      vsrules = myvirtualserver['rules']
    except:
      vsrules = 'no irules listed'

    print 'Virtual server', vsname, vsdest, vsmask, 
    try:
      list_poolmembers('ltm/pool/'+(string.replace(myvirtualserver['pool'],'/','~')))
    except:
      print 'no default pool'
    print "  iRules: ", vsrules
    try:
      myjsonprofiles = get_profiles(myvirtualserver['profilesReference']['link'])
      vsprofiles = list_profiles(myjsonprofiles)
    except:
      vsprofiles = "no profiles applied?"
    print "  Profiles applied to virtual server: ", vsprofiles
