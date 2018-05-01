#!/usr/local/bin/python3
#This script (Requires Python >= 3.x) translates pix/asa access-list and their associated objects into afm
#The afm ruleset is left to the admin to assign how they choose, this translates and builds all rulesets and the associated objects only
#There are no plans to translate the rest of the cisco config, as the acls and objects are usually 90% + of the config. Nat rules are not supported or planned
#of course each asa/pix implementation will vary
#Usage: python asatoafm.py <pix or asa config> (the script should run in 1 sec or so, even w/ thousands of acls, depending on the host machine
#NOTE: the resulting file will be in the output dir in the form ipv6.pix-2013-8-4-20-2-19.tmsh, you will need to a sanity check
#To import into tmos do (copying and pasting large files skips some commands, resulting in errors, go idea to backup your config before importing):
# tmsh < <asa_pix_filename>.pix-2013-8-4-20-2-19.tmsh (imports can take some time, depending on the size)
#The firewall can be completed cleaned of any imported from a file converted by this script using:
#tmsh delete /security firewall rule-list all
#tmsh delete /security firewall port-list all
#tmsh delete /security firewall address-list all
#You may get warnings about services already existing, this is normal and can be ignored. Such as
#[admin@bigip191:Active:Standalone] tmp # tmsh < objects.pix-2013-8-25-0-7-17.tmsh 
#01020066:3: The requested Firewall IP port list entry (/Common/radius-udp 1812 1813) already exists in partition Common.
#Some example configs are located here: http://www.cisco.com/en/US/products/ps6120/prod_configuration_examples_list.html
#Standard distro of python is all that is required, requires Python 3.x, nothing fancy afaik :)
#Revision: 0.1 Alpha (This is currently experimental, please report issues to ryan.johnson@f5.com)
#Last updated: 2017-5-12

#Features
#Currently translated are the following
#asa/pix names such as name 24.222.31.32 mhart-officelan, cisco names in objects groups
#Network, Icmp and Service objects, NOTE that afm does not support icmp object, currently there is a SF idea for this
#Network, Icmp and Service objects in acls, Note that icmp acl w/ object groups are expanded into the codes that are contained
#in the object groups, since afm does not support icmp object groups
#Ipv6 preliminary support for icmp, tcp, udp and any other ip protocol

#Yet to be implemented
#Types of acls that are not supported: Sctp acls, acls that contain ipv6 network objects
#Service object groups w/ multiple protocols
# object-group service TCP_UDP_26000 tcp-udp

#Todos
#Move to named regex, provide easier reading, more importantly provide a better way of detecting matching. Some of this has been completed, just a nice to have, much more readable
#Test and work icmp v6 (object groups and acl)

#What needs work? possibly other ip protocols that afm may or may not support, just need to look into this

#Need to look at interface rules, access-list inetdmz-in extended permit icmp interface inetdmz any 
#any to 1-65535?
#Still need to add other ip protocols
#For tracing/debugging
#python3 -m trace --trace --ignore-module=re,str,fileinput,inspect,sre_parse,posix,sre_compile,posixpath,linecache,genericpath asatoafm.py ipprotoobjectgroup.txt 
 

from asatoafm_config import *

#Good for large files, after line is read, the line is taken out of memory
import fileinput
import os
import re
import sys
import datetime
from pprint import pprint
#debugging
from inspect import currentframe, getframeinfo
import pdb

#Require Python v3 or greater
if sys.version_info[:3] < (3,0,0):
    print('requires Python >= 3.0.0')
    sys.exit(1)

#Global variables
portMappingHash = {}
ciscoIcmpMappingHash = {}
ciscoConfFileHash = {}
ciscoConfFileList = []

#Original                         1                  2			3					4		
#aclRegex = '^\s*[ipv6]*\s*access-list ([0-9a-zA-Z\_\-]+)\s*(extended)*\s*(permit|deny) (ip|tcp|udp|icmp|[0-9]+|gre|icmp6)'
#aclRegex = '^\s*[ipv6]*\s*access-list ([0-9a-zA-Z\_\-]+)\s*(extended)*\s*(permit|deny) (ip|icmp|igmp|ggp|ipencap|st2|tcp|cbt|egp|igp|bbn-rcc|nvp|pup|argus|emcon|xnet|chaos|udp|mux|dcn|hmp|prm|xns-idp|trunk-1|trunk-2|leaf-1|leaf-2|rdp|irtp|iso-tp4|netblt|mfe-nsp|merit-inp|sep|3pc|idpr|xtp|ddp|idpr-cmtp|tp++|il|ipv6|sdrp|ipv6-route|ipv6-frag|idrp|rsvp|gre|mhrp|bna|esp|ah|i-nlsp|swipe|narp|mobile|tlsp|skip|ipv6-icmp|ipv6-nonxt|ipv6-opts|cftp|sat-expak|kryptolan|rvd|ippc|sat-mon|visa|ipcv|cpnx|cphb|wsn|pvp|br-sat-mon|sun-nd|wb-mon|wb-expak|iso-ip|vmtp|secure-vmtp|vines|ttp|nsfnet-igp|dgp|tcf|eigrp|ospf|sprite-rpc|larp|mtp|ax|ipip|micp|scc-sp|etherip|encap|gmtp|ifmp|pnni|pim|aris|scps|qnx|a|ipcomp|snp|compaq-peer|ipx-in-ip|vrrp|pgm|l2tp|ddx|iatp|st|srp|uti|smp|sm|ptp|isis|fire|crtp|crdup|sscopmce|iplt|sps|pipe|sctp|fc|divert|icmp6)'
#protocolobject aclRegex = '^\s*[ipv6]*\s*access-list (?P<aclname>[0-9a-zA-Z\_\-]+)\s*(?P<extended>extended)*\s*(?P<permitdeny>permit|deny) (?P<ipproto>object-group\s+[a-z0-9A-Z\-\_\.]+|ip|icmp|igmp|ggp|ipencap|st2|tcp|cbt|egp|igp|bbn\-rcc|nvp|pup|argus|emcon|xnet|chaos|udp|mux|dcn|hmp|prm|xns\-idp|trunk\-1|trunk\-2|leaf\-1|leaf\-2|rdp|irtp|iso\-tp4|netblt|mfe\-nsp|merit\-inp|sep|3pc|idpr|xtp|ddp|idpr\-cmtp|tp\+\+|il|ipv6|sdrp|ipv6\-route|ipv6\-frag|idrp|rsvp|gre|mhrp|bna|esp|ah|i\-nlsp|swipe|narp|mobile|tlsp|skip|ipv6\-icmp|ipv6\-nonxt|ipv6\-opts|cftp|sat\-expak|kryptolan|rvd|ippc|sat\-mon|visa|ipcv|cpnx|cphb|wsn|pvp|br\-sat\-mon|sun\-nd|wb\-mon|wb\-expak|iso\-ip|vmtp|secure\-vmtp|vines|ttp|nsfnet\-igp|dgp|tcf|eigrp|ospf|sprite\-rpc|larp|mtp|ax|ipip|micp|scc\-sp|etherip|encap|gmtp|ifmp|pnni|pim|aris|scps|qnx|a|ipcomp|snp|compaq\-peer|ipx\-in\-ip|vrrp|pgm|l2tp|ddx|iatp|st|srp|uti|smp|sm|ptp|isis|fire|crtp|crdup|sscopmce|iplt|sps|pipe|sctp|fc|divert|icmp6)'
aclRegex = '^\s*[ipv6]*\s*access-list (?P<aclname>[0-9a-zA-Z\_\-]+)\s*(?P<extended>extended)*\s*(?P<permitdeny>permit|deny) (?P<ipproto>object-group\s+[A-Za-z0-9\-\_\.]+|ip|icmp|igmp|ggp|ipencap|st2|tcp|cbt|egp|igp|bbn\-rcc|nvp|pup|argus|emcon|xnet|chaos|udp|mux|dcn|hmp|prm|xns\-idp|trunk\-1|trunk\-2|leaf\-1|leaf\-2|rdp|irtp|iso\-tp4|netblt|mfe\-nsp|merit\-inp|sep|3pc|idpr|xtp|ddp|idpr\-cmtp|tp\+\+|il|ipv6|sdrp|ipv6\-route|ipv6\-frag|idrp|rsvp|gre|mhrp|bna|esp|ah|i\-nlsp|swipe|narp|mobile|tlsp|skip|ipv6\-icmp|ipv6\-nonxt|ipv6\-opts|cftp|sat\-expak|kryptolan|rvd|ippc|sat\-mon|visa|ipcv|cpnx|cphb|wsn|pvp|br\-sat\-mon|sun\-nd|wb\-mon|wb\-expak|iso\-ip|vmtp|secure\-vmtp|vines|ttp|nsfnet\-igp|dgp|tcf|eigrp|ospf|sprite\-rpc|larp|mtp|ax|ipip|micp|scc\-sp|etherip|encap|gmtp|ifmp|pnni|pim|aris|scps|qnx|a|ipcomp|snp|compaq\-peer|ipx\-in\-ip|vrrp|pgm|l2tp|ddx|iatp|st|srp|uti|smp|sm|ptp|isis|fire|crtp|crdup|sscopmce|iplt|sps|pipe|sctp|fc|divert|icmp6)'


#Nested acl examples, where action is below access-list declaration. These are turned into rule lists in afm
#ip access-list standard monitor
#permit 10.5.1.29
#!
#ip access-list extended atm-corp
# permit gre 3.1.1.0 0.0.0.7 host 10.74.253.230
nestedAclRegex = '^\s*(?P<ipversion>ip|ipv6)\s*access-list\s*(?P<extended>standard|extended)*\s*(?P<aclname>[0-9a-zA-Z\_\-]+)'
nestedAclActionRegex = '^\s*(?P<permitdeny>permit|deny)'

aclIpv6StartRegex = '^\s*[ipv6]'
aclStartRegex = '^\s*[ipv6]*\s*access-list'

#                         5                                      6                                                                                 7                                                                                                                       8       9
noPortRegex = ' (\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|any|host \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*)+ (\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|any|host \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*)+\s*(log)*\s*(?P<loglevel>\d+)*'
#                      5                                                                                              6                                                                                                    7                                                                                             not grouped      8       9
icmpRegex = ' (\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|any|host \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*)+ (\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|any|host \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*)+\s*(object\-group [A-Za-z0-9\-\_]+|[A-Za-z\-\_]+(?=\s+log|\s*$))*\s*(log)*\s*(\d)*'
ipv6Regex = '([0-9A-Fa-f\:]+)\/([0-9]*)'


#					5		source ip																							                              6 sport																						       7 destination ip																					                                                            8 dest port																																			                                          9 log  10 log level

tcpUdpRegex = ' (?P<sourceip>any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_\.]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*|host [0-9A-Fa-f\:]+)\s*(?P<sourceport>range [a-zA-Z0-9]+ [a-zA-Z0-9]+|deq [A-Za-z0-9\-]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+)*\s*(?P<destinationip>any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_\.]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*|host [0-9A-Fa-f\:]+)\s*(?P<destinationport>eq \d+|range [a-zA-Z0-9]+ [a-zA-Z0-9]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+|object\-group [A-Za-z0-9\-\_\.]+)*\s*(?P<loggingenabled>log)*\s*(?P<loglevel>\d+)*\s*(?P<timerange>inactive|time-range\s+[A-Za-z0-9\-\_\.]+)*\s*(?P<inactive>)*'

###Protocol group associated regex
#Essentially the same as the tcpudp regex
#object-group protocol tcpudp
# protocol-object tcp
# protocol-object udp
protocolGroupAclRegex = ' (?P<sourceip>any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_\.]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(?P<sourceport>eq \d+|range [a-zA-Z0-9]+ [a-zA-Z0-9]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+|object\-group [A-Za-z0-9\-\_\.]+)*\s*(?P<destinationip>any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_\.]+|object [A-Za-z0-9\-\_\.]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(?P<destinationport>eq \d+|range [a-zA-Z0-9]+ [a-zA-Z0-9]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+|object\-group [A-Za-z0-9\-\_\.]+)*\s*(?P<logging>log)*\s*(\d+)*\s*(?P<timerange>inactive|time-range\s+[A-Za-z0-9\-\_\.]+)*\s*(?P<inactive>)*'
#Used to extract the name of the ip protocol group
protocolGroupNameRegex = 'object-group\s+(?P<ipprotogroupname>[A-Za-z0-9\-\_\.]+)'
#Regex to extract the name of the protocol object contained w/in the protocol group
protocolObjectNameRegex = ' protocol-object\s+(?P<protocolobjectname>[A-Za-z0-9\-\_\.]+)'
inProtocolGroupObjectRegex = '^object\-group\s+protocol\s+([A-Za-z0-9\-\_\.]+)'
protocolObjectRegex = '^\s+protocol\-object\s+(?P<protoname>[A-Za-z0-9\-\_\.]+)'
protocolGroupObjectDescriptionRegex = '\s+description\s+([A-Za-z0-9\-\_\s\.]+)'
protocolGroupObjectRegex = '^\s+group\-object\s+(?P<objectname>[A-Za-z0-9\-\_\.]+)'
###End of Protocol group associated regex

#Before dot in object-group
#tcpUdpRegex = ' (any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(range [a-zA-Z0-9]+ [a-zA-Z0-9]+|deq [A-Za-z0-9\-]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+)*\s*(any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(eq \d+|range [a-zA-Z0-9]+ [a-zA-Z0-9]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+|object\-group [A-Za-z0-9\-\_\.]+)*\s*(log)*\s*(\d+)*\s*(?P<timerange>inactive|time-range\s+[A-Za-z0-9\-\_\.]+)*\s*(?P<inactive>)*'
#Before timerange
#tcpUdpRegex = ' (any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(range [a-zA-Z0-9]+ [a-zA-Z0-9]+|deq [A-Za-z0-9\-]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+)*\s*(any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(eq \d+|range [a-zA-Z0-9]+ [a-zA-Z0-9]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+|object\-group [A-Za-z0-9\-\_]+)*\s*(log)*\s*(\d+)*\s*'
#tcpUdpRegex = ' (any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(range [a-zA-Z0-9]+ [a-zA-Z0-9]+|deq [A-Za-z0-9\-]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+|any)*\s*(any|host \d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|object\-group [A-Za-z0-9\-\_]+|[0-9A-Fa-f\:]+\/[0-9]*)\s*(eq \d+|range [a-zA-Z0-9]+ [a-zA-Z0-9]+|gt [A-Za-z0-9\-]+|lt [A-Za-z0-9\-]+|eq [A-Za-z0-9\-]+|any|object\-group [A-Za-z0-9\-\_]+)*\s*(log)*\s*(\d+)*\s*'
justAccessListRegex = '^\s*access-list'
portMappingFileRegex = '([A-Za-z0-9\-]+)\s+([0-9]+[0,5])\/((tcp|udp)+)'

createRuleListString = 'create /security firewall rule-list '
modifyRuleListString = 'modify /security firewall rule-list '

ipAndNetmaskRegex = '(\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+\/[0-9]+)\s*(\d+\.\d+\.\d+\.\d+)*'
nameAndNetmaskRegex = '(?P<name>[A-Za-z0-9\-\_\.]+)\s+(?P<netmask>\d+\.\d+\.\d+\.\d+)'
hostAndIpRegex = '(host)\s+(\d+\.\d+\.\d+\.\d+)'
hostAndIpv6Regex = '(host)\s+(?P<ipv6address>[0-9A-Fa-f\:]+)'
hostAndNameRegex = '(host)\s+([A-Za-z0-9\-\_\.]+)'
networkGroupObjectLineRegex = '^\s*group-object\s+([A-Za-z0-9\-\_\.]+)'

inServiceObjectGroupRegex ='^object\-group\s+service\s+(?P<name>[A-Za-z0-9\-\_\.]+)\s+(?P<proto>tcp|udp)'


		

#For tcp/udp acl to detect if the port value is a range
portRangeRegex = 'range\s+([a-zA-z0-9]+)\s+([a-zA-Z0-9]+)'
portRangeObjectRegex = '\s+port\-object\s+range\s+([a-z0-9A-Z\-]+)\s+([a-z0-9A-Z\-]+)'
portObjectRegex = '\s+port\-object\s+(?P<quantifier>eq|gt|lt|range)\s+(?P<port1>[a-z0-9A-Z\-]+)\s*(?P<port2>[a-z0-9A-Z\-]*)'
portQuantifierRegex = '(eq|lt|gt|deq)\s+([a-z0-9A-Z\-]+)'
portSingleObjectRegex =  '\s+port\-object\s+(eq|gt|lt)\s+([a-z0-9A-Z\-]+)'
aclRemarkRegex = 'access-list\s+([a-z0-9A-Z\-\_\.]+)\s+remark(.*)'

#object-group network DMZ_PROD_VLANS
# group-object DMZ_EXTSVC
# network-object host 192.5.73.3
# network-object 172.26.249.0 255.255.255.0
# network-object object vvomaddc01.prod.vegas.com
# description "Prod"
objectGroupRegex = 'object\-group\s+([a-z0-9A-Z\-\_\.]+)'
#Descriptions do not have "" in cisco, if we get those, it causes issues in afm
objectGroupDescriptionRegex = '\s+description\s+(?P<description>[A-Za-z0-9\-\_\s\.]+)'
ipAndNetmaskRegexNetworkObject = '\s*network\-object\s+(\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+\/[0-9]+)\s*(\d+\.\d+\.\d+\.\d+)*'
nameAndNetmaskRegexNetworkObject = '\s*network\-object\s+([A-Za-z0-9\-\_\.]+)\s+(\d+\.\d+\.\d+\.\d+|[0-9]+)'
hostAndIpRegexNetworkObject = '\s*network\-object\s+(host)\s+(\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+)'
hostAndNameRegexNetworkObject = '\s*network\-object\s+(host)\s+([A-Za-z0-9\-\_\.]+)'
inNetworkObjectGroupRegex ='^object\-group\s+network\s+([A-Za-z0-9\-\_\.]+)'
networkObjectRegex = '^\s*network\-object\s+(host\s+\d+\.\d+\.\d+\.\d+|host\s+[A-Za-z0-9\-\_]+|\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+|[A-Za-z0-9\-\_\.]+\s+\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+\/[0-9]*|host [0-9A-Fa-f\:]+)'
networkGroupObjectRegex = '^\s+group\-object\s+([A-Za-z0-9\-\_\.]+)'
networkObjectObjectRegex = '^\s+network\-object\s+object\s+(?P<objectname>[A-Za-z0-9\-\_\.]+)'
objectObjectRegex = 'object\s+(?P<objectname>[A-Za-z0-9\-\_\.]+)'
objectGroupStartRegex='\s*object-group'

objectGroupNetworkStartRegex='\s*object\-group\s*network'
networkObjectLineRegex='\s*network-object\s+object'


portGroupObjectRegex='^\s+group\-object\s+(?P<objectname>[A-Za-z0-9\-\_\.]+)'

#object network PROD-networks
# subnet 172.24.10.0 255.255.255.0
# description Created during name migration
#object network vdcnetap01.corp.vegas.com
# host 10.25.16.82
objectNetworkRegex = 'object\s+network\s+([a-z0-9A-Z\-\_\.]+)'
objectNetworkDescriptionRegex = '\s+description\s+([A-Za-z0-9\-\_\s]+)'
ipAndNetmaskRegexObjectNetwork = '\s*subnet\s+(?P<ipaddr>\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+\/[0-9]+)\s*(?P<netmask>\d+\.\d+\.\d+\.\d+)*'
hostAndIpRegexObjectNetwork = '\s*(host)\s+(?P<ipaddr>\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+)'
rangeRegexObjectNetwork = '\s*range\s+(?P<ipaddr1>\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+)\s+(?P<ipaddr2>\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+)'
inObjectNetworkRegex = 'object\s+network\s+([a-z0-9A-Z\-\_\.]+)'
objectNetworkStartRegex = 'object\s+'

#time-range 1wk_SFTP
# absolute end 23:59 14 June 2013
#time-range TEMP_24HR
# absolute end 23:59 07 June 2011
# periodic daily 0:00 to 23:59
#!
#time-range TEMP_72
# absolute start 12:24 16 November 2009 end 12:24 19 November 2009
#!
#time-range Titan_LDAP
# periodic Monday 9:30 to 10:30
inTimeRangeRegex = 'time-range\s+(?P<timeRangeName>[a-z0-9A-Z\-\_\.]+)'
timeRangeAclRegex = '(?P<inactive>inactive)|time-range\s+(?P<timerange>[A-Za-z0-9\-\_\.]+)'
#regex where both start and end are specified
absoluteTimeRangeTwoRegex = '^\s*absolute\s+(?P<startend1>end|start)\s+(?P<time1>\d+\:\d+)\s+(?P<date1>\d+)\s+(?P<month1>[A-Za-z]+)\s+(?P<year1>\d+)\s+(?P<startend2>end|start)\s+(?P<time2>\d+\:\d+)\s+(?P<date2>\d+)\s+(?P<month2>[A-Za-z]+)\s+(?P<year2>\d+)$'
#regex where either start or end are specified
absoluteTimeRangeOneRegex = '^\s*absolute\s+(?P<startend1>end|start)\s+(?P<time1>\d+\:\d+)\s+(?P<date1>\d+)\s+(?P<month1>[A-Za-z]+)\s+(?P<year1>\d+)$'
periodicTimeRangeRegex = '\s*periodic\s+(?P<days>(weekdays\s*|weekend |daily |Monday |Tuesday |Wednesday |Thursday |Friday |Saturday |Sunday )+)(?P<time1>\d+\:\d+)\s+to\s+(?P<time2>\d+\:\d+)'

#For limiting logging to timeRange
timeRangeStartRegex = '\s*time-range'
#Name appended to schedule name when there are more than 1 periodic time
scheduleObjectAfmName = 'script_'

ciscoPortMapFileRegex = '\s*([A-Za-z0-9\-]+)\s+(\d+)'
ciscoIcmpMappingFileRegex = '([A-Za-z0-9\-\_]+)\s*([0-9]+)'

inIcmpObjectGroupRegex ='^\s*object\-group\s+icmp\-type\s+([A-Za-z0-9\-\_]+)'
icmpObjectRegex='\s*icmp-object\s+([A-Za-z0-9\-\_]+)'

nameRegex = '^name\s+(?P<ipaddress>\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f\:]+\/[0-9]*)\s+(?P<name>[A-Za-z0-9\-\_\.]+)\s*(?P<description>description)*\s*(?P<other>.*)' 

ipv6HostAddressRegex='(?P<ipaddr>[0-9A-Fa-f]+\:[0-9A-Fa-f\:]+)'
ipv6AddressAndNetmaskRegex='(?P<ipaddr>[0-9A-Fa-f\:]+\/[0-9]+)'
justIpRegex = '(\:|\d+\.\d+\.\d+\.\d+|any|2001|[0-9A-Fa-f\:]+)'
groupedIpRegex='(\d+)\.(\d+)\.(\d+)\.(\d+)'
justNameRegex = '([A-Za-z0-9\-\_]+)'

emptyLineRegex = '^$|^\s+$'

###Pre execution
if len(sys.argv) > 1:

	ciscoAclFile=sys.argv[1]
	
else:
    
    print('Error requires cisco acl file as first argument')
    sys.exit()
###End of pre execution

#BEGIN Classes

#Object to hold a line of text that is an acl
class aclLine():

	def __init__(self,line,linenumber):
	
		log("IN class aclLine contstructor 1.\n",1)

		self.line = line
		self.linenumber = linenumber
	
	
#Class to handle acl that have ports, tcp, udp, sctp, ie
#access-list acl_outside extended permit udp 56.72.7.106 255.255.255.254 eq netbios-ns 56.81.167.106 255.255.255.254 eq netbios-ns 	
class tcpUdpAcl():

	def __init__(self,name):
	
		log("IN class tcpUdpAcl contstructor 1.",1)

		self.ciscoName = name
		self.afmName = name
	
	def __init__(self,name,action,protocol,source,sourcePort,destination,destinationPort,line,remark,ciscoPortMapDictionary,loggingenabled,loglevel,aclTimeRange,isIpv6,lineNumber):
		
		log("IN class tcpUdpAcl contstructor 2.",1)
		
		self.ciscoLine = line
		
		self.lineNumber = lineNumber
		
		#Set acl names
		self.ciscoName = name
		self.afmName = name
		
		#Set acl protocols
		self.ciscoProtocol = protocol
		self.afmProtocol = protocol
		
		#Set Remarks
		if remark: 
		
			self.ciscoRemark = remark
			self.afmRemark = remark.replace('\"','')
		
		else:
		
			self.ciscoRemark = " "
			self.afmRemark = " "
		
		#Set actions
		self.ciscoAction = action
		self.afmAction = returnAfmAction(self.ciscoAction)
								
		#Set source
		self.ciscoSource = source
		self.afmSource = returnAfmDestinationSource(self.ciscoSource)
		
		#Set destination
		self.ciscoDestination = destination
		self.afmDestination = returnAfmDestinationSource(self.ciscoDestination)
		
		#Set source port
		self.ciscoSourcePort = sourcePort
		self.afmSourcePort = returnAfmDestinationSourcePort(sourcePort,ciscoPortMapDictionary)
		
		#Set destination port
		self.ciscoDestinationPort = destinationPort
		self.afmDestinationPort = returnAfmDestinationSourcePort(destinationPort,ciscoPortMapDictionary)
		
		self.ciscoLoggingEnabled = loggingenabled
		self.afmLoggingEnabled = loggingenabled	
		self.ciscoLogLevel = loglevel
		
		#Schedule
		self.schedule = aclTimeRange
		
		self.inactive = ""
		self.isIpv6 = isIpv6
		
		log("IN class tcpUdpAcl contstructor 2 values:\n \
		ciscoLine" + self.ciscoLine \
		+ "Cisco name: " + self.ciscoName + "Afm name: " + self.afmName
		,1)
		
	def setTcpUdpAclLineNumber(self,lineNumber):
		
		self.lineNumber = lineNumber		
	
class protocolGroupAcl():

	def __init__(self,name):
	
		log("IN class protocolGroupAcl contstructor 1.",1)
	
		self.ciscoName = name
		self.afmName = name
		self.protocolGroupOriginallyNested = 0
		self.protocolGroupUnNested = 0
		self.nestedParentAclCiscoLine = ""
		self.ciscoLogLevel = ""

	def __init__(self,name,action,protocolGroupObjectName,protocolGroupObject,source,sourcePort,destination,destinationPort,line,remark,ciscoPortMapDictionary,loggingenabled,loglevel,aclTimeRange,isIpv6):
		
		log("IN class protocolGroupAcl contstructor 2.",1)

		self.hasNested = 0
		self.wasNested = 0
		self.nestedParentAclCiscoLine = ""
	
		self.ciscoLine = line
		#If this is a protocol group, set to 1, always should be, use this for checking to see what type of object it is
		self.isProtocolGroup = 1
		
		#Set acl names
		self.ciscoName = name
		self.afmName = name
		
		#Set acl protocol names
		self.ciscoProtocol = protocolGroupObjectName
		self.afmProtocol = protocolGroupObjectName
		
		#Set protocolGroupObject, looked up in convertProtocolGroupAclListToObjects
		self.protocolGroupObject = protocolGroupObject
		
		#Set Remarks
		if remark: 
		
			self.ciscoRemark = remark
			self.afmRemark = remark.replace('\"','')
		
		else:
		
			self.ciscoRemark = " "
			self.afmRemark = " "
		
		#Set actions
		self.ciscoAction = action
		self.afmAction = returnAfmAction(self.ciscoAction)
		log("IN class protocolGroupAcl contstructor 2 afmAction: " + self.afmAction,1)
							
		#Set source
		self.ciscoSource = source
		self.afmSource = returnAfmDestinationSource(self.ciscoSource)
		
		#Set destination
		self.ciscoDestination = destination
		self.afmDestination = returnAfmDestinationSource(self.ciscoDestination)
		
		#Set source port
		self.ciscoSourcePort = sourcePort
		afmSourcePortList = returnAfmDestinationSourcePort(sourcePort,ciscoPortMapDictionary)
		self.afmSourcePort = afmSourcePortList[0]
		
		#Set destination port
		self.ciscoDestinationPort = destinationPort
		afmDestinationPortList = returnAfmDestinationSourcePort(destinationPort,ciscoPortMapDictionary)
		self.afmDestinationPort = afmDestinationPortList[0]
	

		self.ciscoLoggingEnabled = loggingenabled
		self.afmLoggingEnabled = loggingenabled	
		self.ciscoLogLevel = loglevel
		
		#Schedule
		self.schedule = aclTimeRange
		
		self.inactive = ""
		self.isIpv6 = isIpv6	
		
		#needs to be tested
		self.ciscoAclTimeRange = aclTimeRange
		self.afmAclTimeRange = aclTimeRange
		
	#When Denesting pof cisco protocol (tcp/udp/sctp) group objects (afm does not support protocol group objects as of 11.6), we convert the protocolGroupAcl object variables into tcp/udp/sctp acls then use the writeTcpUdpPortAclListRules	
	#to write the resulting rules
	def convertProtocolGroupAclObjectToTcpUdpAclObjectList(self,ciscoPortMapDictionary):
	
		log("IN class protocolGroupAcl convertProtocolGroupAclObjectToTcpUdpAclObjectList().",1)
	
		tcpUdpAclObjectList = []
		protocolGroupAclObject = self
	
		for protocolObject in self.protocolGroupObject.protocolObjectList:
		
			protocol = protocolObject.afmName
		
			#source and destination port are lists access by [0], do we need to add logic to iterate thru list?					
			log("IN class protocolGroupAcl convertProtocolGroupAclObjectToTcpUdpAclObjectList for values:" + " afmName: " + self.afmName + " afmSourcePort: " + self.afmSourcePort[0] +  " afmDestinationPort: " + self.afmDestinationPort[0] + "\n",1)
			tcpUdpAclObject = tcpUdpAcl(self.afmName,self.ciscoAction,protocol,self.ciscoSource,protocolGroupAclObject.ciscoSourcePort,self.ciscoDestination,protocolGroupAclObject.ciscoDestinationPort,self.ciscoLine,self.afmRemark,ciscoPortMapDictionary,self.afmLoggingEnabled,self.ciscoLogLevel,self.afmAclTimeRange,self.isIpv6,self.lineNumber)
			tcpUdpAclObject.setTcpUdpAclLineNumber(protocolGroupAclObject.lineNumber)
			tcpUdpAclObjectList.append(tcpUdpAclObject)
	
		log("LEAVING class protocolGroupAcl convertProtocolGroupAclObjectToTcpUdpAclObjectList().",1)
	
		return tcpUdpAclObjectList			
			
class noPortAcl():
	
	def __init__(self,name):
		
		self.name = name
			
	def __init__(self,name,action,protocol,source,destination,line,remark,loggingenabled,loglevel,isIpv6):
		
		self.ciscoLine = line
		
		#Set acl names
		self.ciscoName = name
		self.afmName = name
		
		#Set acl protocols
		self.ciscoProtocol = protocol
		self.afmProtocol = protocol
		
		#Set Remarks
		if remark: 
			self.ciscoRemark = remark
			self.afmRemark = remark.replace('\"','')
		else:
			self.ciscoRemark = " "
			self.afmRemark = " "
			
		#Set actions
		self.ciscoAction = action
		self.afmAction = returnAfmAction(self.ciscoAction)
								
		#Set source
		self.ciscoSource = source
		self.afmSource = returnAfmDestinationSource(self.ciscoSource)
		
		#Set destination
		self.ciscoDestination = destination
		self.afmDestination = returnAfmDestinationSource(self.ciscoDestination)
		
		self.ciscoLoggingEnabled = loggingenabled
		self.afmLoggingEnabled = loggingenabled
		
		self.ciscoLogLevel = loglevel
		self.isIpv6 = isIpv6

		
class icmpAcl():
	
	def __init__(self,name):
		
		self.name = name
			
	def __init__(self,name,action,protocol,source,destination,line,icmptype,remark,loggingenabled,loglevel,isIpv6):
		
		self.ciscoLine = line
		
		#Set acl names
		self.ciscoName = name
		self.afmName = name
		
		#Set acl protocols
		self.ciscoProtocol = protocol
		
		if protocol == "icmp6":
		
			self.afmProtocol = "ipv6-icmp"
		
		else:
		
			self.afmProtocol = protocol
		
		#Set Remarks
		if remark: 
		
			self.ciscoRemark = remark
			self.afmRemark = remark.replace('\"','')
		
		else:
		
			self.ciscoRemark = " "
			self.afmRemark = " "
			
		#Set actions
		self.ciscoAction = action
		self.afmAction = returnAfmAction(self.ciscoAction)
								
		#Set source
		self.ciscoSource = source
		self.afmSource = returnAfmDestinationSource(self.ciscoSource)
		
		#Set destination
		self.ciscoDestination = destination
		self.afmDestination = returnAfmDestinationSource(self.ciscoDestination)
		
		#Set icmp type
		self.ciscoIcmpString = icmptype
		
		if icmptype:
		
			if re.match(objectGroupRegex,icmptype):
			
				if ICMPOBJECTSEXPAND == 1:
		
					self.afmIcmpString = icmptype
				
				else:
			
					self.afmIcmpString = re.match(inIcmpObjectGroupRegex,icmptype).group(1)
			
			else: 
				
				self.afmIcmpString = ciscoIcmpMappingHash[icmptype]
				
		else:
		
			self.afmIcmpString = "NULL"	
			
		self.ciscoLoggingEnabled = loggingenabled
		self.afmLoggingEnabled = loggingenabled
		
		self.ciscoLogLevel = loglevel
		self.isIpv6 = isIpv6


#Class to hold cisco service object to afm		
class serviceGroupObject():

	def __init__(self,name):
		
		self.ciscoName = name
		self.ciscoLine = ""
		self.afmName = name
		self.portObjectList = []
		self.description = ""
	
	def setDescription(self,description):
	
		self.description = description.rstrip()
		
	def setProtocol(self,protocol):
	
		self.protocol = protocol
		
	def appendPortObject(self,portObjectString,ciscoPortMapDictionary):
	
		portObject1 = portObject(portObjectString,ciscoPortMapDictionary)	
		self.portObjectList.append(portObject1)
		
#Class to hold cisco timerange objects
#Only 1 absolute range can exist
#Multiple periodic
class timeRangeObject():

	def __init__(self,name,ciscoTimeRangeString):
	
		self.ciscoName = name
		self.afmName = moveNumbersToEndOfString(name)
		self.ciscoTimeRangeString = ciscoTimeRangeString
		self.hasAbsoluteTime = 0
		#If the object has only one date
		self.hasAbsoluteTime1 = 0
		#If the object has two dates
		self.hasAbsoluteTime2 = 0
		self.hasPeriodicTime = 0
		self.periodicNumberOfLinesCheck = 0
		self.periodicNumberOfLines = 0
		self.periodicTimeRangeObjectList = []
		self.absoluteStartEnd1 = ""
		self.absoluteStartEnd2 = ""
		self.absoluteTime1 = ""
		self.absoluteTime2 = ""
		self.absoluteYear1 = ""
		self.absoluteYear2 = ""
		self.absoluteMonth1 = ""
		self.absoluteMonth2 = ""
		self.absoluteDate1 = ""
		self.absoluteDate2 = ""
		self.afmAbsoluteTime1String = ""
		self.afmAbsoluteTime2String = ""
		
class periodicTimeRangeObject():

	def __init__(self,startTime,endTime,dayString,ciscoString):
	
		self.startTime = startTime
		self.endTime = endTime
		self.dayString = dayString
		self.ciscoString = ciscoString
		self.afmName = ""
	
##Protocol objects
#object-group protocol tcpudp
# protocol-object tcp
# protocol-object udp	
#Class to hold and convert protocol lines to afm, which are contained in service objects
class protocolObject():

	def __init__(self,ciscoProtocolObjectString):
	
		log("IN class protocolObject constructor protocolObjectString: " + ciscoProtocolObjectString, 1)
		
		self.ciscoProtocolObjectString = ciscoProtocolObjectString
		matchProtocolObjectNameRegex = re.match(protocolObjectNameRegex,ciscoProtocolObjectString)
				
		if matchProtocolObjectNameRegex:
			
			self.protocol = matchProtocolObjectNameRegex.group('protocolobjectname')
			self.afmName = matchProtocolObjectNameRegex.group('protocolobjectname')
			
		else: 
		
			self.protocol = "UNDEFINED"
			self.afmName = "UNDEFINED"
			log("In class protocolObject constructor new object's protocol is undefined: " + self.ciscoProtocolObjectString,0)

		self.isObject = 0

#Class to hold and convert protocol lines to afm, which are contained in service objects	
class protocolGroupObject():

	def __init__(self,name):
		
		log("IN class protocolGroupObject constructor",1)
		
		self.ciscoName = name
		self.ciscoLine = ""
		self.afmName = name
		self.protocolObjectList = []
		self.description = ""
	
	def setDescription(self,description):
	
		self.description = description.rstrip()
		
	def setProtocol(self,protocol):
	
		self.protocol = protocol
		
	def appendProtocolObject(self,protocolObjectString):

		log("IN class protocolGroupObject appendProtocolObject() protocolObjectString: " + protocolObjectString, 1)

		protocolObject1 = protocolObject(protocolObjectString)	
		self.protocolObjectList.append(protocolObject1)
		
##End of Protocol objects
		
#Class to hold and convert port-object lines to afm, which are contained in service objects
class portObject():

	def __init__(self,ciscoPortString,ciscoPortMapDictionary):
	
		self.ciscoPortString = ciscoPortString
		self.portObjectList = []
		self.isObject = 0
				
		portSingleObjectRegexMatch = re.match(portSingleObjectRegex,ciscoPortString)
		portRangeObjectRegexMatch = re.match(portRangeObjectRegex,ciscoPortString)
		matchPortGroupObjectRegex = re.match(portGroupObjectRegex,ciscoPortString)

		if portSingleObjectRegexMatch:
		
			justDigitsInPort = re.match('^\d+$',portSingleObjectRegexMatch.group(2))
		
			if justDigitsInPort:
			
				self.afmPortString = justDigitsInPort.group(0)
			
			else:
			
				ciscoPort = portSingleObjectRegexMatch.group(2)
				#NEEDS to be changed
				self.afmPortString = ciscoPortMapDictionary[ciscoPort]
	
		elif portRangeObjectRegexMatch:
		
			self.afmPortString = returnAfmPortRange(portRangeObjectRegexMatch.group(1),portRangeObjectRegexMatch.group(2),ciscoPortMapDictionary)
			
		elif matchPortGroupObjectRegex:
		
			self.afmPortString = matchPortGroupObjectRegex.group('objectname')
			self.isObject = 1
			log("In class portObject new object is a service/port group object: " + self.ciscoPortString,1)
			
		else:
				
			self.afmPortString = "UNDEFINED"
			log("Exception in class portObject instantiation, string not converted: " + self.ciscoPortString,0)
			
class icmpGroupObject():

	def __init__(self,name):
	
		self.ciscoName = name
		self.afmName = name
		self.icmpObjectList = []
		self.description = ""

	def appendIcmpObject(self,icmpObjectString,nameObjectList):
	
		icmpObject1 = icmpObject(icmpObjectString,nameObjectList)	
		self.icmpObjectList.append(icmpObject1)
		
	def setDescription(self,description):
	
		self.description = description.rstrip()
		
class icmpObject():

	def __init__(self,ciscoIcmpString,nameObjectList):
				
		self.ciscoIcmpString = ciscoIcmpString
		
		matchIcmpObjectRegex = re.match(icmpObjectRegex,ciscoIcmpString)
		
		if matchIcmpObjectRegex:
		
			self.afmIcmpString = matchIcmpObjectRegex.group(1)
		
		else:
		
			self.afmIcmpString = "ICMPOBject class regex failed"
			log("ICMPOBject class regex failed: " + ciscoIcmpString,0)

##CBEGIN Classes

#Name object class holds name ip <name> <description>
#name 172.16.100.28 GWC-0.BARIONSRDS0 description Barrie CS2K RMGC
class nameObject():

	def __init__(self,networkHost,name,ciscoLine):
	
		self.afmNetworkString = networkHost
		self.name = name
		self.ciscoName = name
		self.description = ""
		self.afmName = name
		self.ciscoLine = ciscoLine
		
	def setDescription(self,description):
	
		self.description = description
		
	def setLineNumber(self,lineNumber):
	
		self.setLineNumber = lineNumber		

#Class to handle object-groups which is built of networkObject classes
#object-group network internet-radius-allowed
# network-object 10.0.0.0 255.0.0.0
# network-object host 76.11.59.242
# network-object internet-servers 255.255.255.0	
# network-object object vvpintap02.lasvegas.com			
class networkGroupObject():

	def __init__(self,name,line):
	
		self.ciscoName = name
		self.afmName = name
		
		#For
		# network-object 10.0.0.0 255.0.0.0
		# network-object host 76.11.59.242
		self.networkObjectList = []
		
		#For
		#object network objectnetwork1
 		# host 172.26.6.1
		self._objectNetworkList = []
		self.description = ""
		self.ciscoLine = line
		
	#object-group network cli_SVC_CIC_ALL
 	#network-object host 172.26.248.20
	def appendNetworkObject(self,networkObjectString,nameObjectList):
	
		networkObject1 = networkObject(networkObjectString,nameObjectList)	
		self.networkObjectList.append(networkObject1)
		
	#object-group network DM_INLINE_NETWORK_6
 	#group-object srv_WS.CYLLENIUS.COM
 	#group-object srv_WS.LASVEGAS.COM	
	def appendGroupObject(self,networkObjectString,nameObjectList):
		
		networkObject1 = networkObject(networkObjectString,nameObjectList)	
		networkObject1.setIsNetworkGroupObject()
		self.networkObjectList.append(networkObject1)
	
	#object-group network srv_GOOGLE_NOTIFICATIONS
 	#network-object object google_network01
 	#network-object object google_network02
	def appendNetworkObjectObject(self,networkObjectString,objectNetworkObjectList,isFromNetworkObjectGroup):
	
		log("In class networkGroupObject appendNetworkObjectObject\n",1)
	
		self.isFromNetworkObjectGroup = 1
		matchNetworkObjectObjectRegex = re.match(networkObjectObjectRegex,networkObjectString)
				
		if matchNetworkObjectObjectRegex:
		
			afmName = matchNetworkObjectObjectRegex.group('objectname')
			#networkObjectObject1 = objectNetworkObject(afmName,objectNetworkObjectList)
			networkObjectObject1 = objectNetworkObject(afmName,networkObjectString)

			self.networkObjectObjectList.append(networkObjectObject1)
			log("In class networkGroupObject appendNetworkObjectObject networkobjectobject is: " + networkObjectObject1 .afmName + "\n",1)

	#replacement for appendNetworkObjectObject, needed to have this append the real object as found by readFirewallFileToObjectNetworkObjectList()
	#object-group network srv_GOOGLE_NOTIFICATIONS
 	#network-object object google_network01
 	#network-object object google_network02
	def appendNetworkObjectObject2(self,networkObjectObject):
	
		log("In class networkGroupObject appendNetworkObjectObject2\n",1)
		self.networkObjectObjectList.append(networkObjectObject)
		log("In class networkGroupObject appendNetworkObjectObject2 networkobjectobject is: " + networkObjectObject.afmName + "\n",1)

	def setDescription(self,description):
	
		self.description = description.rstrip()
		
#Class to handle network-objects w/in object-group
#object-group network internet-radius-allowed
# network-object 10.0.0.0 255.0.0.0
# network-object host 76.11.59.242
# network-object internet-servers 255.255.255.0	
# network-object object vvpintap02.lasvegas.com	
class networkObject():

	def __init__(self,ciscoNetworkString,nameObjectList):
		
		self.ciscoNetworkString = ciscoNetworkString
		self.ciscoLine = ciscoNetworkString
		self.isNetworkGroupObject = 0
		
		ipAndNetmaskRegexMatch = re.match(ipAndNetmaskRegexNetworkObject,ciscoNetworkString)
		nameAndNetmaskRegexMatch = re.match(nameAndNetmaskRegexNetworkObject,ciscoNetworkString)
		hostAndIpRegexMatch = re.match(hostAndIpRegexNetworkObject,ciscoNetworkString)
		hostAndNameRegexMatch = re.match(hostAndNameRegexNetworkObject,ciscoNetworkString)
		networkGroupObjectLineRegexMatch = re.match(networkGroupObjectLineRegex,ciscoNetworkString)
				
		if networkGroupObjectLineRegexMatch:
		
			self.afmNetworkString = networkGroupObjectLineRegexMatch.group(1)
			self.isNetworkGroupObject = 1
		
		elif hostAndIpRegexMatch:
						
			self.afmNetworkString =  hostAndIpRegexMatch.group(2) + "/32"
			
		elif hostAndNameRegexMatch:
			
			nameToIp = str(findNetworkHostFromNameObjectList(hostAndNameRegexMatch.group(2),nameObjectList))
			self.afmNetworkString =  nameToIp + "/32"
			
		elif ipAndNetmaskRegexMatch:
					
			ipv6AddressAndNetmaskRegexMatch = re.match(ipv6AddressAndNetmaskRegex,ipAndNetmaskRegexMatch.group(1))
			
			#network-object is ipv6			
			if ipv6AddressAndNetmaskRegexMatch :
			
				self.afmNetworkString =  ipv6AddressAndNetmaskRegexMatch.group(1) + "/" + ipv6AddressAndNetmaskRegexMatch.group(2)
					
			#network-object is ipv4
			else:
			
				self.afmNetworkString =  ipAndNetmaskRegexMatch.group(1) + "/" + ipAndNetmaskRegexMatch.group(2)
			
		elif nameAndNetmaskRegexMatch:
				
			nameToIp = str(returnNetworkHostFromNameObjectList(nameAndNetmaskRegexMatch.group(1),nameObjectList))
			self.afmNetworkString =  nameToIp + "/" + nameAndNetmaskRegexMatch.group(2)	
			
		else:
		
			readFirewallFileToNetworkObjectList
			
	def setIsNetworkGroupObject(self): 
	
		self.isNetworkGroupObject = 1

#Class that holds object network types
#object network 66.238.46.193
# host 66.238.46.193
# description just host
#object network testobject12
# range 1.1.1.2 1.1.1.3
# description range
#For some reason if I use objectNetwork, I get unbound local variable, so need the _ in front
class _objectNetwork():

	def __init__(self,name,ciscoNetworkString):
	
		self.ciscoName = name
		self.afmName = name
		self.ciscoLine = ciscoNetworkString
		self.description = ""
		self.type = ""
		self.afmNetworkString = ""
		
	def setObjectNetworkAddress(self,ciscoNetworkString):
	
		ipAndNetmaskRegexMatch = re.match(ipAndNetmaskRegexObjectNetwork,ciscoNetworkString)
		hostAndIpRegexMatch = re.match(hostAndIpRegexObjectNetwork,ciscoNetworkString)
		rangeRegexMatch = re.match(rangeRegexObjectNetwork,ciscoNetworkString)
		log("In class objectNetworkObject function setObjectNetworkAddress cisco line: " + ciscoNetworkString + "\n",1)
		
		if hostAndIpRegexMatch:
				
			ipv6HostAddressRegexMatch = re.match(ipv6HostAddressRegex,hostAndIpRegexMatch.group('ipaddr'))
						
			if ipv6HostAddressRegexMatch:
			
				self.afmNetworkString = ipv6HostAddressRegexMatch.group('ipaddr')
				log("In class objectNetworkObject function setObjectNetworkAddress ipv6HostAddressRegexMatch afmNetworkString is: " + self.afmNetworkString + "\n",1)
			
			#Ipv4 host
			else:
						
				self.afmNetworkString =  hostAndIpRegexMatch.group('ipaddr') + "/32"
				log("In class objectNetworkObject function setObjectNetworkAddress ipv4 hostAndIpRegexMatch afmNetworkString is: " + self.afmNetworkString + "\n",1)
			
			log("In class objectNetworkObject function setObjectNetworkAddress hostAndIpRegexMatch afmNetworkString is: " + self.afmNetworkString + "\n",1)
			
		elif ipAndNetmaskRegexMatch:
					
			ipv6AddressAndNetmaskRegexMatch = re.match(ipv6AddressAndNetmaskRegex,ipAndNetmaskRegexMatch.group('ipaddr'))
			
			#network-object is ipv6			
			if ipv6AddressAndNetmaskRegexMatch:
			
				self.afmNetworkString =  ipv6AddressAndNetmaskRegexMatch.group('ipaddr')								
				log("In class objectNetworkObject function setObjectNetworkAddress ipAndNetmaskRegexMatch ipv6 afmNetworkString is: " + self.afmNetworkString + "\n",1)
					
			#network-object is ipv4
			else:
			
				self.afmNetworkString =  ipAndNetmaskRegexMatch.group('ipaddr') + "/" + ipAndNetmaskRegexMatch.group('netmask')		
		
				log("In class objectNetworkObject function setObjectNetworkAddress ipAndNetmaskRegexMatch ipv4 afmNetworkString is: " + self.afmNetworkString + "\n",1)
				
		elif rangeRegexMatch:
							
			self.afmNetworkString =  rangeRegexMatch.group('ipaddr1') + "-" + rangeRegexMatch.group('ipaddr2') + " {}"
			
			log("In class objectNetworkObject function setObjectNetworkAddress rangeRegexMatch afmNetworkString is: " + self.afmNetworkString + "\n",1)
	
	def setDescription(self,description,ciscoNetworkString):
	
		self.description = description.rstrip()
		self.ciscodescription = ciscoNetworkString	
#END of classes
	
def convertCiscoMonthToNumber(monthString):

	months = {'January' : '01', 'February' : '02', 'March' : '03', 'April' : '04', 'May' : '05', 'June' : '06', 'July' : '07', 'August' : '08', 'September' : '09', 'October' : '10', 'November' : '11', 'December' : '12'}
	
	return months[monthString]
	
#		
def convertIcmpAclListToObjects(icmpAclList,icmpAclObjectList,aclNameDict,firewallFileReadonlyList):

	fullIcmpRegex = aclRegex + icmpRegex
	lineCount = 0

	for aclLineObject in icmpAclList:
	
		isIpv6 = 0
		line = aclLineObject.line
		lineNumber = aclLineObject.linenumber
		matchAcl = re.match(fullIcmpRegex,line)
		
		matchAclIpv6StartRegex = re.match(aclIpv6StartRegex,line)
			
		if matchAclIpv6StartRegex:
			
			isIpv6 = 1
				
		else:
			
			isIpv6 = 0
		
		if matchAcl:
			
			aclName = matchAcl.group(1)
			
			#Add the acl name if its unique
			if not aclName in aclNameDict:
							
				aclNameDict.update({ aclName: 1 })
				
			#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
			else:
			
				aclNameDict[aclName] += 1	
				
			possibleRemark = firewallFileReadonlyList[lineNumber-1]
			aclRemark = ""		
				
			matchAclRemarkRegex = re.match(aclRemarkRegex,possibleRemark)
				
			if matchAclRemarkRegex:
			
				aclRemark = matchAclRemarkRegex.group(2)
				
			aclAction = matchAcl.group(3)
			aclProtocol = matchAcl.group(4)
			aclSource = matchAcl.group(5)
			aclDestination = matchAcl.group(6)
			icmpType = matchAcl.group(7)
			aclLine = line
			
			if matchAcl.group(8):
			
				aclLoggingEnabled = 1
				
			else:
			
				aclLoggingEnabled = 0
				
			if matchAcl.group(9):
			
				aclLogLevel = matchAcl.group(9)
				
			else:
			
				aclLogLevel = -1
									
			newObject = icmpAcl(aclName,aclAction,aclProtocol,aclSource,aclDestination,aclLine,icmpType,aclRemark,aclLoggingEnabled,aclLogLevel,isIpv6)
			icmpAclObjectList.append(newObject)	
			
		lineCount += 1		
		
def convertNoPortAclListToObjects(noPortAclList,noPortAclObjectList,aclNameDict,firewallFileReadonlyList):

	fullNoPortRegex = aclRegex + noPortRegex
		
	lineCount = 0

	for aclLineObject in noPortAclList:
		
		isIpv6 = 0
		line = aclLineObject.line
		lineNumber = aclLineObject.linenumber
		matchAcl = re.match(fullNoPortRegex,line)
		matchAclIpv6StartRegex = re.match(aclIpv6StartRegex,line)
			
		if matchAclIpv6StartRegex:
			
			isIpv6 = 1
				
		else:
			
			isIpv6 = 0
		
		if matchAcl:
		
			aclName = matchAcl.group(1)
			
			#Add the acl name if its unique
			if not aclName in aclNameDict:
							
				aclNameDict.update({ aclName: 1 })
				
			#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
			else:
			
				aclNameDict[aclName] += 1	
				
			possibleRemark = firewallFileReadonlyList[lineNumber-1]
			aclRemark = ""		
				
			matchAclRemarkRegex = re.match(aclRemarkRegex,possibleRemark)
				
			if matchAclRemarkRegex:
			
				aclRemark = matchAclRemarkRegex.group(2)
				
			aclAction = matchAcl.group(3)
			aclProtocol = matchAcl.group(4)
			aclSource = matchAcl.group(5)
			aclDestination = matchAcl.group(6)

			aclLine = line
			
			if matchAcl.group(8):
			
				aclLoggingEnabled = 1
				
			else:
			
				aclLoggingEnabled = 0
				
			if matchAcl.group('loglevel'):
			
				aclLogLevel = matchAcl.group(9)
				
			else:
			
				aclLogLevel = -1
						
			newObject = noPortAcl(aclName,aclAction,aclProtocol,aclSource,aclDestination,aclLine,aclRemark,aclLoggingEnabled,aclLogLevel,isIpv6)
			noPortAclObjectList.append(newObject)	
			
		lineCount += 1

def convertTcpUdpAclListToObjects(tcpUdpAclList,tcpUdpAclObjectList,aclNameDict,firewallFileReadonlyList,ciscoPortMapDictionary):

	log("In convertTcpUdpAclListToObjects()\n",1)
	print("In convertTcpUdpAclListToObjects()\n")


	fullTcpUdpRegex = aclRegex + tcpUdpRegex
	
	lineCount = 0

	#Run through tcpUdpAclList which is create from readAclToList
	for aclLineObject in tcpUdpAclList:
		print("In convertTcpUdpAclListToObjects is acl: " + aclLineObject.line)

		isIpv6 = 0
		line = aclLineObject.line
		lineNumber = aclLineObject.linenumber
		matchAcl = re.match(fullTcpUdpRegex,line)
		matchAclIpv6StartRegex = re.match(aclIpv6StartRegex,line)
			
		if matchAclIpv6StartRegex:
			
			isIpv6 = 1
				
		else:
			
			isIpv6 = 0
		
		if matchAcl:
		
			log("In convertTcpUdpAclListToObjects is acl: " + aclLineObject.line,1)
			print("In convertTcpUdpAclListToObjects is acl: " + aclLineObject.line)

				
			aclName = matchAcl.group('aclname')
			
			#Add the acl name if its unique
			if not aclName in aclNameDict:
							
				aclNameDict.update({ aclName: 1 })
				
			#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
			else:
			
				aclNameDict[aclName] += 1
				
			possibleRemark = firewallFileReadonlyList[lineNumber-1]
			aclRemark = ""		
				
			matchAclRemarkRegex = re.match(aclRemarkRegex,possibleRemark)
				
			if matchAclRemarkRegex:
			
				aclRemark = matchAclRemarkRegex.group(2)
				
			aclAction = matchAcl.group('permitdeny')
			aclProtocol = matchAcl.group('ipproto')
			aclSource = matchAcl.group('sourceip')
			print("SOURCEIP: " + aclSource)
			aclDestination = matchAcl.group('destinationip')	
			print("DESTIP: " + aclDestination)
			
			aclSourcePort = ""
			aclDestinationPort = ""
			aclLoggingEnabled = ""
			aclLoggingLevel = ""
			aclTimeRange = ""
		
			if matchAcl.group('sourceport'):

				aclSourcePort = matchAcl.group('sourceport')
				
			if matchAcl.group('destinationport'):
			
				aclDestinationPort = matchAcl.group('destinationport')
				
			if matchAcl.group('loggingenabled'):
			
				aclLoggingEnabled = 1
				
			else:
			
				aclLoggingEnabled = 0
				
			if matchAcl.group(10):
			
				aclLogLevel = matchAcl.group('loglevel')
				
			else:
			
				aclLogLevel = -1	
				
			if matchAcl.group('timerange'):
			
				matchTimeRangeAclRegex = re.match(timeRangeAclRegex,matchAcl.group('timerange'))
				
				if matchTimeRangeAclRegex:
			
					aclTimeRange = 	matchTimeRangeAclRegex.group('timerange')
					
				else:
				
					aclTimeRange = ""
			
			aclLine = line
				
			newObject = tcpUdpAcl(aclName,aclAction,aclProtocol,aclSource,aclSourcePort,aclDestination,aclDestinationPort,aclLine,aclRemark,ciscoPortMapDictionary,aclLoggingEnabled,aclLoggingLevel,aclTimeRange,isIpv6,lineCount)
			tcpUdpAclObjectList.append(newObject)

		log("LEAVING convertTcpUdpAclListToObjects()\n",1)
		lineCount += 1
		
def convertProtocolGroupAclListToObjects(protocolGroupAclList,protocolGroupAclObjectList,protocolGroupObjectList,aclNameDict,firewallFileReadonlyList,ciscoPortMapDictionary):

	log("IN convertProtocolGroupAclListToObjects()\n",1)

	fullProtocolGroupRegex = aclRegex + protocolGroupAclRegex
	
	lineCount = 0

	for aclLineObject in protocolGroupAclList:
		
		isIpv6 = 0
		line = aclLineObject.line
		lineNumber = aclLineObject.linenumber
		matchAcl = re.match(fullProtocolGroupRegex,line)
		matchAclIpv6StartRegex = re.match(aclIpv6StartRegex,line)
			
		if matchAclIpv6StartRegex:
			
			isIpv6 = 1
				
		else:
			
			isIpv6 = 0
		
		if matchAcl:
				
			aclName = matchAcl.group(1)
			
			log("IN convertProtocolGroupAclListToObjects if matchAcl aclName: " + aclName,1)
		
			#Add the acl name if its unique
			if not aclName in aclNameDict:
							
				aclNameDict.update({ aclName: 1 })
				
			#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
			else:
			
				aclNameDict[aclName] += 1
				
			possibleRemark = firewallFileReadonlyList[lineNumber-1]
			aclRemark = ""		
				
			matchAclRemarkRegex = re.match(aclRemarkRegex,possibleRemark)
				
			if matchAclRemarkRegex:
			
				aclRemark = matchAclRemarkRegex.group(2)
				
			aclAction = matchAcl.group(3)
			aclSource = matchAcl.group('sourceip')
			aclDestination = matchAcl.group('destinationip')			
			
			aclSourcePort = ""
			aclDestinationPort = ""
			aclLoggingEnabled = ""
			aclLoggingLevel = ""
			aclTimeRange = ""
		
			if matchAcl.group('sourceport'):

				aclSourcePort = matchAcl.group('sourceport')
				
			if matchAcl.group('destinationport'):
			
				aclDestinationPort = matchAcl.group('destinationport')

			if matchAcl.group('logging'):
			
				aclLoggingEnabled = 1
				
			else:
			
				aclLoggingEnabled = 0
				
				
			####NEEDS Work	
			if matchAcl.group(10):
			
				aclLogLevel = matchAcl.group(10)
				
			else:
			
				aclLogLevel = -1	
				
			if matchAcl.group('timerange'):
			
				matchTimeRangeAclRegex = re.match(timeRangeAclRegex,matchAcl.group('timerange'))
				
				if matchTimeRangeAclRegex:
			
					aclTimeRange = 	matchTimeRangeAclRegex.group('timerange')
					
				else:
				
					aclTimeRange = ""
			
			aclLine = line
				
			matchProtocolGroupNameRegex = re.match(protocolGroupNameRegex,matchAcl.group('ipproto'))
			protocolGroupObjectName = matchProtocolGroupNameRegex.group('ipprotogroupname')
			
			#find the protocolGroupObject by name from the protocolGroupObjectList 
			protocolGroupObject = returnProtocolGroupObject(protocolGroupObjectName,protocolGroupObjectList)
			protocolGroupAclObject = protocolGroupAcl(aclName,aclAction,protocolGroupObjectName,protocolGroupObject,aclSource,aclSourcePort,aclDestination,aclDestinationPort,aclLine,aclRemark,ciscoPortMapDictionary,aclLoggingEnabled,aclLoggingLevel,aclTimeRange,isIpv6)
			protocolGroupAclObject.lineNumber = lineCount
			protocolGroupAclObjectList.append(protocolGroupAclObject)

		log("LEAVING convertProtocolGroupAclListToObjects()\n",1)
		lineCount += 1
		
def createFiles():

	#Create a blank tmsh output file
	currentTimeString = getCurrentTimeString()
	global TMSHAFMFILE
	TMSHAFMFILE = OUTPUTDIR + ciscoAclFile + currentTimeString + TMSHAFMFILEEXTENSION

	TMSHAFMFILEHANDLE = open(TMSHAFMFILE,'w')
	TMSHAFMFILEHANDLE.close
	
	#Create the cisco to tmsh log
	global CISCOTMSHLOG
	CISCOTMSHLOG = CISCOTMSHLOGDIR + ciscoAclFile + currentTimeString + CISCOTMSHLOGEXTENSION
	CISCOTMSHLOGHANDLE = open(CISCOTMSHLOG,'w')
	CISCOTMSHLOGHANDLE.close
	
	global ERRORLOG
	global ERRORLOGHANDLE
	ERRORLOG = ERRORLOGDIR + ciscoAclFile + currentTimeString + ERRORLOGEXTENSION
	ERRORLOGHANDLE = open(ERRORLOG,'w')
	ERRORLOGHANDLE.close
	
	global ACLNOTWRITTENLOG
	global ACLNOTWRITTENLOGHANDLE
	ACLNOTWRITTENLOG = ACLNOTWRITTENLOGDIR + ciscoAclFile + currentTimeString + ACLNOTWRITTENLOGEXTENSION
	ACLNOTWRITTENLOGHANDLE = open(ACLNOTWRITTENLOG,'w')
	ACLNOTWRITTENLOGHANDLE.close
	
	if DEBUG == 1:
	
		global DEBUGLOG 
		global DEBUGLOGHANDLE
		
		DEBUGLOG = DEBUGLOGDIR + ciscoAclFile + currentTimeString + DEBUGLOGEXTENSION
		DEBUGLOGHANDLE = open(DEBUGLOG,'w')
		DEBUGLOGHANDLE.close

#Takes ios netmask and flips it to read correctly
#Not used in PIX/ASA			
def flipNetmask(mask):

	flipDictionary = {"1":"0","0":"1",".":"."}
	flippedMaskBin = ""

	binaryRepresentation =  '.'.join([bin(int(x)+256)[3:] for x in mask.split('.')])
	
	for bit in binaryRepresentation:
		
		flippedMaskBin = flippedMaskBin + flipDictionary[bit] 
		
	flippedMaskDec = '.'.join([str((int(y,2))) for y in flippedMaskBin.split('.')])
	
	return flippedMaskDec
		
def getCurrentTimeString ():

	now = datetime.datetime.now()
	currentTimeString = "-" + str(now.year) + "-" + str(now.month) + "-" + str(now.day) + "-" + str(now.hour) + "-" + str(now.minute) + "-" + str(now.second)

	return currentTimeString

def log(logString,whereToLog):


	logString = logString + (getframeinfo(currentframe()).filename + ':' + str(getframeinfo(currentframe()).lineno))
	
	if whereToLog == 0:
	
		ERRORLOGHANDLE.write(logString)
	
	#Log to debug
	elif whereToLog == 1:
	
		DEBUGLOGHANDLE.write(logString)
		ERRORLOGHANDLE.write(logString)
		
	elif whereToLog == 2:
	
		DEBUGLOGHANDLE.write(logString)
		ACLNOTWRITTENLOGHANDLE.write(logString)

def makeDirs():

	directoryList = [ OUTPUTDIR, CISCOTMSHLOGDIR, DEBUGLOGDIR, ERRORLOGDIR, ACLNOTWRITTENLOGDIR ]

	for dir in directoryList:
	
		if not os.path.exists(dir):
   
   	 		os.makedirs(dir)
   	 			
def moveNumbersToEndOfString(string):

	newstring= ""
	
	matchNumbersStartOfString = re.match('^(?P<startnumbers>\d+)[A-Za-z0-9\_\-\.]*$',string)

	if matchNumbersStartOfString:
	
		lengthOfNumbers = len(matchNumbersStartOfString.group('startnumbers'))
		newstring = string[lengthOfNumbers:] + string[:lengthOfNumbers]
		return newstring

	return string
						


#Parse periodic time-range strings and set the timeRangeObject vars appropriately
#time-range Kids_Hours
# periodic Sunday 8:30 to 21:00
# periodic Friday Saturday 8:30 to 23:59
# periodic Wednesday 16:00 to 21:00
# periodic Monday Tuesday Thursday 17:30 to 21:00
# periodic Wednesday 15:30 to 21:00
# periodic weekdays 5:30 to 6:15
def parsePeriodicTimeRange(ciscoString,timeRangeObject):

	matchPeriodicTimeRangeRegex = re.match(periodicTimeRangeRegex,ciscoString)
	
	if matchPeriodicTimeRangeRegex:
	
		if matchPeriodicTimeRangeRegex.group('days'):
				
			if re.match('weekdays', matchPeriodicTimeRangeRegex.group('days')):
				
				timeRangeObject.hasPeriodicTime = 1
				periodicTimeRangeObject1 = periodicTimeRangeObject(matchPeriodicTimeRangeRegex.group('time1'),matchPeriodicTimeRangeRegex.group('time2'),"monday tuesday wednesday thursday friday",ciscoString)
				timeRangeObject.periodicTimeRangeObjectList.append(periodicTimeRangeObject1)		
				log("In parsePeriodicTimeRange weekdays set to " + periodicTimeRangeObject1.dayString + "\n",1)
				
				if timeRangeObject.periodicNumberOfLines > 1:
				
					periodicTimeListLength = len(timeRangeObject.periodicTimeRangeObjectList)
					periodicTimeRangeObject1.afmName = timeRangeObject.afmName + scheduleObjectAfmName + str(periodicTimeListLength)
					log("In parsePeriodicTimeRange periodicNumberOfLines > 1 weekdays periodicTime name set to " + periodicTimeRangeObject1.afmName + "\n",1)
			
			elif re.match('weekend', matchPeriodicTimeRangeRegex.group('days')):
			
				timeRangeObject.hasPeriodicTime = 1
				periodicTimeRangeObject1 = periodicTimeRangeObject(matchPeriodicTimeRangeRegex.group('time1'),matchPeriodicTimeRangeRegex.group('time2'),"saturday sunday",ciscoString)
				timeRangeObject.periodicTimeRangeObjectList.append(periodicTimeRangeObject1)			
				log("In parsePeriodicTimeRange weekend set to " + matchPeriodicTimeRangeRegex.group('days') + "\n",1)
				
				if timeRangeObject.periodicNumberOfLines > 1:
				
					periodicTimeListLength = len(timeRangeObject.periodicTimeRangeObjectList)
					periodicTimeRangeObject1.afmName = timeRangeObject.afmName + scheduleObjectAfmName + str(periodicTimeListLength)
					log("In parsePeriodicTimeRange weekend periodicTime name set to " + periodicTimeRangeObject1.afmName + "\n",1)
			
			elif re.match('daily', matchPeriodicTimeRangeRegex.group('days')):
			
				timeRangeObject.hasPeriodicTime = 1
				periodicTimeRangeObject1 = periodicTimeRangeObject(matchPeriodicTimeRangeRegex.group('time1'),matchPeriodicTimeRangeRegex.group('time2'),"monday tuesday wednesday thursday friday saturday sunday",ciscoString)
				timeRangeObject.periodicTimeRangeObjectList.append(periodicTimeRangeObject1)						
				log("In parsePeriodicTimeRange daily set to " + matchPeriodicTimeRangeRegex.group('days') + "\n",1)
				
				if timeRangeObject.periodicNumberOfLines > 1:
				
					periodicTimeListLength = len(timeRangeObject.periodicTimeRangeObjectList)
					periodicTimeRangeObject1.afmName = timeRangeObject.afmName + scheduleObjectAfmName + str(periodicTimeListLength)
					log("In parsePeriodicTimeRange days periodicTime name set to " + periodicTimeRangeObject1.afmName + "\n",1)
				
			#Match any days named out, Monday, Wednesday, etc afm requires them to be lowercase
			else:
			
				timeRangeObject.hasPeriodicTime = 1
				periodicTimeRangeObject1 = periodicTimeRangeObject(matchPeriodicTimeRangeRegex.group('time1'),matchPeriodicTimeRangeRegex.group('time2'),matchPeriodicTimeRangeRegex.group('days').lower(),ciscoString)
				timeRangeObject.periodicTimeRangeObjectList.append(periodicTimeRangeObject1)				
				log("In parsePeriodicTimeRange days set to " + matchPeriodicTimeRangeRegex.group('days') + "\n",1)
				
				if timeRangeObject.periodicNumberOfLines > 1:
				
					periodicTimeListLength = len(timeRangeObject.periodicTimeRangeObjectList)
					periodicTimeRangeObject1.afmName = timeRangeObject.afmName + scheduleObjectAfmName + str(periodicTimeListLength)
					log("In parsePeriodicTimeRange weekdays periodicTime name set to " + periodicTimeRangeObject1.afmName + "\n",1)
				
	return

##BEGIN Read functions
#Read entire file into a list so we can use the list index to access the line number
def readFirewallFileToIcmpObjectList(nameObjectList):

	icmpObjectList = []
	inIcmpObject = 0
	icmpObjectReadCount = 0
	
	for line in fileinput.input([ciscoAclFile]):
		
		matchStartOfIcmpObject = re.match(inIcmpObjectGroupRegex,line)
		matchDescription = re.match(objectGroupDescriptionRegex,line)
		matchIcmpObject = re.match(icmpObjectRegex,line)
		
		if matchStartOfIcmpObject:
								
			inIcmpObject = 1			
			icmpObject = icmpGroupObject(matchStartOfIcmpObject.group(1))
			icmpObjectList.append(icmpObject)	
			icmpObjectReadCount += 1	
			
		elif (inIcmpObject == 1) and matchDescription:
								
			icmpObject = icmpObjectList[len(icmpObjectList)-1]
			icmpObject.setDescription(matchDescription.group(1))
			
		elif (inIcmpObject == 1) and matchIcmpObject:
			
			icmpObject.appendIcmpObject(line,nameObjectList)
			
		elif (inIcmpObject == 1):
		
			log("Exception in function readFirewallFileToIcmpObjectList function line: "  + line + "\n",0)
									
	return icmpObjectList,icmpObjectReadCount

def readPortMappingFile():

	for line in fileinput.input([portMappingFile]):
	
		matchObject = re.match(portMappingFileRegex,line)

		if matchObject:
		
			portMappingHash[matchObject.group(1)]=matchObject.group(2)

		else:
		
			log("Exception in function readPortMappingsFile, line is not a defined service " + line,1)

def readFirewallFileToLists():

	firewallFileReadonlyList = []
	firewallFileWriteList = []

	for line in fileinput.input([ciscoAclFile]):
	
		firewallFileReadonlyList.append(line)
		firewallFileWriteList.append({line : "" })

	return firewallFileReadonlyList, firewallFileWriteList		
	
def readCiscoIcmpMappingFile():

	for line in fileinput.input([CISCOICMPMAPPINGFILE]):
	
		matchObject = re.match(ciscoIcmpMappingFileRegex,line)

		if matchObject:
		
			ciscoIcmpMappingHash[matchObject.group(1)]=matchObject.group(2)

		elif DEBUG == 1:
		
			DEBUGLOGHANDLE.write("Exception in function ciscoIcmpMappingsFile, line is not a defined type " + line)
	
#list is nice because it correlates directly to line numbers
#Read all acl from asa config file and put them in their own lists
def readAclsToLists():

	log("IN readAclsToLists()\n",1)

	noPortAclList = []
	tcpUdpAclList = []
	icmpAclList = []
	protocolGroupAclList = []
	linenumber = 0
	inNestedAcl = 0
	inNestedAclCount = 0
	currentNestedAclName = ""
	currentNestedAclType = ""
	currentNestedAclIpVersion = ""
	
	allAclCount = 0
	allIpv4AclCount = 0
	allIpv6AclCount = 0
	icmp4AclCount = 0
	icmp6AclCount = 0
	tcpUdp4AclCount = 0
	tcpUdp6AclCount = 0
	noPort4AclCount = 0
	noPort6AclCount = 0
	protocolGroup4AclCount = 0
	protocolGroup6AclCount = 0
	
	#Count all acl
	for allLine in fileinput.input([ciscoAclFile]):
	
		matchAclStartRegex = re.match(aclStartRegex,allLine)
		matchNestedAclRegex = re.match(nestedAclRegex,allLine)
		matchAclRemarkRegexAll = re.match(aclRemarkRegex,allLine)
		
		if matchNestedAclRegex and (not matchAclRemarkRegex) and (not inNestedAclCount):

			inNestedAclCount = 1
		
		elif inNestedAclCount:
		
			if matchNestedAclAction:
			
				allAclCount += 1
			
			else:
			
				inNestedAclCount = 0
		
		elif matchAclStartRegex and (not matchAclRemarkRegexAll) and (not inNestedAclCount):
			
			allAclCount += 1
		
	for line in fileinput.input([ciscoAclFile]):

		matchAcl = re.match(aclRegex,line)
		matchNestedAclRegex = re.match(nestedAclRegex,line)
		matchAclFallback = re.match(justAccessListRegex,line)
		matchAclRemarkRegex = re.match(aclRemarkRegex,line)
		matchNestedAclActionRegex = re.match(nestedAclActionRegex,line)
		
		if inNestedAcl:
		
			#if we find a nested acl line eg. permit 10.5.1.29,  permit gre 3.1.1.0 0.0.0.7 host 10.74.253.230
			#note that the nested acl is different from the very beginning calling out standard acls, extended and standard being in a different place in the linn
			#like ip access-list standard monitor
			#we rewrite the line into a format we already know eg
			#access-list new_mpe permit icmp host 56.72.37.20 host 56.72.6.179 echo 
			if matchNestedAclAction:
			
				print("Hello")
			
			else:
			
				inNestedAcl = 0
		
		#If we match acl, ipv4 or ipv6
		if matchAcl and (not matchAclRemarkRegex):
			
			matchAclIpv6StartRegex = re.match(aclIpv6StartRegex,line)
			
			#Get count of each acl, ipv4 or ipv6
			if matchAclIpv6StartRegex:
			
				print("IPv6 line: " + line)
			
				allIpv6AclCount += 1
				
			else:
			
				allIpv4AclCount += 1
				
			#Catch all acl w/ ports (udp, tcp, sctp)
			if matchAcl.group('ipproto') == "tcp" or matchAcl.group('ipproto') == "udp" or matchAcl.group('ipproto') == "sctp" :
					
				print("matchLength of tcpUdpAclList: " + str(len(tcpUdpAclList)) )

				if matchAclIpv6StartRegex:
			
					tcpUdp6AclCount += 1
				
				else:
			
					tcpUdp4AclCount += 1
			
				fullTcpUdpRegex = aclRegex + tcpUdpRegex
				matchFullTcpUdpRegex = re.match(fullTcpUdpRegex,line)
				
				if matchFullTcpUdpRegex:
											
					print("matchLength of tcpUdpAclList: " + str(len(tcpUdpAclList)) )
					log("IN readAclsToLists() acl if full tcpUdp\n",1)
					aclLineObject = aclLine(line,linenumber)
					tcpUdpAclList.append(aclLineObject)	
					print("Length of tcpUdpAclList: " + str(len(tcpUdpAclList)) )
				
				else:
						
					if not matchAclRemarkRegex:
			
						log("Exception in function readAclsToLists Line is a tcp/udp acl, but not caught in regex:\n" + line,0)
						log(line,2)
					
			#Catch all icmp acl
			elif matchAcl.group('ipproto') == "icmp" or matchAcl.group('ipproto') == "icmp6":
			
				if matchAclIpv6StartRegex:
			
					icmp6AclCount += 1
				
				else:
			
					icmp4AclCount += 1
			
				fullIcmpRegex = aclRegex + icmpRegex
				matchFullIcmpRegex = re.match(fullIcmpRegex,line)
			
				if matchFullIcmpRegex:
			
					aclLineObject = aclLine(line,linenumber)
					icmpAclList.append(aclLineObject)
					
				else:
				
					if not matchAclRemarkRegex:
						
						log("Exception in function readAclsToLists Line is a icmp acl, but not caught in regex:\n" + line,0)
						log(line,2)
				
			#If acl contains a protocol group		
			elif matchAcl.group('ipproto').startswith('object-group'):
			
				if matchAclIpv6StartRegex:
			
					protocolGroup6AclCount += 1
				
				else:
			
					protocolGroup4AclCount += 1
			
				fullTcpUdpRegex = aclRegex + tcpUdpRegex
				matchFullTcpUdpRegex = re.match(fullTcpUdpRegex,line)
				
				if matchFullTcpUdpRegex:
						
					aclLineObject = aclLine(line,linenumber)
					protocolGroupAclList.append(aclLineObject)	
				
				else:
						
					if not matchAclRemarkRegex:
			
						log("Exception in function readAclsToLists Line is a protocol group acl, but not caught in regex:\n" + line,0)
						log(line,2)
		
			#We assume anything that is not tcp or udp does not have a port and therefore, looks like an ip acl
			else:
			
				if matchAclIpv6StartRegex:
			
					noPort6AclCount += 1
				
				else:
			
					noPort4AclCount += 1
			
				fullNoPortRegex = aclRegex + noPortRegex
				matchFullNoPortRegex = re.match(fullNoPortRegex,line)
			
				if matchFullNoPortRegex:
			
					aclLineObject = aclLine(line,linenumber)
					noPortAclList.append(aclLineObject)	
					
				else:
				
					if not matchAclRemarkRegex:
					
						log("Exception in function readAclsToLists Line is a ip acl, but not caught in regex:\n" + line,0)
						log(line,2)
	
		elif matchNestedAclRegex and (not matchAclRemarkRegex) and (not inNestedAcl):

			inNestedAcl = 1	
			
			nestedAclRegex = '^\s*(?P<ipversion>ip|ipv6)\s*access-list\s*(?P<extended>standard|extended)*\s*(?P<aclname>[0-9a-zA-Z\_\-]+)'

			currentNestedAclName = matchNestedAclRegex.group('aclname')
			currentNestedAclType = matchNestedAclRegex.group('extended')
			currentNestedAclIpVersion = matchNestedAclRegex.group('ipversion')
			
		#If the line has access-list in it, but was not caught, we want to log this
		elif matchAclFallback and (not matchNestedAclRegex):
		
			if not matchAclRemarkRegex:
		
				log("Exception in function readAclsToLists Line is acl, but not caught in regex:\n" + line,0)
				log(line,2)
			
		linenumber += 1

	log("LEAVING readAclsToLists()\n",1)
	return noPortAclList,tcpUdpAclList,icmpAclList, protocolGroupAclList, allAclCount, allIpv4AclCount, allIpv6AclCount, icmp4AclCount, icmp6AclCount, tcpUdp4AclCount, tcpUdp6AclCount, noPort4AclCount, noPort6AclCount, protocolGroup4AclCount, protocolGroup6AclCount
	
def readCiscoPortMapFileToDictionary():

	ciscoPortMapDictionary = {}

	for line in fileinput.input([ciscoPortMapFile]):
	
		matchPortMapLine = re.match(ciscoPortMapFileRegex,line)
		
		if matchPortMapLine:
		
			ciscoPortMapDictionary[matchPortMapLine.group(1)] = matchPortMapLine.group(2)
			
		else:
		
			emptyLineRegexMatch = re.match(emptyLineRegex,line)
			
			if not emptyLineRegexMatch:
		
				log("Exception in function readCisoPortMapFileToDictionary, line not caught:  " + line,1)
		
	return ciscoPortMapDictionary

#object-group protocol tcpudp
# protocol-object tcp
# protocol-object udp
def readFirewallFileToProtocolGroupObjectList():

	log("In readFirewallFileToProtocolObjectList \n",1)

	protocolGroupObjectList = []
	
	#Holder for whether we are in an object
	inProtocolGroupObject = 0

	for line in fileinput.input([ciscoAclFile]):
			
		matchStartOfProtocolGroupObject = re.match(inProtocolGroupObjectRegex,line)
		matchProtocolGroupObjectRegex = re.match(protocolGroupObjectRegex,line)
		matchDescription = re.match(protocolGroupObjectDescriptionRegex,line)
		matchProtocolObjectRegex = re.match(protocolObjectRegex,line)
		
		if matchStartOfProtocolGroupObject:
		
			log("In readFirewallFileToProtocolObjectList for: "  + line + "\n",1)

		if matchStartOfProtocolGroupObject:
				
			log("In readFirewallFileToProtocolObjectList matchStartOfProtocolObject line: "  + line + "\n",1)
			inProtocolGroupObject = 1	
			protocolGroupObjectCurrent = protocolGroupObject(matchStartOfProtocolGroupObject.group(1))
			protocolGroupObjectCurrent.ciscoLine = line
			protocolGroupObjectList.append(protocolGroupObjectCurrent)		
		
		elif (inProtocolGroupObject == 1) and matchDescription:
								
			log("In readFirewallFileToProtocolObjectList matchDescription line: "  + line + "\n",1)	
			protocolGroupObjectCurrent = protocolGroupObjectList[len(protocolGroupObjectList)-1]
			protocolGroupObjectCurrent.setDescription(matchDescription.group(1))
			
		elif (inProtocolGroupObject == 1) and matchProtocolObjectRegex:
				
			log("In readFirewallFileToServiceObjectList matchPortGroupObjectRegex: " + line + "\n",1)
			protocolGroupObjectCurrent.appendProtocolObject(line)
			
		elif (inProtocolGroupObject == 1):
		
			log("In readFirewallFileToProtocolGroupObjectList leaving protocol group object line: "  + line + "\n",0)
			inProtocolOGroupbject = 0
	
	return protocolGroupObjectList

def readFirewallFileToServiceObjectList(ciscoPortMapDictionary):

	log("In readFirewallFileToServiceObjectList \n",1)

	serviceObjectList = []
	
	#Holder for whether we are in an object
	inServiceObject = 0
	serviceObjectReadCount = 0

	for line in fileinput.input([ciscoAclFile]):
				
		matchStartOfServiceObject = re.match(inServiceObjectGroupRegex,line)
		matchDescription = re.match(objectGroupDescriptionRegex,line)
		matchPortObject = re.match(portObjectRegex,line)
		matchPortGroupObjectRegex = re.match(portGroupObjectRegex,line)
		
		if matchStartOfServiceObject or inServiceObject:
		
			log("In readFirewallFileToServiceObjectList for: "  + line + "\n",1)

		if matchStartOfServiceObject:
							
			log("In readFirewallFileToServiceObjectList matchStartOfServiceObject line: "  + line + "\n",1)
				
			inServiceObject = 1
			
			serviceObject = serviceGroupObject(matchStartOfServiceObject.group('name'))
			serviceObject.setProtocol(matchStartOfServiceObject.group('proto'))
			serviceObject.ciscoLine = line
			serviceObjectList.append(serviceObject)	
			
			serviceObjectReadCount += 1	
			
		elif (inServiceObject == 1) and matchDescription:
				
			log("In readFirewallFileToServiceObjectList matchDescription line: "  + line + "\n",1)
			
			serviceObject = serviceObjectList[len(serviceObjectList)-1]
			serviceObject.setDescription(matchDescription.group('description'))
			
		elif (inServiceObject == 1) and matchPortObject:
		
			log("In readFirewallFileToServiceObjectList matchPortObject line: "  + line + "\n",1)
		
			serviceObject.appendPortObject(line,ciscoPortMapDictionary)	
			
		elif (inServiceObject == 1) and matchPortGroupObjectRegex:
		
			log("In readFirewallFileToServiceObjectList matchPortGroupObjectRegex: " + line + "\n",1)

			serviceObject.appendPortObject(line,ciscoPortMapDictionary)
			
		elif (inServiceObject == 1):
		
			log("In readFirewallFileToServiceObjectList leaving service object line: "  + line + "\n",0)
			inServiceObject = 0

	return serviceObjectList, serviceObjectReadCount
	
#Read cisco object network statements and store them into objectNetwork objects so they can 
#be translated to AFM
#object network PROD-networks
# subnet 172.24.10.0 255.255.255.0
# description Created during name migration
#object network vdcnetap01.corp.vegas.com
# host 10.25.16.82
def readFirewallFileToObjectNetworkList():

	log("In readFirewallFileToObjectNetworkObjectList\n",1)

	objectNetworkList = []
	
	#Holder for whether we are in an object
	inObjectNetwork = 0
	objectNetworkReadCount = 0
	
	for line in fileinput.input([ciscoAclFile]):
	
		matchObjectNetworkStartRegex = re.match(objectNetworkStartRegex,line)
	
		if (inObjectNetwork == 1) or matchObjectNetworkStartRegex:
	
			log("In readFirewallFileToObjectNetworkObjectList in for: " + line + "\n",1)

		matchStartOfObjectNetwork = re.match(inObjectNetworkRegex,line)
		matchDescription = re.match(objectNetworkDescriptionRegex,line)
		matchNetworkObject = re.match(networkObjectRegex,line)
		matchIpAndNetmaskRegexObjectNetwork = re.match(ipAndNetmaskRegexObjectNetwork,line)
		matchHostAndIpRegexObjectNetwork = re.match(hostAndIpRegexObjectNetwork,line)
		matchRangeRegexObjectNetwork = re.match(rangeRegexObjectNetwork,line)
		
		if matchStartOfObjectNetwork:
		
			log("In readFirewallFileToObjectNetworkObjectList matchStartOfObjectNetwork: " + line + "\n",1)
			
			inObjectNetwork = 1			
			objectNetwork = _objectNetwork(matchStartOfObjectNetwork.group(1),line)
			objectNetworkList.append(objectNetwork)		
			objectNetworkReadCount += 1
			
		elif (inObjectNetwork == 1) and matchDescription:
					
			log("In readFirewallFileToObjectNetworkObjectListt matchDescription: " + matchDescription.group(1) + "\n",1)
					
			objectNetwork = objectNetworkList[len(objectNetworkList)-1]
			objectNetwork.setDescription(matchDescription.group(1),line)
			
		elif (inObjectNetwork == 1) and matchIpAndNetmaskRegexObjectNetwork:
			
			log("In readFirewallFileToObjectNetworkObjectList matchIpAndNetmaskRegexObjectNetwork: \n",1)
			
			objectNetwork = objectNetworkList[len(objectNetworkList)-1]
			objectNetwork.setObjectNetworkAddress(line)
			objectNetwork.type = "subnet"
			
		elif (inObjectNetwork == 1) and matchHostAndIpRegexObjectNetwork:
		
			log("In readFirewallFileToObjectNetworkObjectList matchHostAndIpRegexObjectNetwork: \n",1)
		
			objectNetwork = objectNetworkList[len(objectNetworkList)-1]
			objectNetwork.setObjectNetworkAddress(line)
			objectNetwork.type = "host"
					
		elif (inObjectNetwork == 1) and matchRangeRegexObjectNetwork:
		
			log("In readFirewallFileToObjectNetworkObjectList matchRangeRegexObjectNetwork: \n",1)
	
			objectNetwork = objectNetworkList[len(objectNetworkList)-1]
			objectNetwork.setObjectNetworkAddress(line)
			objectNetwork.type = "range"
			
		elif (inObjectNetwork == 1):
		
			log("Exception in function readFirewallFileToObjectNetworkObjectList function line: "  + line + "\n",0)
											
	return objectNetworkList,objectNetworkReadCount

#time-range 1wk_SFTP
# absolute end 23:59 14 June 2013
#time-range TEMP_24HR
# absolute end 23:59 07 June 2011
# periodic daily 0:00 to 23:59
#!
#time-range TEMP_72
# absolute start 12:24 16 November 2009 end 12:24 19 November 2009
#!
#time-range Titan_LDAP
# periodic Monday 9:30 to 10:30
# periodic Monday Tuesday Thursday 17:30 to 21:00	
def readTimeRangeToObjectList():

	timeRangeObjectList = []
	
	#Holder for whether we are in an object
	inTimeRange = 0
	lineCount = 0
	timeRangeObjectReadCount = 0
	
	#for line in fileinput.input([ciscoAclFile]):
	for dict in ciscoConfFileList:
	 
		lineCount += 1
	 
		for line in dict:		
	
			matchTimeRangeStartRegex = re.match(timeRangeStartRegex,line)
	
			if matchTimeRangeStartRegex:
	
				log("In readTimeRangeToObjectList for: intimeRange " +  str(inTimeRange) + " line: " + line + "\n",1)

		matchStartOfTimeRange = re.match(inTimeRangeRegex,line)
		matchAbsoluteTimeRangeTwoRegex = re.match(absoluteTimeRangeTwoRegex,line)
		matchAbsoluteTimeRangeOneRegex = re.match(absoluteTimeRangeOneRegex,line)
		matchPeriodicTimeRangeRegex = re.match(periodicTimeRangeRegex,line)

		if matchStartOfTimeRange:
			
			log("In readTimeRangeToObjectList matchStartOfTimeRange: " + line + "\n",1)
			
			inTimeRange = 1			
			timeRangeObject1 = timeRangeObject(matchStartOfTimeRange.group('timeRangeName'),line)
			timeRangeObjectList.append(timeRangeObject1)	
			timeRangeObjectReadCount += 1
			
		elif (inTimeRange == 1) and matchAbsoluteTimeRangeOneRegex:
		
			log("In readTimeRangeToObjectList matchAbsoluteTimeRangeOneRegex: " + line + "\n",1)

			timeRangeObject1 = timeRangeObjectList[len(timeRangeObjectList)-1]
			timeRangeObject1.hasAbsoluteTime = 1
			timeRangeObject1.hasAbsoluteTime1 = 1			
					
			if matchAbsoluteTimeRangeOneRegex.group('startend1') == "end":
			
				timeRangeObject1.afmAbsoluteTime1String = "date-valid-end"
				
			elif matchAbsoluteTimeRangeOneRegex.group('startend1') == "start":

				timeRangeObject1.afmAbsoluteTime1String = "date-valid-start"

			else:
			
				log("In readTimeRangeToObjectList matchAbsoluteTimeRangeOneRegex invalid first start end string: " + line + "\n",0)
				
			timeRangeObject1.abosoluteYear1 = matchAbsoluteTimeRangeOneRegex.group('year1')
			timeRangeObject1.abosoluteMonth1 = convertCiscoMonthToNumber(matchAbsoluteTimeRangeOneRegex.group('month1'))
			timeRangeObject1.abosoluteDate1 = matchAbsoluteTimeRangeOneRegex.group('date1')
			timeRangeObject1.abosoluteTime1 = matchAbsoluteTimeRangeOneRegex.group('time1')
			timeRangeObject1.afmAbsoluteTime1String = timeRangeObject1.afmAbsoluteTime1String + " " + timeRangeObject1.abosoluteYear1 + "-" + timeRangeObject1.abosoluteMonth1 + "-" + timeRangeObject1.abosoluteDate1 	+ ":" + timeRangeObject1.abosoluteTime1  + ":00"
			
		elif (inTimeRange == 1) and matchAbsoluteTimeRangeTwoRegex:
		
			log("In readTimeRangeToObjectList matchAbsoluteTimeRangeTwoRegex: " + line + "\n",1)

			timeRangeObject1 = timeRangeObjectList[len(timeRangeObjectList)-1]
			timeRangeObject1.hasAbsoluteTime = 1
			timeRangeObject1.hasAbsoluteTime2 = 1
					
			if matchAbsoluteTimeRangeTwoRegex.group('startend1') == "end":
			
				timeRangeObject1.afmAbsoluteTime1String = "date-valid-end"
				
			elif matchAbsoluteTimeRangeTwoRegex.group('startend1') == "start":

				timeRangeObject1.afmAbsoluteTime1String = "date-valid-start"

			else:
			
				log("In readTimeRangeToObjectList matchAbsoluteTimeRangeTwoRegex invalid first start end string: " + line + "\n",0)
				
			timeRangeObject1.abosoluteYear1 = matchAbsoluteTimeRangeTwoRegex.group('year1')
			timeRangeObject1.abosoluteMonth1 = convertCiscoMonthToNumber(matchAbsoluteTimeRangeTwoRegex.group('month1'))
			timeRangeObject1.abosoluteDate1 = matchAbsoluteTimeRangeTwoRegex.group('date1')
			timeRangeObject1.abosoluteTime1 = matchAbsoluteTimeRangeTwoRegex.group('time1') 
			timeRangeObject1.afmAbsoluteTime1String = timeRangeObject1.afmAbsoluteTime1String + " " + timeRangeObject1.abosoluteYear1 + "-" + timeRangeObject1.abosoluteMonth1 + "-" + timeRangeObject1.abosoluteDate1 	+ ":" + timeRangeObject1.abosoluteTime1  + ":00"
				
			#parse second date/time part of string			
			if matchAbsoluteTimeRangeTwoRegex.group('startend2') == "end":
			
				timeRangeObject1.afmAbsoluteTime2String = "date-valid-end"
				
			elif matchAbsoluteTimeRangeTwoRegex.group('startend2') == "start":

				timeRangeObject1.afmAbsoluteTime2String = "date-valid-start"

			else:
			
				log("In readTimeRangeToObjectList matchAbsoluteTimeRangeTwoRegex invalid second start end string: " + line + "\n",0)
			
			timeRangeObject1.abosoluteYear2 = matchAbsoluteTimeRangeTwoRegex.group('year2')
			timeRangeObject1.abosoluteMonth2 = convertCiscoMonthToNumber(matchAbsoluteTimeRangeTwoRegex.group('month2'))
			timeRangeObject1.abosoluteDate2 = matchAbsoluteTimeRangeTwoRegex.group('date2')
			timeRangeObject1.abosoluteTime2 = matchAbsoluteTimeRangeTwoRegex.group('time2') 
			timeRangeObject1.afmAbsoluteTime2String = timeRangeObject1.afmAbsoluteTime2String + " " + timeRangeObject1.abosoluteYear2 + "-" + timeRangeObject1.abosoluteMonth2 + "-" + timeRangeObject1.abosoluteDate2 	+ ":" + timeRangeObject1.abosoluteTime2  + ":00"
		
		#Get periodic times,
		# periodic weekdays 5:30 to 6:15	
		elif (inTimeRange == 1) and matchPeriodicTimeRangeRegex:
		
			log("In readTimeRangeToObjectList matchPeriodicTimeRangeRegex: " + line + "\n",1)

			#Since AFM does not support multiple periodic times in one schedule, we need to create multiple schedules if there are more than 1 periodic time
			if timeRangeObject1.periodicNumberOfLinesCheck == 0:
			
				periodicLineCount = 0
				timeRangeObject1.periodicNumberOfLinesCheck = 1
			
				for dict in ciscoConfFileList[lineCount:]:
	 
					for dictionaryLine in dict:
			
						matchPeriodicTimeRangeRegex = re.match(periodicTimeRangeRegex,dictionaryLine)
				
						if matchPeriodicTimeRangeRegex:
							
							timeRangeObject1.periodicNumberOfLines += 1
												
						else:
						
							break
					
			timeRangeObject1 = timeRangeObjectList[len(timeRangeObjectList)-1]
			parsePeriodicTimeRange(line,timeRangeObject1)		
			
	return timeRangeObjectList,timeRangeObjectReadCount

def readCiscoConfFileToHashAndList():

	for line in fileinput.input([ciscoAclFile]):
	
		ciscoConfFileList.append({ line : 0 })
		
	return
	
def readFirewallFileToNameObjectList():

	nameObjectList = []
	lineNumber = 0
	nameObjectCount = 0

	for line in fileinput.input([ciscoAclFile]): 
	
		matchNameRegex = re.match(nameRegex,line)
		
		if matchNameRegex:
		
			nameObject1 = nameObject(matchNameRegex.group('ipaddress'),matchNameRegex.group('name'),line)
			nameObject1.setLineNumber(lineNumber)
			nameObjectList.append(nameObject1)
			nameObjectCount += 1
			
			if matchNameRegex.group('description') and matchNameRegex.group('other'):
			
				nameObject1.setDescription(matchNameRegex.group('other'))
				
		lineNumber += 1
	
	return nameObjectList, nameObjectCount
	
#Translates these lines
#object-group network srv_DNS_OUTSIDE
# network-object object ns1.vegas.com
# network-object object ns2.vegas.com
# network-object object ns3.vegas.com
# network-object object ns4.vegas.com
# network-object object ns5.vegas.com
# network-object object ns6.vegas.com
#object-group network net_PRIVATE
# network-object 10.0.0.0 255.0.0.0
# network-object 172.16.0.0 255.240.0.0
# network-object 192.168.0.0 255.255.0.0
#Gets all the object-group stanzas, takes list of "name 10.26.18.128 VDC_VM_HILTON" then "object network vdp-rpt-dw.svc.prod.vegas.com
# host 172.26.2.212"
#as arguments
def readFirewallFileToObjectGroupNetworkList(nameObjectList,objectNetworkList):

	log("In readFirewallFileToNetworkObjectList\n",1)

	networkObjectList = []
	
	#Holder for whether we are in an object
	inNetworkObject = 0
	objectGroupNetworkReadCount = 0

	for line in fileinput.input([ciscoAclFile]):
	    
		matchObjectGroupNetworkStartRegex = re.match(objectGroupNetworkStartRegex,line)
		matchNetworkObjectLineRegex = re.match(networkObjectLineRegex,line)
		
		if matchNetworkObjectLineRegex or matchObjectGroupNetworkStartRegex:
	
			log("In readFirewallFileToNetworkObjectList in for: " + line + "\n",1)

		matchStartOfNetworkObject = re.match(inNetworkObjectGroupRegex,line)
		matchDescription = re.match(objectGroupDescriptionRegex,line)
		matchNetworkObject = re.match(networkObjectRegex,line)
		matchNetworkObjectObject = re.match(networkObjectObjectRegex,line)
		matchNetworkGroupObject = re.match(networkGroupObjectRegex,line)
		
		if matchStartOfNetworkObject:
		
			log("In readFirewallFileToNetworkObjectList matchStartOfNetworkObject: " + line + "\n",1)
			
			inNetworkObject = 1			
			networkObject = networkGroupObject(matchStartOfNetworkObject.group(1),line)
			networkObjectList.append(networkObject)	
			objectGroupNetworkReadCount += 1	
			
		elif (inNetworkObject == 1) and matchDescription:
						
			networkObject = networkObjectList[len(networkObjectList)-1]
			networkObject.setDescription(matchDescription.group(1))
			
		#object-group network srv_DNS_OUTSIDE
 		#network-object object ns1.vegas.com
		elif (inNetworkObject == 1) and matchNetworkObjectObject:
		
			log("In readFirewallFileToNetworkObjectList matchNetworkObjectObject: " + line + "\n",1)
			networkObjectObjectInObjectGroupNetwork = returnNetworkObjectObjectOrNameObjectByName(objectNetworkList,nameObjectList,matchNetworkObjectObject.group('objectname'))
			networkObject.networkObjectObjectList.append(networkObjectObjectInObjectGroupNetwork)
			
		elif (inNetworkObject == 1) and matchNetworkObject:
			
			log("In readFirewallFileToNetworkObjectList matchNetworkObject: " + line + "\n",1)
			
			networkObject.appendNetworkObject(line,nameObjectList)
			
		elif (inNetworkObject == 1) and matchNetworkGroupObject:
		
			log("In readFirewallFileToNetworkObjectList matchNetworkGroupObject: " + line + "\n",1)

			networkObject.appendGroupObject(line,nameObjectList)
			
		elif (inNetworkObject == 1):
		
			log("In readFirewallFileToNetworkObjectList leaving object-group network line: "  + line + "\n",0)
			inNetworkObject = 0
											
	return networkObjectList,objectGroupNetworkReadCount
##END Read functions
		
##BEGIN Return functions
def returnNetworkHostFromNameObjectList(name,nameObjectList):

	for object in nameObjectList:
	
		if object.name == name:
		
			return object.afmNetworkString

def returnAfmDestinationSource(ciscoDestinationSource):

		matchObjectSourceIpNetmask = re.match(ipAndNetmaskRegex,ciscoDestinationSource)
		matchObjectSourceHost = re.match(hostAndIpRegex,ciscoDestinationSource)
		matchObjectIpv6SourceHost = re.match(hostAndIpv6Regex,ciscoDestinationSource)
		matchObjectGroup = re.match(objectGroupRegex,ciscoDestinationSource)
		matchObjectObjectRegex = re.match(objectObjectRegex,ciscoDestinationSource)
		matchIpv6 = re.match(ipv6Regex,ciscoDestinationSource)	
		
		if ciscoDestinationSource == "any":
		
			afmDestinationSource = "any"
			return afmDestinationSource
			
		elif matchIpv6:
		
			afmDestinationSource = ciscoDestinationSource
			return afmDestinationSource
			
		elif matchObjectSourceIpNetmask:
	
			netmask = matchObjectSourceIpNetmask.group(2)	
			afmDestinationSource = matchObjectSourceIpNetmask.group(1) + '/' + netmask
			return afmDestinationSource
			
		elif matchObjectSourceHost:
		
			afmDestinationSource = matchObjectSourceHost.group(2) + '/' + '32'
			return afmDestinationSource
			
		elif matchObjectGroup:
		
			afmDestinationSource = matchObjectGroup.group(1)
			return afmDestinationSource
			
		elif matchObjectObjectRegex:	
		
			afmDestinationSource = matchObjectObjectRegex.group('objectname')
			return afmDestinationSource
			
		elif matchObjectIpv6SourceHost:
		
			afmDestinationSource = matchObjectIpv6SourceHost.group('ipv6address')
			return afmDestinationSource

		else:
		
			afmDestinationSource = "UNDEFINEDDESTINATIONORSOURCEIP"
			log("Exception in function returnAfmDestinationSource: "  + ciscoDestinationSource + "\n",0)

		return afmDestinationSource

def returnAfmAction(ciscoAction):

	if ciscoAction == "deny":
			
		afmAction = "drop"
		return afmAction
				
	elif ciscoAction == "permit":
		
		afmAction = "accept"
		return afmAction
				
	else:
		
		afmAction = "UNDEFINEDACTION"
		log("Exception in function returnAfmAction: "  + ciscoAction + "\n",0)
		return afmAction
		 
	afmAction = "UNDEFINEDACTION"
	log("Exception in function returnAfmAction: "  + ciscoAction + "\n",0)
	return afmAction
	
def returnAfmPortRange(ciscoPort1,ciscoPort2,ciscoPortMapDictionary):

	justDigitsInPort1 = re.match('^\d+$',ciscoPort1)
	justDigitsInPort2 = re.match('^\d+$',ciscoPort2)
			
	afmPort1 = ""
	afmPort2 = ""

	if justDigitsInPort1:
			
		afmPort1 = ciscoPort1

	else:
			
		afmPort1 = ciscoPortMapDictionary[ciscoPort1]

	if justDigitsInPort2:
			
		afmPort2 = ciscoPort2

	else:
			
		afmPort2 = ciscoPortMapDictionary[ciscoPort2]
				
	afmPortString = afmPort1 + "-" + afmPort2
	
	return afmPortString
				
def returnAfmDestinationSourcePort(ciscoDestinationSourcePort,ciscoPortMapDictionary):

	log("IN method returnAfmDestinationSourcePort() ciscoDestinationSourcePort: " + ciscoDestinationSourcePort,1)

	matchPortRangeRegex = re.match(portRangeRegex,ciscoDestinationSourcePort)	
	matchObjectGroup = re.match(objectGroupRegex,ciscoDestinationSourcePort)
	matchPortQuantifier = re.match(portQuantifierRegex,ciscoDestinationSourcePort)

	afmDestinationSourcePortList = []

	if (ciscoDestinationSourcePort == "any") or (ciscoDestinationSourcePort == ""): 

		afmDestinationSourcePortList.append("1-65535")

	elif matchPortRangeRegex:
	
		afmDestinationSourcePortList.append(returnAfmPortRange(matchPortRangeRegex.group(1),matchPortRangeRegex.group(2),ciscoPortMapDictionary))	
		
	elif matchObjectGroup:
	
		afmDestinationSourcePortList.append(matchObjectGroup.group(1))
		
	elif matchPortQuantifier:
	
		if matchPortQuantifier.group(1) == "eq":
								
			justDigitsInPort = re.match('^(\d+)$',matchPortQuantifier.group(2))
		
			if justDigitsInPort:
		
				afmDestinationSourcePortList.append(matchPortQuantifier.group(2))
				
			else:
			
				afmDestinationSourcePortList.append(ciscoPortMapDictionary[matchPortQuantifier.group(2)])
	
		elif matchPortQuantifier.group(1) == "lt":
		
			justDigitsInPort = re.match('^(\d+)$',matchPortQuantifier.group(2))
			
			if justDigitsInPort:
			
				afmDestinationSourcePortList.append("1-" + str( int( matchPortQuantifier.group(2) )  -1) )
				
			else:
			
				afmDestinationSourcePortList.append("1-" + str( int(ciscoPortMapDictionary[matchPortQuantifier.group(2)])-1) )
				
		elif matchPortQuantifier.group(1) == "gt":
		
		
			justDigitsInPort = re.match('^(\d+)$',matchPortQuantifier.group(2))
			
			if justDigitsInPort:
			
				afmDestinationSourcePortList.append(  str(int(matchPortQuantifier.group(2))+1) + "-65535")
				
			else:
			
				afmDestinationSourcePortList.append( str( int(ciscoPortMapDictionary[matchPortQuantifier.group(2)])+1) + "-65535")	
				
		elif matchPortQuantifier.group(1) == "deq":
		
			justDigitsInPort = re.match('^(\d+)$',matchPortQuantifier.group(2))
			
			if justDigitsInPort:
						
				if not ((justDigitsInPort.group(2)-1)<0):

					startString = "1-" + str(justDigitsInPort.group(2)-1)
					afmDestinationSourcePortList.append(startString)
				
				if not ((justDigitsInPort.group(2)+1)>65535):
				
					endString = str(justDigitsInPort.group(2)+1) + "65535"
					afmDestinationSourcePortList.append(endString)
			
			else:
							
				if (  (int(ciscoPortMapDictionary[matchPortQuantifier.group(2)])-1) >= 0 ) and ( ( int(ciscoPortMapDictionary[matchPortQuantifier.group(2)]) +1) <= 65535):

					startString = "1-" + str( int( ciscoPortMapDictionary[matchPortQuantifier.group(2)] ) -1 )
					afmDestinationSourcePortList.append(startString)
				
					endString = str( int(ciscoPortMapDictionary[matchPortQuantifier.group(2)]) + 1) + "-65535"
					afmDestinationSourcePortList.append(endString)
				
				else: 
				
					afmDestinationSourcePortList.append("DEQ UNDEFINEDSOURCEORDESTINATIONPORT")
						
	else:
	
		afmDestinationSourcePortList.append("UNDEFINEDSOURCEORDESTINATIONPORT")
	
	return afmDestinationSourcePortList

#Return
def returnProtocolGroupObject(protocolGroupObjectName,protocolGroupObjectList):

	protocolGroupObjectReturn = ""

	for protocolGroupObject in protocolGroupObjectList:
	
			if protocolGroupObject.afmName == protocolGroupObjectName:
			
				protocolGroupObjectReturn = protocolGroupObject
			
	return protocolGroupObjectReturn

def returnListOfProtocolsFromProtocolObjectGroup(protocolGroupAclObjectList,procotolGroupObjectName):

	protocolList = []
	
	for protocolGroupObject in protocolGroupAclObjectList:
		
		if protocolGroupObject.afmName == procotolGroupObjectName:
	
			for protocolObject in protocolGroupObject.protocolObjectList:
	
				protocolList.append(protocolObject.afmName)
		
	return protocolList

def returnNetworkGroupObjectByName(networkObjectList,networkGroupObjectName):

	log("In returnNetworkGroupObjectByName, looking for: " + networkGroupObjectName + "\n",1)
	
	for object in networkObjectList:
	
		if object.afmName == networkGroupObjectName:
		
			log("In returnNetworkGroupObjectByName, found object: " + object.ciscoLine +"\n",1)	
			return object

#Return		
def returnNetworkObjectObjectByName(networkObjectObjectList,nameToFind):		
	
	log("In returnObjectNetworkObjectByName networkObjectObjectList is length: " + str(len(networkObjectObjectList))+"\n",1)

	for networkObjectObject in networkObjectObjectList:
		
		log("In returnNetworkObjectObjectByName, in for object name is: " + nameToFind + " current object is: " + networkObjectObject.afmName + "\n",1)

		if networkObjectObject.afmName == nameToFind:
			
			log("In returnNetworkObjectObjectByName, found object ciscoLine: " + networkObjectObject.ciscoLine + "afmName: " + networkObjectObject.afmName + "\n",1)
			return networkObjectObject
			
def returnNameObjectByName(nameObjectList,nameToFind):		
	
	log("In returnNameObjectByNamee nameObjectList is length: " + str(len(nameObjectList))+"\n",1)

	for nameObject in nameObjectList:
		
		log("In returnNameObjectByName, in for object name is: " + nameToFind + " current object is: " + nameObject.afmName + "\n",1)

		if nameObject.afmName == nameToFind:
			
			log("In returnNameObjectByName, found object ciscoLine: " + nameObject.ciscoLine + "afmName: " + nameObject.afmName + "\n",1)
			return nameObject
			
def returnNetworkObjectObjectOrNameObjectByName(networkObjectObjectList,nameObjectList,nameToFind):		

	log("In returnObjectNetworkObjectByName looking for: " + nameToFind + "\n",1)
	networkObjectObject = returnNetworkObjectObjectByName(networkObjectObjectList,nameToFind)
	
	if networkObjectObject is None:
	
		nameObject = returnNameObjectByName(nameObjectList,nameToFind)
		
		if nameObject is None:
		
			sys.exit("Hello")
		
		else:
		
			return nameObject
	
	else:
	
		return networkObjectObject
		
	
#Return	the service object by looking up the port object name
#object-group service TCP_HTTP.HTTPS tcp
# port-object eq www
# port-object eq https
#object-group service DM_INLINE_TCP_4 tcp
# group-object TCP_HTTP.HTTPS
# port-object eq 4000		
def returnServiceObjectByName(serviceObjectList,portObjectName):

	log("In returnServiceObjectByName looking for portObjectName: " + portObjectName + "\n",1)

	for serviceObject in serviceObjectList:
	
		log("In returnServiceObjectByName for: " + serviceObject.afmName + "\n",1)
	
		if serviceObject.afmName == portObjectName:
		
			log("In returnServiceObjectByName, found object ciscoLine: " + serviceObject.ciscoLine + "afmName: " + serviceObject.afmName + "\n",1)
			return serviceObject
##END Return functions

#If UNNESTNETWORKOBJECTS=1 then we use this function
#object-group network networknestedgroup1
# network-object host 5.5.5.6
# group-object networkgroup1
def unnestNetworkObjects(parentObject,networkObject1,networkObjectList,objectNetworkObjectList):

	log("In unnestNetworkObjects()\n",1)

	if networkObject1.isNetworkGroupObject == 0:
	
		log("In unnestNetworkObjects() parentObject: " + parentObject.afmName + "\n",1)					
		addNetworkString = "modify /security firewall address-list " + parentObject.afmName + " addresses add { " +  networkObject1.afmNetworkString + " } \n"
		writeTmshLine(addNetworkString,parentObject.ciscoName,0)
			
	elif networkObject1.isNetworkGroupObject == 1:
				
		log("In unnestNetworkObjects(), object is a nested object-group: "  +  networkObject1.ciscoLine + "\n",1)
		networkGroupObject = returnNetworkGroupObjectByName(networkObjectList,networkObject1.afmNetworkString)	
				
		for objectNetworkObject1 in networkGroupObject._objectNetworkList:
		
			log("In unnestNetworkObjects(), object from NetworkObject is: " + objectNetworkObject1.afmName + "\n",1)
			objectNetworkObject2 = returnObjectNetworkObjectByName(objectNetworkObjectList,objectNetworkObject1.afmName)
			log("In unnestNetworkObjects(), object from returnObjectNetworkObjectByName: " + objectNetworkObject2.afmName + "\n",1)
			addNetworkString = "modify /security firewall address-list " + parentObject.afmName + " addresses add { " + objectNetworkObject2.afmNetworkString + " }\n"
			writeTmshLine(addNetworkString,objectNetworkObject1.ciscoName,0)
						
		for networkObject2 in networkGroupObject.networkObjectList:
		
			if networkObject2.isNetworkGroupObject == 0:
	
				log("In unnestNetworkObjects() in nested object-group, network object is not nested " + networkObject2.ciscoLine + "\n",1)				
				addNetworkString = "modify /security firewall address-list " + parentObject.afmName + " addresses add { " +  networkObject2.afmNetworkString + " } \n"
				writeTmshLine(addNetworkString,parentObject.ciscoName,0)
			
			elif networkObject2.isNetworkGroupObject == 1:
			
				log("In unnestNetworkObjects() in nested object-group, network object is nested " + networkObject2.ciscoLine + "\n",1)
				unnestNetworkObjects(parentObject,networkObject2,networkObjectList,objectNetworkObjectList)	


##BEGIN Write functions
def writeClearCommands ():

	if ENABLECLEARCOMMANDS:

		TMSHAFMFILEHANDLE = open(TMSHAFMFILE,'a')
		TMSHAFMFILEHANDLE.write("delete /security firewall rule-list all\n")
		TMSHAFMFILEHANDLE.write("delete /security firewall port-list all\n")
		TMSHAFMFILEHANDLE.write("delete /security firewall address-list all\n")
		TMSHAFMFILEHANDLE.close
	
	return

def writeCreateRulesets (aclNameDict):

	for aclName in aclNameDict:

		writeTmshLine(createRuleListString + aclName + "\n","",0)
		
	return
	
def writeTmshLine(tmshLine,ciscoLine,writeCiscoOrNot):

	TMSHAFMFILEHANDLE = open(TMSHAFMFILE,'a')
	TMSHAFMFILEHANDLE.write(tmshLine)
	TMSHAFMFILEHANDLE.close
	
	if DEBUG == 1:
	
		log(tmshLine,1)
	
	if writeCiscoOrNot:
	
		CISCOTMSHFILEHANDLE = open(CISCOTMSHLOG,'a')
		CISCOTMSHFILEHANDLE.write(ciscoLine)
		CISCOTMSHFILEHANDLE.write(tmshLine)
		CISCOTMSHFILEHANDLE.close

#Write cisco lines like 
#access-list aclint_INSIDE extended permit object-group tcpudp object-group net_PRIVATE object-group srv_DNS_OUTSIDE eq domain 
#in tmsh format
def writeProtocolGroupAclListRules(protocolGroupAclObjectList,aclNameDictCount,tcpUdpAclObjectList,icmpObjectList,firewallFileWriteList,ciscoPortMapDictionary):

	log("IN writeProtocolGroupAclListRules()\n",1)
	
	icmpProtocolGroupObjectsWrittenCount = 0
	tcpUdpPortObjectsProtocolGroupWrittenCount = 0
	noPortObjectsProtocolGroupWrittenCount = 0
	uniqueProtocolGroupAclNameCount = 0
	uniqueProtocolGroupAclNameList = []
	
	for protocolGroupAclObject in protocolGroupAclObjectList:
	
		protocolGroupObject = protocolGroupAclObject.protocolGroupObject
			
		#afm as of 11.6 does not support more than 1 protocol in an acl, so they must be split into multiple rules
		if UNNESTPROTOCOLGROUPOBJECTS == 1:
		
			log("IN writeProtocolGroupAclListRules() were unnested\n",1)
			log("IN writeProtocolGroupAclListRules() for protocolGroupAclObject name: " + protocolGroupAclObject.afmName + "\n",1)

			if protocolGroupAclObject.afmName not in uniqueProtocolGroupAclNameList:
		
				uniqueProtocolGroupAclNameList.append(protocolGroupAclObject.afmName)
				uniqueProtocolGroupAclNameCount = len(uniqueProtocolGroupAclNameList)
			
			if protocolGroupAclObject.afmProtocol == 'icmp':
		
				log("IN writeProtocolGroupAclListRules() for protocolGroupAclObject is icmp\n",1)
				tempIcmpAclObjectList = []
				tempIcmpAclObjectList.append(protocolGroupAclObject)
				icmpObjectsWrittenCount = icmpObjectsWrittenCount + writeIcmpAclListRules(tempIcmpAclObjectList,aclNameDictCount,icmpObjectList,firewallFileWriteList)
			
			elif protocolGroupAclObject.protocolGroupObject.protocolObjectList[0].afmName == 'tcp' or protocolGroupAclObject.protocolGroupObject.protocolObjectList[0].afmName  == 'udp' or protocolGroupAclObject.protocolGroupObject.protocolObjectList[0].afmName  == 'sctp':
		
				log("IN writeProtocolGroupAclListRules() for protocolGroupAclObject is tcp, udp or sctp\n",1)
			
				#Need to convert line to tcp and udp acl objects
				tempTcpUdpAclObjectList = protocolGroupAclObject.convertProtocolGroupAclObjectToTcpUdpAclObjectList(ciscoPortMapDictionary)
				tcpUdpPortObjectsWrittenCount, tcpUdpIpv4AclObjectsWrittenCount, tcpUdpIpv6AclObjectsWrittenCount  = writeTcpUdpPortAclListRules(tempTcpUdpAclObjectList,aclNameDictCount,firewallFileWriteList)
				tcpUdpPortObjectsProtocolGroupWrittenCount = tcpUdpPortObjectsProtocolGroupWrittenCount + tcpUdpPortObjectsWrittenCount	
			
			else:
						
				log("IN writeProtocolGroupAclListRules() for protocolGroupAclObjects in else, which writes NoPortAclListRules\n",1)
				tempNoPortAclObjectList = []
				tempNoPortAclObjectList.append(protocolGroupAclObject)
				noPortObjectsWrittenCount = noPortObjectsWrittenCount + writeNoPortAclListRules(tempNoPortAclObjectList,aclNameDictCount,firewallFileWriteList)
				
		#If afm supports protocol objects in acl
		else:
		
			#write nested protocol group objects from acl
			log("IN writeProtocolGroupAclListRules() are nested\n",1)
			print("AFM supports protocol groups, this script does not yet support this")
			sys.exit()	
	
	log("LEAVING writeProtocolGroupAclListRules()\n",1)
		
	return uniqueProtocolGroupAclNameCount,icmpProtocolGroupObjectsWrittenCount,tcpUdpPortObjectsProtocolGroupWrittenCount,noPortObjectsProtocolGroupWrittenCount
	
def writeTcpUdpPortAclListRules(tcpUdpPortAclObjectList,aclNameDictCount,firewallFileWriteList):

	log("In writeTcpUdpPortAclListRules\n",1)

	tcpUdpAclObjectsWrittenCount = 0
	tcpUdpIpv4AclObjectsWrittenCount = 0
	tcpUdpIpv6AclObjectsWrittenCount = 0

	for tcpUdpAclObject in tcpUdpPortAclObjectList:
		
		log("In writeTcpUdpPortAclListRules for name: " + tcpUdpAclObject.afmName + "\n",1)
		
		aclName = tcpUdpAclObject.ciscoName
		tmshLine = ""
			
		#Add the acl name if its unique
		if not aclName in aclNameDictCount:

			#aclNameDictCount.update({ aclName: 1 })
			aclNameDictCount[aclName] = 1
				
		#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
		else:
		
			aclNameDictCount[aclName] += 1
				
		aclAction = tcpUdpAclObject.afmAction
		aclProtocol = tcpUdpAclObject.afmProtocol
		aclSource = tcpUdpAclObject.afmSource
		aclDestination = tcpUdpAclObject.afmDestination
		afmDestinationPort = tcpUdpAclObject.afmDestinationPort
		afmSourcePort = tcpUdpAclObject.afmSourcePort
		description = tcpUdpAclObject.afmRemark
		loggingEnabled = tcpUdpAclObject.afmLoggingEnabled	
		
		if tcpUdpAclObject.schedule:
		
			scheduled = moveNumbersToEndOfString(tcpUdpAclObject.schedule)
		
		else:
		
			scheduled = ""
		
		aclSourceAddressAddString = ""
		justIpRegexSourceAddressMatch = re.match(justIpRegex,aclSource)
		justNameRegexSourceAddressMatch = re.match(justNameRegex,aclSource)
		
		if justIpRegexSourceAddressMatch:
		
			aclSourceAddressAddString = "addresses add"
		
		elif justNameRegexSourceAddressMatch:
		
			aclSourceAddressAddString = "address-lists add"
			
		aclSourcePortAddString = ""
		justPortnumberRegexSourcePortMatch = re.match('^([0-9\-]+|any)$',afmSourcePort[0])
		justNameRegexSourcePortMatch = re.match(justNameRegex,afmSourcePort[0])
		
		if justPortnumberRegexSourcePortMatch:
		
			aclSourcePortAddString = "ports add"
			
		elif justNameRegexSourcePortMatch:
		
			aclSourcePortAddString = "port-lists add"	
		
		aclDestinationAddressAddString = ""
		justIpRegexDestinationAddressMatch = re.match(justIpRegex,aclDestination)
		justNameRegexDestinationAddressMatch = re.match(justNameRegex,aclDestination)
		
		if justIpRegexDestinationAddressMatch:
		
			aclDestinationAddressAddString = "addresses add"
		
		elif justNameRegexSourceAddressMatch:
		
			aclDestinationAddressAddString = "address-lists add"
			
			print("aclDestination: " + aclDestination)

		#create /security firewall rule-list testrulelist rules add { rulelist_4  { place-after last action accept }}
		tmshLine = " " + aclName + " rules add { " + aclName + str(aclNameDictCount[aclName]) + " { destination { " + aclDestinationAddressAddString + " { " + aclDestination + " } " 
		for dstPort in afmDestinationPort:
		
			aclDestinationPortAddString = ""
			justPortnumberRegexDestinationPortMatch = re.match('^([0-9\-]+|any)$',dstPort)
			justNameRegexDestinationPortMatch = re.match(justNameRegex,dstPort)
		
			if justPortnumberRegexDestinationPortMatch:
		
				aclDestinationPortAddString = "ports add { " + dstPort + " } "
			
			elif justNameRegexDestinationPortMatch:
		
				aclDestinationPortAddString = "port-lists add { "  + dstPort + " } "
		
			tmshLine = tmshLine + aclDestinationPortAddString
		 	
		tmshLine = tmshLine +  " } " + "ip-protocol " + aclProtocol + " source { " +  aclSourceAddressAddString + " { " +  aclSource + " } "
	
		for srcPort in afmSourcePort:
		
			aclSourcePortAdsrcring = ""
			justPortnumberRegexSourcePortMatch = re.match('^([0-9\-]+|any)$',srcPort)
			justNameRegexSourcePortMatch = re.match(justNameRegex,srcPort)
		
			if justPortnumberRegexSourcePortMatch:
		
					aclSourcePortAdsrcring = "ports add { " + srcPort + " } "
			
			elif justNameRegexSourcePortMatch:
		
				aclSourcePortAdsrcring = "port-lists add { "  + srcPort + " } "
		
			tmshLine = tmshLine + aclSourcePortAdsrcring
		 	
		tmshLine = tmshLine + " } "
		 	
		if loggingEnabled and ENABLELOGGING:
		
			tmshLine = tmshLine + " log yes "
				 	
		
		#If there is time-range object in the acl
		if scheduled:
		
			tmshLine = tmshLine + " schedule " + scheduled
		
			
		tmshLine = tmshLine + " place-after last action " + aclAction +  " description \"" + description + " \"}}\n" 
		
		lineCount = 0
		
		for lineDict in firewallFileWriteList:
		
			#if tcpUdpAclObject.ciscoLine in lineDict:
			
				#print(str(lineCount))
				
			lineCount += 1
		
		firewallFileWriteList[tcpUdpAclObject.lineNumber][tcpUdpAclObject.ciscoLine] = modifyRuleListString + tmshLine
		writeTmshLine(modifyRuleListString + tmshLine,tcpUdpAclObject.ciscoLine,1) 	 
		tcpUdpAclObjectsWrittenCount += 1
		
		if tcpUdpAclObject.isIpv6 == 1:
		
			tcpUdpIpv6AclObjectsWrittenCount += 1
		
		else:
		
			tcpUdpIpv4AclObjectsWrittenCount += 1
			
	return tcpUdpAclObjectsWrittenCount, tcpUdpIpv4AclObjectsWrittenCount, tcpUdpIpv6AclObjectsWrittenCount

#Convert access-list DMZ_IPTSRV_access_in extended permit icmp object-group DMZ_IPTSRV any object-group ICMP_REQUESTS 
#lines to tmsh	
def writeIcmpAclListRules(icmpAclObjectList,aclNameDictCount,icmpObjectList,firewallFileWriteList):

	log("In writeIcmpAclListRules()\n",1)

	icmpAclObjectsWrittenCount = 0
	icmpIpv4AclObjectsWrittenCount = 0
	icmpIpv6AclObjectsWrittenCount = 0
	
	tmshLine = ""

	for object in icmpAclObjectList:
	
		log("In writeIcmpAclListRules for name: " + object.afmName + "\n",1)

	
		aclName = object.ciscoName
		
		#Add the acl name if its unique
		if not aclName in aclNameDictCount:
						
			#aclNameDictCount.update({ aclName: 1 })
			aclNameDictCount[aclName] = 1
		
		#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
		else:
		
			aclNameDictCount[aclName] += 1
					
		aclAction = object.afmAction
		aclProtocol = object.afmProtocol
		aclSource = object.afmSource
		aclDestination = object.afmDestination
		description = object.afmRemark	
		loggingEnabled = object.afmLoggingEnabled	
		
		aclSourceAddressAddString = ""
		justIpRegexSourceAddressMatch = re.match(justIpRegex,aclSource)
		justNameRegexSourceAddressMatch = re.match(justNameRegex,aclSource)
		
		if justIpRegexSourceAddressMatch:
		
			aclSourceAddressAddString = "addresses add"
		
		elif justNameRegexSourceAddressMatch:
		
			aclSourceAddressAddString = "address-lists add"
			
		aclDestinationAddressAddString = ""
		justIpRegexDestinationAddressMatch = re.match(justIpRegex,aclDestination)
		justNameRegexDestinationAddressMatch = re.match(justNameRegex,aclDestination)
		
		if justIpRegexDestinationAddressMatch:
		
			aclDestinationAddressAddString = "addresses add"
		
		elif justNameRegexSourceAddressMatch:
		
			aclDestinationAddressAddString = "address-lists add"
	
		#modify /security firewall rule-list icmp rules modify { icmp1 { icmp add { echo } } }
		#create /security firewall rule-list testrulelist rules add { rulelist_4  { place-after last action accept }}
		tmshLine = modifyRuleListString + " " + aclName + " rules add { " + aclName  + str(aclNameDictCount[aclName]) + " { "
		
		if object.afmIcmpString != "NULL":
				
			icmpString = object.afmIcmpString
			
			if (re.match(objectGroupRegex,icmpString)):
					
				if ICMPOBJECTSEXPAND:
							
					for icmpGroupObject in icmpObjectList:
				
						for icmpObject in icmpGroupObject.icmpObjectList:
											
							tmshLine = tmshLine + " icmp add { " + ciscoIcmpMappingHash[icmpObject.afmIcmpString] + " } "
			
				else:
				
					tmshLine = tmshLine + " icmp add { " + re.match(inIcmpObjectGroupRegex,icmpString).group(1) + " } "
				
			else:
		
				tmshLine = tmshLine + " icmp add { " + icmpString + " } "
				
		if loggingEnabled and ENABLELOGGING:
		
			tmshLine = tmshLine + " log yes "
		
		tmshLine = tmshLine + "ip-protocol " + aclProtocol + " destination { " + aclDestinationAddressAddString + " { " + aclDestination + " }} " +  " source { " + aclSourceAddressAddString + " { " +  aclSource + " }}  place-after last action " + aclAction + " description \"" + description + " \"}}\n"
		writeTmshLine(tmshLine,object.ciscoLine,1)
		icmpAclObjectsWrittenCount += 1
		
		if object.isIpv6 == 1:
		
			icmpIpv6AclObjectsWrittenCount += 1
		
		else:
		
			icmpIpv4AclObjectsWrittenCount += 1
			
	print("Icmp IPv4 Tmsh lines written: 					" + str(icmpIpv4AclObjectsWrittenCount))
	print("Icmp IPv6 Tmsh lines written: 					" + str(icmpIpv6AclObjectsWrittenCount))		
	print("Icmp Tmsh lines written: 					" + str(icmpAclObjectsWrittenCount)) 
		
	return icmpAclObjectsWrittenCount
	
def writeNoPortAclListRules(noPortAclObjectList,aclNameDictCount,firewallFileWriteList):

	log("IN writeNoPortAclListRules()\n",1)

	noPortAclObjectsWrittenCount = 0
	noPortIpv4AclObjectsWrittenCount = 0
	noPortIpv6AclObjectsWrittenCount = 0
	
	tmshLine = ""

	for object in noPortAclObjectList:
	
		aclName = object.ciscoName
		
		#Add the acl name if its unique
		if not aclName in aclNameDictCount:
						
			#aclNameDictCount.update({ aclName: 1 })
			aclNameDictCount[aclName] = 1
		
		#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
		else:
		
			aclNameDictCount[aclName] += 1
					
		aclAction = object.afmAction
		aclProtocol = object.afmProtocol
		aclSource = object.afmSource
		aclDestination = object.afmDestination
		description = object.afmRemark
		loggingEnabled = object.afmLoggingEnabled		
		aclSourceAddressAddString = ""
		justIpRegexSourceAddressMatch = re.match(justIpRegex,aclSource)
		justNameRegexSourceAddressMatch = re.match(justNameRegex,aclSource)
		
		if justIpRegexSourceAddressMatch:
				
			aclSourceAddressAddString = "addresses add"
		
		elif justNameRegexSourceAddressMatch:
		
			aclSourceAddressAddString = "address-lists add"
			
		aclDestinationAddressAddString = ""
		justIpRegexDestinationAddressMatch = re.match(justIpRegex,aclDestination)
		justNameRegexDestinationAddressMatch = re.match(justNameRegex,aclDestination)
		
		if justIpRegexDestinationAddressMatch:
		
			aclDestinationAddressAddString = "addresses add"
		
		elif justNameRegexSourceAddressMatch:
		
			aclDestinationAddressAddString = "address-lists add"
			
		if loggingEnabled and ENABLELOGGING:
		
			tmshLine = tmshLine + " log yes "
	
		#create /security firewall rule-list testrulelist rules add { rulelist_4  { place-after last action accept }}
		tmshLine = modifyRuleListString + " " + aclName + " rules add { " + aclName + str(aclNameDictCount[aclName]) + " { destination { " + aclDestinationAddressAddString + " { " + aclDestination + " }} " + "ip-protocol " + aclProtocol + " source { " + aclSourceAddressAddString + " { " +  aclSource + " }}  place-after last action " + aclAction + " description \"" + description + " \"}}\n"
		writeTmshLine(tmshLine,object.ciscoLine,1)
		noPortAclObjectsWrittenCount += 1
		
		if object.isIpv6 == 1:
		
			noPortIpv6AclObjectsWrittenCount += 1
		
		else:
		
			noPortIpv4AclObjectsWrittenCount += 1
			
	print("Other IPv4 Tmsh lines written: 					" + str(noPortIpv4AclObjectsWrittenCount))
	print("Other IPv6 Tmsh lines written: 					" + str(noPortIpv6AclObjectsWrittenCount))		
	print("Other Tmsh lines written: 					" + str(noPortAclObjectsWrittenCount)) 
	
	log("LEAVING writeNoPortAclListRules()\n",1)
	
	return noPortAclObjectsWrittenCount

def writeServiceObjects(serviceObjectList):
# create /security firewall port-list test ports add { 1-1 }
#modify  /security firewall port-list test description 

	log("In writeServiceObjects\n",1)

	for object in serviceObjectList:
	
		log("In writeServiceObjects for object in serviceObjectList afmName: " + object.afmName + "\n",1)

		createServiceObjectLine = "create /security firewall port-list " + object.afmName + " ports add { 1-1 } description \"" + object.description + " \"\n"
		writeTmshLine(createServiceObjectLine,object.ciscoName,0)
		
		for portObject in object.portObjectList:
		
			#If 11.4.1 or less, nested service/port object are not supported until 11.5
			if UNNESTPORTOBJECTS == 1:
		
				log("In writeServiceObjects UNNESTPORTOBJECTS == 1\n",1)

				#If object 
				if portObject.isObject == 0:
				
					log("In writeServiceObjects portObject.isObject == 0 afmName: " + object.afmName + "\n",1)
					addPortString =  "modify /security firewall port-list " + object.afmName + " ports add { " + portObject.afmPortString + " } \n"
					writeTmshLine(addPortString,object.ciscoName,0)
	
				else:
				
					log("In writeServiceObjects portObject.isObject == 1 afmName: " + object.afmName + " portObject.afmName: " + portObject.afmPortString + "\n",1)
					
					#Nested object
					#object-group service TCP_HTTP.HTTPS tcp
 					# port-object eq www
 					# port-object eq https
					#object-group service DM_INLINE_TCP_4 tcp
 					# group-object TCP_HTTP.HTTPS
					# port-object eq 4000
					serviceObject1 = returnServiceObjectByName(serviceObjectList,portObject.afmPortString)
					
					for portObject1 in serviceObject1.portObjectList:
					
						log("In writeServiceObjects portObject.isObject == 1 for portObject1.afmName: " + object.afmName + " afmPortString: " + portObject1.afmPortString + "\n",1)
						addPortString =  "modify /security firewall port-list " + object.afmName + " ports add { " + portObject1.afmPortString + " } \n"
						writeTmshLine(addPortString,object.ciscoName,0)
			
			#Don't unnest service/port objects
			else:
			
				addPortString =  "modify /security firewall port-list " + object.afmName + " ports add { " + portObject.afmPortString + " } \n"
				writeTmshLine(addPortString,object.ciscoName,0)
				
		deleteTempServiceObjectLine = "modify /security firewall port-list " + object.afmName + " ports delete { 1-1 } \n"
		writeTmshLine(deleteTempServiceObjectLine,object.ciscoName,0)

	return
				
#object-group network srv_DNS_OUTSIDE
# network-object object ns1.vegas.com
# network-object object ns2.vegas.com
# network-object object ns3.vegas.com
# network-object object ns4.vegas.com
# network-object object ns5.vegas.com
# network-object object ns6.vegas.com
#object-group network net_PRIVATE
# network-object 10.0.0.0 255.0.0.0
# network-object 172.16.0.0 255.240.0.0
# network-object 192.168.0.0 255.255.0.0						
def writeObjectGroupNetwork(networkObjectList,networkObjectObjectList):

	log("In writeGroupNetworkObjects\n",1)

	for networkGroupObject in networkObjectList:
		
		log("In writeNetworkGroupObjects for networkGroupObject cisco name: " + networkGroupObject.ciscoName + "\n",1)
		createNetworkObjectLine = "create /security firewall address-list " + networkGroupObject.afmName + " addresses add { 127.0.0.3/32 } description \"" + networkGroupObject.description + " \"\n"
		writeTmshLine(createNetworkObjectLine,networkGroupObject.ciscoName,0)
		
		for networkObject1 in networkGroupObject.networkObjectList:
		
			log("In writeGroupNetworkObjects networkObject is: " + networkObject1.ciscoLine + "\n",1)

			if UNNESTNETWORKOBJECTS == 1:
			
				unnestNetworkObjects(networkGroupObject,networkObject1,networkObjectList,networkObjectObjectList)
				
			else:
			
				addNetworkString = "modify /security firewall address-list " + networkGroupObject.afmName + " addresses add { " +  networkObject1.afmNetworkString + " } \n"
				writeTmshLine(addNetworkString,networkGroupObject.ciscoName,0)	
			
		#See if there are any  network-object object vvpintap02.lasvegas.com objects, if so look up the real object and extract it	
		#The list we are iterating thru only contains networkObjectObjects
		for networkObjectObject1 in networkGroupObject._objectNetworkList:
		
			log("In writeNetworkGroupObjects, object from NetworkObject is: " + networkObjectObject1.afmName + "\n",1)
			addNetworkString = "modify /security firewall address-list " + networkGroupObject.afmName + " addresses add { " + networkObjectObject1.afmNetworkString + " }\n"
			writeTmshLine(addNetworkString,networkObjectObject1.ciscoName,0)
			 
		deleteNetworkObjectLine = "modify /security firewall address-list " + networkGroupObject.afmName + " addresses delete { 127.0.0.3/32 } \n"
		writeTmshLine(deleteNetworkObjectLine,networkGroupObject.ciscoName,0)
	
	return	

#Write cisco lines like name 192.5.73.15 ns1.vegas.com in tmsh format
def writeNameObjects(nameObjectList):

	log("In writeNameObjects\n",1)
	
	nameObjectWrittenCount = 0
	
	for nameObject in nameObjectList:
	
		log("In writeNameObjects for nameObject cisco name: " + nameObject.ciscoName + "\n",1)
		createNetworkObjectLine = "create /security firewall address-list " + nameObject.afmName + " addresses add { " + nameObject.afmNetworkString + " } description \"" + nameObject.description + " \"\n"
		writeTmshLine(createNetworkObjectLine,nameObject.ciscoName,0)
		nameObjectWrittenCount += 1

	return nameObjectWrittenCount		

def writeObjectNetwork(objectNetworkList):

	log("In writeObjectNetworkObjects\n",1)

	for object in objectNetworkList:
		
		log("In writeObjectNetworks for afmName: " +  object.afmName + " description: " + object.description + "\n",1)

		createNetworkObjectLine = "create /security firewall address-list " + object.afmName + " addresses add { 127.0.0.3/32 } description \"" + object.description + " \"\n"
		writeTmshLine(createNetworkObjectLine,object.ciscoName,0)
		
		if object.type == "range":
		
			addNetworkString = "modify /security firewall address-list " + object.afmName + " addresses add { " +  object.afmNetworkString + " } \n"
			writeTmshLine(addNetworkString,object.ciscoName,0)			
		
		elif object.type == "host":
		
			addNetworkString = "modify /security firewall address-list " + object.afmName + " addresses add { " +  object.afmNetworkString + " } \n"
			writeTmshLine(addNetworkString,object.ciscoName,0)
			
		elif object.type == "subnet":
		
			addNetworkString = "modify /security firewall address-list " + object.afmName + " addresses add { " +  object.afmNetworkString + " } \n"
			writeTmshLine(addNetworkString,object.ciscoName,0)
			
		else:
		
			log("In writeObjectNetworks unknown type: " + object.ciscoLine + "\n",1)

		deleteNetworkObjectLine = "modify /security firewall address-list " + object.afmName + " addresses delete { 127.0.0.3/32 } \n"
		writeTmshLine(deleteNetworkObjectLine,object.ciscoName,0)
		
	return
	
def writeTimeRangeObjects(timeRangeObjectList):

	for timeRangeObject in timeRangeObjectList:
	
		if timeRangeObject.periodicNumberOfLines <= 1:

			createTimeRangeObjectLine = "create /security firewall schedule " + timeRangeObject.afmName +"\n"
			writeTmshLine(createTimeRangeObjectLine,timeRangeObject.ciscoName,0)
			log("In writeTimeRangeObjects creating object line: " + createTimeRangeObjectLine + "\n",1)

		if timeRangeObject.hasAbsoluteTime == 1:
		
			if timeRangeObject.periodicNumberOfLines <= 1:
			
				log("In writeTimeRangeObjects has absolute time \n",1)
				writeAbsoluteTimeRangeObjects(timeRangeObject,timeRangeObject.afmName)
				
		if timeRangeObject.hasPeriodicTime == 1:
		
			if timeRangeObject.periodicNumberOfLines > 1:
		
				objectCount = 1
		
				for periodicTimeObject in timeRangeObject.periodicTimeRangeObjectList:
				
					scheduleName = timeRangeObject.afmName + scheduleObjectAfmName + str(objectCount)
					
					createTimeRangeObjectLine = "create /security firewall schedule " + scheduleName + "\n"
					writeTmshLine(createTimeRangeObjectLine,timeRangeObject.ciscoName,0)
					writeAbsoluteTimeRangeObjects(timeRangeObject,scheduleName)
					modifyTimeRangeObjectLine = "modify /security firewall schedule " + scheduleName + " daily-hour-start " + periodicTimeObject.startTime + "\n"
					writeTmshLine(modifyTimeRangeObjectLine,timeRangeObject.ciscoName,0)
					modifyTimeRangeObjectLine = "modify /security firewall schedule " + scheduleName + " daily-hour-end " + periodicTimeObject.endTime + "\n"
					writeTmshLine(modifyTimeRangeObjectLine,timeRangeObject.ciscoName,0)
					modifyTimeRangeObjectLine = "modify /security firewall schedule " + scheduleName + " days-of-week { " + periodicTimeObject.dayString + " }\n"
					writeTmshLine(modifyTimeRangeObjectLine,timeRangeObject.ciscoName,0)
					log("In writeTimeRangeObjects modifying object periodic line: " + modifyTimeRangeObjectLine + "\n",1)
				
					objectCount += 1
						
			else:
				periodicTimeObject = timeRangeObject.periodicTimeRangeObjectList[0]
				modifyTimeRangeObjectLine = "modify /security firewall schedule " + timeRangeObject.afmName + " daily-hour-start " + periodicTimeObject.startTime + "\n"
				writeTmshLine(modifyTimeRangeObjectLine,timeRangeObject.ciscoName,0)
				modifyTimeRangeObjectLine = "modify /security firewall schedule " + timeRangeObject.afmName + " daily-hour-end " + periodicTimeObject.endTime + "\n"
				writeTmshLine(modifyTimeRangeObjectLine,timeRangeObject.ciscoName,0)
				modifyTimeRangeObjectLine = "modify /security firewall schedule " + timeRangeObject.afmName + " days-of-week { " + periodicTimeObject.dayString + " }\n"
				writeTmshLine(modifyTimeRangeObjectLine,timeRangeObject.ciscoName,0)
				log("In writeTimeRangeObjects modifying object periodic line: " + modifyTimeRangeObjectLine + "\n",1)
			
	return	

#write the absolute time lines
def writeAbsoluteTimeRangeObjects(timeRangeObject,scheduleName):

	if timeRangeObject.hasAbsoluteTime1 == 1:
			
		modifyTimeRangeObjectLine1 = "modify /security firewall schedule " + scheduleName + " " + timeRangeObject.afmAbsoluteTime1String +"\n"
		writeTmshLine(modifyTimeRangeObjectLine1,timeRangeObject.ciscoName,0)
		log("In writeAbsoluteTimeRangeObjects modifying object line: " + modifyTimeRangeObjectLine1 + "\n",1)

	elif timeRangeObject.hasAbsoluteTime2 == 1:
			
		modifyTimeRangeObjectLine1 = "modify /security firewall schedule " + scheduleName + " " + timeRangeObject.afmAbsoluteTime1String +"\n"
		writeTmshLine(modifyTimeRangeObjectLine1,timeRangeObject.ciscoName,0)
		log("In writeAbsoluteTimeRangeObjects modifying object absolute time 1 line: " + modifyTimeRangeObjectLine1 + "\n",1)
				
		modifyTimeRangeObjectLine2 = "modify /security firewall schedule " + scheduleName + " " + timeRangeObject.afmAbsoluteTime2String +"\n"
		writeTmshLine(modifyTimeRangeObjectLine2,timeRangeObject.ciscoName,0)
		log("In writeAbsoluteTimeRangeObjects modifying object absolute time 2 line: " + modifyTimeRangeObjectLine2 + "\n",1)	
		
	return				

##Main - begin execution		                   
def main():
	
	#Make all the necessary dirs if they do 
	makeDirs()
	#Create the necessary files
	createFiles()
	
	#An array/list that contain all noPortAcl objects, which will be written to the tmsh output
	noPortAclObjectList = []
	#An array/list that contain all tcpUdpAcl objects, which will be written to the tmsh output
	tcpUdpAclObjectList = []
	
	icmpAclObjectList = []
	protocolGroupAclObjectList = []

	aclNameDictCount = {}

	#Hash to keep all acl names, this is used to create the initial rule lists
	aclNameDict = {}
	
	#readPortMappingFile()
	readCiscoIcmpMappingFile()
	
	ciscoPortMapDictionary = readCiscoPortMapFileToDictionary()
	
	readCiscoConfFileToHashAndList()
	
	#Read entire file into a list so we can use the list index to access the line number
	firewallFileReadonlyList,firewallFileWriteList = readFirewallFileToLists()
	
	#Read all the names and convert to a list of python objects
	nameObjectList, nameObjectCount = readFirewallFileToNameObjectList()
	
	#Read all cisco objects and convert them to python objects
	protocolGroupObjectList = readFirewallFileToProtocolGroupObjectList()
	serviceObjectList,serviceObjectReadCount = readFirewallFileToServiceObjectList(ciscoPortMapDictionary)	
	timeRangeObjectList,timeRangeObjectReadCount = readTimeRangeToObjectList()
	
	#object network objectnetwork1
 	#host 172.26.6.1
	objectNetworkList,objectNetworkReadCount = readFirewallFileToObjectNetworkList()
	objectGroupNetworkList,objectGroupNetworkReadCount = readFirewallFileToObjectGroupNetworkList(nameObjectList,objectNetworkList)
	icmpObjectList,icmpObjectReadCount = readFirewallFileToIcmpObjectList(nameObjectList)
	noPortAclList,tcpUdpAclList,icmpAclList, protocolGroupAclList, allAclCount, allIpv4AclCount, allIpv6AclCount, icmp4AclCount, icmp6AclCount, tcpUdp4AclCount, tcpUdp6AclCount, noPort4AclCount, noPort6AclCount, protocolGroup4AclCount, protocolGroup6AclCount = readAclsToLists()
	print("TcpudpAclList length: " + str (len(tcpUdpAclList)) )

	print("####Acl count from reading file, these are cisco objects and acls")
	print("All Name object Count read:					" + str(nameObjectCount))
	print("All Service object Count read:					" + str(serviceObjectReadCount))
	print("All TimeRange object Count read:				" + str(timeRangeObjectReadCount))
	print("All object network Count read:					" + str(objectNetworkReadCount))
	print("All object-group network Count read:				" + str(objectGroupNetworkReadCount))
	print("All icmp object Count read:					" + str(icmpObjectReadCount))
	print("Other IPv4 Count read:						" + str(noPort4AclCount))
	print("Other IPv6 Count read:						" + str(noPort6AclCount))
	print("Other IPv4+IPv6 Count read:					" + str(noPort4AclCount + noPort6AclCount))
	print("ICMP	IPv4 Count read:					" + str(icmp4AclCount))
	print("ICMP	IPv6 Count read:					" + str(icmp6AclCount))
	print("ICMP	IPv4+IPv6 Count read:					" + str(icmp4AclCount + icmp6AclCount))
	print("Tcp/Udp IPv4 Count read:					" + str(tcpUdp4AclCount))
	print("Tcp/Udp IPv6 Count read:					" + str(tcpUdp6AclCount))
	print("Tcp/Udp IPv4+IPv6 Count read:					" + str(tcpUdp4AclCount + tcpUdp6AclCount))
	print("ProtocolGroup IPv4 Count read:					" + str(protocolGroup4AclCount))
	print("ProtocolGroup IPv6 Count read:					" + str(protocolGroup6AclCount))
	print("ProtocolGroup IPv4+IPv6 Count read:				" + str(protocolGroup4AclCount + protocolGroup6AclCount))
	print("All IPv4 Count read:						" + str(allIpv4AclCount))
	print("All IPv6 Count read:						" + str(allIpv6AclCount))
	print("All IPv4+IPv6 Count read:					" + str(allAclCount))

		
	#If acl list is not empty then convert to objects that can be written to tmsh
	if noPortAclList:
	
		convertNoPortAclListToObjects(noPortAclList,noPortAclObjectList,aclNameDict,firewallFileReadonlyList)
		
	if tcpUdpAclList:
	
		convertTcpUdpAclListToObjects(tcpUdpAclList,tcpUdpAclObjectList,aclNameDict,firewallFileReadonlyList,ciscoPortMapDictionary)
		
	if icmpAclList:
		
		convertIcmpAclListToObjects(icmpAclList,icmpAclObjectList,aclNameDict,firewallFileReadonlyList)	
		
	if protocolGroupAclList:
	
		convertProtocolGroupAclListToObjects(protocolGroupAclList,protocolGroupAclObjectList,protocolGroupObjectList,aclNameDict,firewallFileReadonlyList,ciscoPortMapDictionary)
		
	#Write afm tmsh to file
	writeClearCommands ()
	writeServiceObjects(serviceObjectList)
	writeTimeRangeObjects(timeRangeObjectList)
	nameObjectWrittenCount = writeNameObjects(nameObjectList)
	writeObjectNetwork(objectNetworkList)
	writeObjectGroupNetwork(objectGroupNetworkList,objectNetworkList)
	
	#Afm currently does not support icmp objects
	#writeIcmpObject(icmpObjectList)
	print("\n####Acl count from writing")

	writeCreateRulesets(aclNameDict)
	noPortObjectsWrittenCount = writeNoPortAclListRules(noPortAclObjectList,aclNameDictCount,firewallFileWriteList)
	icmpObjectsWrittenCount = writeIcmpAclListRules(icmpAclObjectList,aclNameDictCount,icmpObjectList,firewallFileWriteList)
	tcpUdpAclObjectsWrittenCount, tcpUdpIpv4AclObjectsWrittenCount, tcpUdpIpv6AclObjectsWrittenCount = writeTcpUdpPortAclListRules(tcpUdpAclObjectList,aclNameDictCount,firewallFileWriteList)
	uniqueProtocolGroupAclNameCount,icmpProtocolGroupObjectsWrittenCount,tcpUdpPortObjectsProtocolGroupWrittenCount,noPortObjectsProtocolGroupWrittenCount = writeProtocolGroupAclListRules(protocolGroupAclObjectList,aclNameDictCount,tcpUdpAclObjectList,icmpObjectList,firewallFileWriteList,ciscoPortMapDictionary)

	allAclObjectsWrittenCount = tcpUdpAclObjectsWrittenCount + icmpObjectsWrittenCount + noPortObjectsWrittenCount + uniqueProtocolGroupAclNameCount
	print("All Name object Count written:					" + str(nameObjectWrittenCount))
	print("TcpUdp IPv4 Tmsh lines written: 				" + str(tcpUdpIpv4AclObjectsWrittenCount))
	print("TcpUdp IPv6 Tmsh lines written: 				" + str(tcpUdpIpv6AclObjectsWrittenCount))
	print("TcpUdp Tmsh lines written: 					" + str(tcpUdpAclObjectsWrittenCount)) 
	print("ProtocolGroup Other Tmsh lines written: 			" + str(noPortObjectsProtocolGroupWrittenCount)) 
	print("ProtocolGroup Icmp Tmsh lines written: 				" + str(icmpProtocolGroupObjectsWrittenCount))
	print("ProtocolGroup Tcp/Udp Tmsh lines written: 			" + str(tcpUdpPortObjectsProtocolGroupWrittenCount))

	print("All Tmsh lines written: 					" + str(allAclObjectsWrittenCount)) 
	print("The number of acl read should equal the number written")

	if allAclObjectsWrittenCount == allAclCount:
	
		print("The number of Acls read equals the number written!")
		
	else:
	
		print("THE NUMBER OF ACLS DOES NOT EQUAL THE NUMBER WRITTEN, PLEASE CHECK THE LOG (this may not be an issue, if acls or objects were unnested this is likely normal: " + ACLNOTWRITTENLOG)
	

	#Close any open files
	if DEBUG == 1:
		DEBUGLOGHANDLE.closed
				
	return
	
#Begin execution
main()