#The below variables can be used to alter the behavior of the asatoafm.py script

#Generally not recommended to change
portMappingFile="services"
ciscoPortMapFile="ciscoPortNameToNumberMapping.txt"
MAINLOGDIR="logs/"

CISCOTMSHLOGEXTENSION=".ciscotmsh"
CISCOTMSHLOGDIR=MAINLOGDIR + "ciscotmsh/"
ICMPOBJECTSEXPAND=1
NETWORKGROUPOBJECTSEXPAND=1
CISCOICMPMAPPINGFILE="ciscoicmptype.txt"

DEBUG=1
DEBUGLOG=""

DEBUGLOGDIR=MAINLOGDIR + "debug/"
DEBUGLOGEXTENSION=".log"

ERRORLOG=""
ERRORLOGDIR=MAINLOGDIR + "error/"
ERRORLOGEXTENSION=".log"

ACLNOTWRITTENLOG=""
ACLNOTWRITTENLOGDIR=MAINLOGDIR + "aclnotwritten/"
ACLNOTWRITTENLOGEXTENSION=".log"

OUTPUTDIR="output/"


TMSHAFMFILEEXTENSION=".tmsh"

CISCOTMSHLOG=""
TMSHAFMFILE=""


#The should be changed based on your requirements
ENABLELOGGING=1

#1 prints out tmsh delete /security firewall rule-list all
#tmsh delete /security firewall port-list all
#tmsh delete /security firewall address-list all
ENABLECLEARCOMMANDS=1

#If AFM is v11.4.1 or less, need to unnest port/service objects, they are not supportted until 11.5
UNNESTPORTOBJECTS=1

#Set this to 1 if you need to unnest a object-group w/ group-objects
#object-group network networknestedgroup1
# network-object host 5.5.5.6
# group-object networkgroup1
#AFM prior to 11.5.1 need this set to 1, 11.5.1 and later can use 0 (don't unnest or 1 unnest)
UNNESTNETWORKOBJECTS=1

#AFM does not support the grouping of ip protocols as of 11.5, so this must be set to 1
UNNESTPROTOCOLGROUPOBJECTS=1
