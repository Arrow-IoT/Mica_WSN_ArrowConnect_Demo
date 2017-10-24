#!/usr/bin/python

#============================ adjust path =====================================

import sys
import os
if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, 'smartmeshsdk', 'libs'))
    sys.path.insert(0, os.path.join(here, 'smartmeshsdk', 'external_libs'))

#============================ verify installation =============================

from SmartMeshSDK.utils import SmsdkInstallVerifier
(goodToGo,reason) = SmsdkInstallVerifier.verifyComponents(
    [
        SmsdkInstallVerifier.PYTHON,
        SmsdkInstallVerifier.PYSERIAL,
    ]
)
if not goodToGo:
    print "Your installation does not allow this application to run:\n"
    print reason
    raw_input("Press any button to exit")
    sys.exit(1)

#============================ imports =========================================

import random
import traceback
from SmartMeshSDK                       import sdk_version
from SmartMeshSDK.IpMgrConnectorSerial  import IpMgrConnectorSerial
from SmartMeshSDK.IpMoteConnector       import IpMoteConnector
from SmartMeshSDK.utils                 import AppUtils, \
                                               FormatUtils

#============================ logging =========================================

# local
import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('App')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

# global
AppUtils.configureLogging()

#============================ defines =========================================

DEFAULT_MGRSERIALPORT   = 'COM52'

#============================ helper functions ================================

#============================ main ============================================

try:
    manager        = IpMgrConnectorSerial.IpMgrConnectorSerial()
    
    print 'ACL Commissioning (c) Dust Networks'
    print 'SmartMesh SDK {0}\n'.format('.'.join([str(b) for b in sdk_version.VERSION]))
    
    print '==== Connect to manager'
    serialport     = ""
    if not serialport:
        serialport = DEFAULT_MGRSERIALPORT
	manager.connect({'port': serialport})
	print 'Connected to manager at {0}.\n'.format(serialport)
	
	joinKey = [0x44, 0x55, 0x53, 0x54, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53, 0x52, 0x4F, 0x43, 0x4B]
	mac = [0x00, 0x17, 0x0d, 0x00, 0x00, 0x30, 0xb3, 0x5c]
	print "Setting ACL for {0} to {1}".format(FormatUtils.formatBuffer(mac), joinKey)
	manager.dn_setACLEntry(macAddress = mac, joinKey = joinKey)
	
	joinKey = [0x44, 0x55, 0x53, 0x54, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53, 0x52, 0x4F, 0x43, 0x4B]
	mac = [0x00, 0x17, 0x0d, 0x00, 0x00, 0x30, 0xb6, 0x81]
	print "Setting ACL for {0} to {1}".format(FormatUtils.formatBuffer(mac), joinKey)
	manager.dn_setACLEntry(macAddress = mac, joinKey = joinKey)
	
	joinKey = [0x44, 0x55, 0x53, 0x54, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53, 0x52, 0x4F, 0x43, 0x4B]
	print "Setting common join key to {0}".format(FormatUtils.formatBuffer(joinKey))
	manager.dn_setCommonJoinKey(joinKey)
    
	networkId = 1337
	apTxPower = 8 # TX power 8
	frameProfile = 1 # Frame profile 1
	maxMotes = 33
	baseBandwidth = 9000
	downFrameMultVal = 1
	numParents = 2
	ccaMode = 0 # off
	channelList = 32767
	autoStartNetwork = True
	locMode = 0
	bbMode = 0 # off
	bbSize = 1
	isRadioTest = 0
	bwMult = 300
	oneChannel = 255
	
	print "Setting network ID to {0}".format(networkId)
	manager.dn_setNetworkConfig(networkId = networkId, apTxPower = apTxPower,
		frameProfile = frameProfile, maxMotes = maxMotes,
		baseBandwidth = baseBandwidth, downFrameMultVal = downFrameMultVal,
		numParents = numParents, ccaMode = ccaMode, channelList = channelList,
		autoStartNetwork = autoStartNetwork, locMode = locMode, bbMode = bbMode,
		bbSize = bbSize, isRadioTest = isRadioTest, bwMult = bwMult, 
		oneChannel = oneChannel)
    
	print "Resetting manager"
	mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	manager.dn_reset(0, mac) # System Reset
	
    print '\n\n==== disconnect from manager'
    manager.disconnect()
    print 'done.\n'

except Exception as err:
    output  = []
    output += ['=============']
    output += ['CRASH']
    output += [str(err)]
    output += [traceback.format_exc()]
    print '\n'.join(output)
else:
    print 'Script ended normally'
finally:
	raw_input("Press Enter to close.")