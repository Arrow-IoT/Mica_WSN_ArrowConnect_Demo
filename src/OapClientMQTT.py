#!/usr/bin/python

#============================ adjust path =====================================

import sys
import os
if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, 'smartmeshsdk','libs'))
    sys.path.insert(0, os.path.join(here, 'smartmeshsdk','external_libs'))

#============================ imports =========================================

import time
import threading
import traceback

from SmartMeshSDK.utils                           import FormatUtils
from SmartMeshSDK.IpMgrConnectorSerial            import IpMgrConnectorSerial
from SmartMeshSDK.IpMgrConnectorMux               import IpMgrSubscribe
from SmartMeshSDK.ApiException                    import APIError, \
                                                         ConnectionError,  \
                                                         CommandTimeoutError
from SmartMeshSDK.protocols.oap                   import OAPDispatcher, \
                                                         OAPClient,     \
                                                         OAPMessage,    \
                                                         OAPNotif
from SmartMeshSDK import sdk_version

#============================ defines =========================================

NUM_BCAST_TO_SEND  = 2
DEFAULT_SERIALPORT = 'COM52'

#============================ globals =========================================

#============================ helpers =========================================
def macToMoteId(macCheck):
    operationalmotes = [] 
    # get list of operational motes
    currentMac     = (0,0,0,0,0,0,0,0) # start getMoteConfig() iteration with the 0 MAC address
    continueAsking = True
    while continueAsking:
        try:
            res = AppData().get('connector').dn_getMoteConfig(currentMac,True)
        except APIError:
            continueAsking = False
        else:
            if ((not res.isAP) and (res.state in [4,])):
                operationalmotes += [tuple(res.macAddress)]
            currentMac = res.macAddress
    AppData().set('operationalmotes',operationalmotes)
    
    for i in operationalmotes:
        shortMac = ':'.join(["%.2x"%m for m in i[4:]])
        if (shortMac == macCheck):
            return operationalmotes.index(i)
    return -1
    
def getMgrMac():
    sysInfo = AppData().get('connector').dn_getSystemInfo()
    return(sysInfo.macAddress)
    
def printExcAndQuit(err):
    output  = []
    output += ["="*30]
    output += ["error"]
    output += [str(err)]
    output += ["="*30]
    output += ["traceback"]
    output += [traceback.format_exc()]
    output += ["="*30]
    output += ["Script ended because of an error. Press Enter to exit."]
    output  = '\n'.join(output)
    
    raw_input(output)
    sys.exit(1)

def getOperationalMotes():

    operationalmotes = [] 
    # get list of operational motes
    currentMac     = (0,0,0,0,0,0,0,0) # start getMoteConfig() iteration with the 0 MAC address
    continueAsking = True
    while continueAsking:
        try:
            res = AppData().get('connector').dn_getMoteConfig(currentMac,True)
        except APIError:
            continueAsking = False
        else:
            if ((not res.isAP) and (res.state in [4,])):
                operationalmotes += [tuple(res.macAddress)]
            currentMac = res.macAddress
    AppData().set('operationalmotes',operationalmotes)
    
    # create an oap_client for each operational mote
    oap_clients = AppData().get('oap_clients')
    for mac in operationalmotes:
        if mac not in oap_clients:
            oap_clients[mac] = OAPClient.OAPClient(
                mac,
                AppData().get('connector').dn_sendData,
                AppData().get('oap_dispatch'),
            )
    
    return len(operationalmotes)
    
def printOperationalMotes():
    output  = []
    numMotes = len(AppData().get('operationalmotes'))
    output += ["{0} operational motes:".format(numMotes)]
    payload = "{\"s|devices\": \""
    for (i,m) in enumerate(AppData().get('operationalmotes')):
        output += ['{0}: {1}'.format(i,FormatUtils.formatMacString(m))]
        payload += ':'.join(["%.2x"%i for i in m[4:]])
        payload += ', ' 
    if (numMotes > 0):
        payload = payload[:-2]
    payload += "\"}"
    
    output  = '\n'.join(output)
    topic = '{0}/{1}/json'.format(MGR_TYPE, ':'.join(["%.2x"%i for i in getMgrMac()[4:]]))
    client.publish(topic, payload)
    print output

def selectOperationalMote(moteNum):
    
    if moteNum>len(AppData().get('operationalmotes')):
        print 'Cannot select mote {0}, there are only {1} motes'.format(
            moteNum,
            len(AppData().get('operationalmotes')),
        )
        return
    
    AppData().set('currentmote',moteNum)
    
    print '\nCurrently using mote {0} ({1}).'.format(
        AppData().get('currentmote'),
        FormatUtils.formatMacString(AppData().get('operationalmotes')[AppData().get('currentmote')])
    )

def togglePrintNotifs():
    
    if AppData().get('printNotifs')==False:
        AppData().set('printNotifs',True)
        print "notifications are ON."
    else:
        AppData().set('printNotifs',False)
        print "notifications are OFF."

def toggleLogNotifs():
    
    if AppData().get('logNotifs')==False:
        AppData().set('logNotifs',True)
        print "logging to logfile is ON."
    else:
        AppData().set('logNotifs',False)
        print "logging to logfile is OFF."

#============================ classes =========================================

class AppData(object):
    #======================== singleton pattern ===============================
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AppData, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        # singleton
        if self._init:
            return
        self._init = True
        # variables
        self.dataLock   = threading.RLock()
        self.data       = {}
    #======================== public ==========================================
    def set(self,k,v):
        with self.dataLock:
            self.data[k] = v
    def get(self,k):
        with self.dataLock:
            return self.data[k]
    def delete(self,k):
        with self.dataLock:
            del self.data[k]

class Manager(object):
    
    def __init__(self):
        
        # OAP dispatcher
        AppData().set('oap_dispatch',OAPDispatcher.OAPDispatcher())
        AppData().get('oap_dispatch').register_notif_handler(self._handle_oap_notif)
        
        # subscriber
        self.subscriber = IpMgrSubscribe.IpMgrSubscribe(AppData().get('connector'))
        self.subscriber.start()
        self.subscriber.subscribe(
            notifTypes =    [
                                IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA,
                            ],
            fun =           self._cb_NOTIFDATA,
            isRlbl =        False,
        )
        self.subscriber.subscribe(
            notifTypes =    [
                                IpMgrSubscribe.IpMgrSubscribe.NOTIFEVENT
                            ],
            fun =           self.handle_event,
            isRlbl =        False,
        )
        
        # list operational motes
        AppData().set('oap_clients',{})
        numMotes = getOperationalMotes()
        if numMotes:
            printOperationalMotes()
            selectOperationalMote(0)
        AppData().set('printNotifs',False)
        togglePrintNotifs()

        # Added to calculate Mgr vs system time offset in the log prints
        self.mapmgrtime = MgrTime(0, 20)
        self.mapmgrtime.start()
        
    #======================== public ==========================================
    
    def disconnect(self):
        AppData().get('connector').disconnect()
        self.log_file.close()
    
    #======================== private =========================================
    
    def _cb_NOTIFDATA(self,notifName,notifParams):
        msg = notifParams.data
        if (msg[0] == 0xfa): # Look for 0xFA - beginning of data packet
            numMeasures = msg[4] # 4th byte of message is number of measurements in packet
            meas = []
            humidityRead = False
            for m in range(0, numMeasures):
                meas = msg[(5 + (m * 5)):(10 + (m * 5))]
                measurement = (meas[1] << 24) | (meas[2] << 16) | (meas[3] << 8) | meas[4]
                if meas[0] == 0x7b: # temperature and humidity share the same message id
                    if humidityRead: # if humidity was read, other byte is temperature
                        new = (meas[4] << 8) | meas[3]
                        msb = (( new >> 8 ) * 64 )
                        lsb = (( new & 255) >> 2 ) / 4.0
                        extTemp = ((( msb + lsb ) / ( 2.0 ** 14 )) * 165) - 40
                        mqtt_publish(notifParams.macAddress, DEVICE_TYPE, 'extTemperature', extTemp, 'f')
                    else: # If humidity hasn't been read yet, that's what this is
                        new = ((meas[4] << 8) | meas[3]) & int('0x3FFF', 16)
                        msb = (( new >> 8 ) & 63) * 256
                        lsb = (( new & 255))
                        extHumidity = (( msb + lsb ) / ( 2.0 ** 14 )) * 100
                        mqtt_publish(notifParams.macAddress, DEVICE_TYPE, 'extHumidity', extHumidity, 'f')
                        humidityRead = True
                elif meas[0] == 0x1e: # Lux measurement
                    exp = meas[3] >> 4
                    man = ((meas[3] & 0x0F) << 8) | meas[4]
                    lux = man * 0.001 * 2**exp
                    mqtt_publish(notifParams.macAddress, DEVICE_TYPE, 'lux', lux, 'f')
                elif meas[0] == 0x14: # Internal temperature measurement
                    intTemp = measurement * 175.72/65536.0 - 46.85
                    mqtt_publish(notifParams.macAddress, DEVICE_TYPE, 'intTemperature', intTemp, 'f')
                elif meas[0] == 0x15: # internal humidity measurement
                    intHumidity = measurement * 125/65536.0 - 6
                    mqtt_publish(notifParams.macAddress, DEVICE_TYPE, 'intHumidity', intHumidity, 'f')
                elif meas[0] == 0x1a: # interrupt event
                    if meas[3] == 0x1f: # PIR triggered
                        mqtt_publish(notifParams.macAddress, DEVICE_TYPE, 'motion', meas[4], 'i')
                    elif meas[3] == 0x12: # Power button event
                        mqtt_publish(notifParams.macAddress, DEVICE_TYPE, 'power', meas[4], 'i')
        AppData().get('oap_dispatch').dispatch_pkt(notifName, notifParams)
        if AppData().get('logNotifs'):
            if notifParams.data[0] == 0:
                self.log_file.write (' Pkt queued Time  ---> {0}.{1:0>6}\n'.format(notifParams.utcSecs, notifParams.utcUsecs))

    def _handle_oap_notif(self,mac,notif):
        topic = '{0}/{1}/json'.format(DEVICE_TYPE, ':'.join(["%.2x"%i for i in mac[4:]]))
        print "OAP notification"
        if isinstance(notif,OAPNotif.OAPTempSample):
            payload = '{{\"f|temperature\": \"{TEMPERATURE}\", \"i|tRate\": \"{RATE}\", \"i|sampleSize\": \"{SAMPLE_SIZE}\", \"i|tTime\": {TIME}}}'.format(
                TEMPERATURE = float(notif.samples[0])/100,
                RATE = notif.rate,
                SAMPLE_SIZE = notif.sample_size,
                TIME = int(round((float(time.time()) - self.mapmgrtime.pctomgr_time_offset), 0)))
        elif isinstance(notif,OAPNotif.OAPAnalogSample):
            payload = '{{\"i|analog{CH}\": \"{ANALOG}\", \"i|a{CH}Rate\": \"{RATE}\", \"i|aSampleSize\": \"{SAMPLE_SIZE}\", \"i|aTime\": {TIME}}}'.format(
                CH = notif.channel[1],
                ANALOG = int(round(float(notif.samples[0]))),
                RATE = notif.rate,
                SAMPLE_SIZE = notif.sample_size,
                TIME = int(round((float(time.time()) - self.mapmgrtime.pctomgr_time_offset), 0)))
        client.publish(topic, payload)
    
    def handle_event(self, notifName, notifParams):
        topic = '{0}/{1}/json'.format(DEVICE_TYPE, ':'.join(["%.2x"%i for i in notifParams.macAddress[4:]]))
        if notifName == 'eventMoteJoin':
            print "Mote joined: {0}".format(FormatUtils.formatMacString(notifParams.macAddress))
            payload = '{\"s|state\": \"joined\"}'
        elif notifName == 'eventMoteOperational':
            print "Mote operational: {0}".format(FormatUtils.formatMacString(notifParams.macAddress))
            payload = '{\"s|state\": \"operational\"}'
        elif notifName == 'eventPathDelete':
            print "Path deleted: from {0} to {1} ({2})".format(formatMacString(notifParams.source), formatMacString(notifParams.dest), notifParams.direction)
        elif notifName == 'eventPathCreate':
            print "Path create: from {0} to {1} ({2})".format(formatMacString(notifParams.source), formatMacString(notifParams.dest), notifParams.direction)
        elif notifName == 'eventMoteLost':
            print "Mote disconnected: {0}".format(FormatUtils.formatMacString(notifParams.macAddress))
            payload = '{\"s|state\": \"lost\"}'
        else:
            print "Event: {0}\r\nData:[{1}]".format(notifName, notifParams)
        client.publish(topic, payload)
        getOperationalMotes()
        printOperationalMotes()

class MgrTime(threading.Thread):
    '''
    This class periodically sends a getTime() API command to the manager to map
    network time to UTC time. The offset is used to calculate the pkt arrival
    time for the same time base as the mote.
    '''

    def __init__(self, pctomgr_time_offset, sleepperiod):
        # init the parent
        threading.Thread.__init__(self)
        self.event                  = threading.Event()
        self.sleepperiod            = sleepperiod
        self.daemon                 = True
        self.pctomgr_time_offset    = pctomgr_time_offset
        # give this thread a name
        self.name                   = 'MgrTime'               

    def run(self):
        while True:
            # Get PC time and send the getTime command to the Manager
            pc_time = float(time.time())
            mgr_timepinres = AppData().get('connector').dn_getTime()
            mgr_time = mgr_timepinres.utcSecs + mgr_timepinres.utcUsecs / 1000000.0
            mgr_asn = int(''.join(["%02x"%i for i in mgr_timepinres.asn]),16)
            self.pctomgr_time_offset = pc_time - mgr_time
            
            self.event.wait(self.sleepperiod)

#============================ CLI handlers ====================================

def connect(params):
    
    # filter params
    #port = params[0]
    port = params
    
    try:
        AppData().get('connector')
    except KeyError:
        pass
    else:
        print 'already connected.'
        return
    
    # create a connector
    AppData().set('connector',IpMgrConnectorSerial.IpMgrConnectorSerial())
    
    # connect to the manager
    try:
        AppData().get('connector').connect({
            'port': port,
        })
    except ConnectionError as err:
        print 'Could not connect to {0}: {1}'.format(
            port,
            err,
        )
        AppData().delete('connector')
        return
    
    # start threads
    AppData().set('manager',Manager())

def oapinfo_response(mac, oap_resp):
    output  = []
    output += ["GET /info response from {0}:".format(FormatUtils.formatMacString(mac))]
    output  = '\n'.join(output)
    
    print output
    print (mac, oap_resp)

def info_clicb(params):
    moteSelected = macToMoteId(params[0])
    if moteSelected < 0:
        print 'moteId invalid'
        return
        
    # filter params
    moteId    = moteSelected
    
    if moteId>len(AppData().get('operationalmotes')):
        print 'moteId {0} impossible, there are only {1} motes'.format(
            moteId,
            len(AppData().get('operationalmotes')),
        )
        return
    
    AppData().get('oap_clients')[AppData().get('operationalmotes')[moteId]].send(
        cmd_type   = OAPMessage.CmdType.GET,
        addr       = [0],
        data_tags  = [],
        cb         = oapinfo_response,
    )

def led(params):
    moteSelected = macToMoteId(params[0])
    if moteSelected < 0:
        print 'moteId invalid'
        return
    
    try:
        moteId    =  moteSelected
        isBcast   = False
    except:
        isBcast   = True
    ledState  = params[1]
    
    if moteId>len(AppData().get('operationalmotes')):
        print 'moteId {0} impossible, there are only {1} motes'.format(
            moteId,
            len(AppData().get('operationalmotes')),
        )
        return
    
    if ledState=="0":
        ledVal = 0
    else:
        ledVal = 1
    
    # send OAP command ... single or all broadcast
    if not isBcast:
        AppData().get('oap_clients')[AppData().get('operationalmotes')[moteId]].send(
            cmd_type   = OAPMessage.CmdType.PUT,
            addr       = [3,2],
            data_tags  = [OAPMessage.TLVByte(t=0,v=ledVal)],
        )
    else:
        # build OAP message
        oap_msg = OAPMessage.build_oap(
            seq          = 0,
            sid          = 0,
            cmd          = OAPMessage.CmdType.PUT,
            addr         = [3,2],
            tags         = [OAPMessage.TLVByte(t=0,v=ledVal)],
            sync         = True,
        )
        oap_msg = [ord(b) for b in oap_msg]
        
        # send OAP message broadcast NUM_BCAST_TO_SEND times
        for i in range (NUM_BCAST_TO_SEND):
            AppData().get('connector').dn_sendData(
                macAddress   = [0xff]*8,
                priority     = 0,
                srcPort      = OAPMessage.OAP_PORT,
                dstPort      = OAPMessage.OAP_PORT,
                options      = 0x00,
                data         = oap_msg,
            )

def temperature(params):
    
    moteSelected = macToMoteId(params[0])
    if moteSelected < 0:
        print 'moteId invalid'
        return
    # filter params
    try:
        moteId    = moteSelected
        isBcast   = False
    except:
        isBcast   = True 
    tempOn      = int(params[1])
    pktPeriod   = int(params[2])
    
    if moteId>len(AppData().get('operationalmotes')):
        print 'moteId {0} impossible, there are only {1} motes'.format(
            moteId,
            len(AppData().get('operationalmotes')),
        )
        return
    
    # send OAP command ... single or all broadcast
    if not isBcast:
        AppData().get('oap_clients')[AppData().get('operationalmotes')[moteId]].send(
            cmd_type   = OAPMessage.CmdType.PUT,
            addr       = [5],
            data_tags  = [
                OAPMessage.TLVByte(t=0,v=tempOn),
                OAPMessage.TLVLong(t=1,v=pktPeriod),
            ],
        )
    else:
        # build OAP message
        oap_msg = OAPMessage.build_oap(
            seq          = 0,
            sid          = 0,
            cmd          = OAPMessage.CmdType.PUT,
            addr         = [5],
            tags         = [
                OAPMessage.TLVByte(t=0,v=tempOn),
                OAPMessage.TLVLong(t=1,v=pktPeriod),
            ],
            sync         = True,
        )
        oap_msg = [ord(b) for b in oap_msg]
        
        # send OAP message broadcast NUM_BCAST_TO_SEND times
        for i in range (NUM_BCAST_TO_SEND):
            AppData().get('connector').dn_sendData(
                macAddress   = [0xff]*8,
                priority     = 0,
                srcPort      = OAPMessage.OAP_PORT,
                dstPort      = OAPMessage.OAP_PORT,
                options      = 0x00,
                data         = oap_msg,
            )

def analog_clicb(params):
    moteSelected = macToMoteId(params[0])
    if moteSelected < 0:
        print 'moteId invalid'
        return
    # filter params
    moteId         = moteSelected
    channel        = int(params[1])
    enable         = int(params[2])
    rate           = int(params[3])
    if (rate == 0):
        rate = 30000
    
    print 'Setting {0} analog {1} rate to {2} ({3})'.format(moteId, channel, rate, enable)
    
    if moteId>len(AppData().get('operationalmotes')):
        print 'moteId {0} impossible, there are only {1} motes'.format(
            moteId,
            len(AppData().get('operationalmotes')),
        )
        return
    
    AppData().get('oap_clients')[AppData().get('operationalmotes')[moteId]].send(
        cmd_type   = OAPMessage.CmdType.PUT,
        addr       = [4,channel],
        data_tags  = [
            OAPMessage.TLVByte(t=0,v=enable),  # enable
            OAPMessage.TLVLong(t=1,v=rate),    # rate
        ],
    )

def quit_clicb():
    
    if AppData().get('connector'):
        AppData().get('connector').disconnect()
    if AppData().get('manager'):
        AppData().get('manager').disconnect()
    
    time.sleep(.3)
    print "bye bye."
	
#============================ mqtt ============================================
import paho.mqtt.client as mqtt

MQTT_HOST = 'localhost'
DEVICE_TYPE = 'Vicotee'
MGR_TYPE = 'DC2274A'

def on_connect(client, userdata, flags, rc):
	print("Connected to MQTT broker with result code " + str(rc))
	
	# Subscribing in on_connect means if we lose connection and reconnect, then
	# subscriptions will be renewed
	client.subscribe("#")

def on_message(client, userdata, msg):
    topic = msg.topic.split('/')
    devType = topic[0]    
    uid = topic[1]
    cmd = topic[2]
    if (cmd == 'led'):
        print("Setting LED " + msg.payload)
        if (msg.payload == '0'):
            ledValue = '0'
        else:
            ledValue = '1'
        params = [uid, ledValue]
        led(params)
    elif (cmd == 'temp'):
        print("Setting temp " + msg.payload)
        tempRate = msg.payload;
        if (tempRate > 0):
            tempOn = '1'
        else:
            tempOn = '0'
        params = [uid, tempOn, tempRate]
        temperature(params)
    elif (cmd == 'motes'):
        getOperationalMotes()
        printOperationalMotes()
    elif (cmd == 'analog0'):
        analogRate = msg.payload;
        if (analogRate == '0'):
            analogOn = 0
        else:
            analogOn = 1
        params = [uid, '0', analogOn, analogRate]
        analog_clicb(params)
    elif (cmd == 'analog1'):
        analogRate = msg.payload;
        if (analogRate == '0'):
            analogOn = 0
        else:
            analogOn = 1
        params = [uid, '1', analogOn, analogRate]
        analog_clicb(params)
    elif (cmd == 'analog2'):
        analogRate = msg.payload;
        if (analogRate == '0'):
            analogOn = 0
        else:
            analogOn = 1
        params = [uid, '2', analogOn, analogRate]
        analog_clicb(params)
    elif (cmd == 'analog3'):
        analogRate = msg.payload;
        if (analogRate == '0'):
            analogOn = 0
        else:
            analogOn = 1
        params = [uid, '3', analogOn, analogRate]
        analog_clicb(params)
    elif (cmd == 'info'):
        params = [uid]
        info_clicb(params)
    elif (cmd == 'get'):
        print(getOperationalMotes())
    #else:
        #print(msg.topic + ": "  + str(msg.payload))

def mqtt_publish(deviceID, deviceType, topic, value, type):
    output  = []
    numMotes = len(AppData().get('operationalmotes'))
    output += ["{0} operational motes:".format(numMotes)]
    payload = "{\"" + type + "|" + topic + "\": " + str(value) + "}"
    topic = '{0}/{1}/json'.format(deviceType, ':'.join(["%.2x"%i for i in deviceID[4:]]))
    print topic + ' [' + payload + ']'
    client.publish(topic, payload)    
    
client = mqtt.Client()

client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_HOST, 1883, 60)

#============================ main ============================================

def main():
        
    # print SmartMesh SDK version
    print 'SmartMesh SDK {0}'.format('.'.join([str(i) for i in sdk_version.VERSION]))
    connect(DEFAULT_SERIALPORT)
    # Blocking call that processes network traffic, dispatches callbacks and handles reconnecting.
    client.loop_forever()

if __name__=='__main__':
    main()
