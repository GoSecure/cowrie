import ConfigParser
import time
import uuid

from twisted.internet import protocol
from twisted.manhole import telnet
from twisted.conch import recvline
from twisted.conch.telnet import AuthenticatingTelnetProtocol, ECHO, \
                                 ITelnetProtocol, TelnetTransport, \
                                 TelnetProtocol, StatefulTelnetProtocol
from twisted.conch.insults import insults
from twisted.conch.ssh import session
from twisted.cred import credentials
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log, components

from cowrie.core.credentials import UsernamePasswordIP
from cowrie.core.honeypot import HoneyPotShell
from cowrie.core.protocol import HoneyPotInteractiveProtocol
from cowrie.core.ssh import CowrieUser, HoneyPotSSHSession, SSHSessionForCowrieUser
from cowrie.insults import insults

class HoneyPotTelnetProtocol(AuthenticatingTelnetProtocol, TimeoutMixin):

    def connectionMade(self):

        self.transportId = uuid.uuid4().hex[:8]

        # FIXME couldn't figure out how to access sessionno, might be needed only post-auth
        #       idea: check if 'New connection' is an outer protocol thing or an internal one
        log.msg(eventid='COW0001',
           format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s)',
           src_ip=self.transport.getPeer().host, src_port=self.transport.getPeer().port,
           dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
           id=self.transportId)

        # p/Cisco telnetd/ d/router/ o/IOS/ cpe:/a:cisco:telnet/ cpe:/o:cisco:ios/a
        # NB _write() is for raw data and write() handles telnet special bytes
        self.transport._write("\xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd\0\xff\xfd\x1f\r\n")
        self.transport.write(self.factory.banner)
        self.transport._write("User Access Verification\r\n\r\nUsername: ")

        self.setTimeout(120)

    # FIXME TelnetTransport is throwing an exception when client disconnects
    def connectionLost(self, reason):
        """
        This seems to be the only reliable place of catching lost connection
        """
        self.setTimeout(None)
        # FIXME couldn't figure out how to access sessionno, might be needed only post-auth
        #if self.transport.sessionno in self.factory.sessions:
        #    del self.factory.sessions[self.transport.sessionno]
        self.transport.connectionLost(reason)
        self.transport = None
        log.msg(eventid='COW0011', format='Connection lost')

    def telnet_Password(self, line):
        username, password = self.username, line
        del self.username
        def login(ignored):
            self.src_ip = self.transport.getPeer().host
            creds = UsernamePasswordIP(username, password, self.src_ip)
            d = self.portal.login(creds, self.src_ip, ITelnetProtocol)
            d.addCallback(self._loginSuccess)
            d.addErrback(self._ebLogin)
        self.transport.wont(ECHO).addCallback(login)

        log.msg(eventid="COW0001", 
                format="USERNAME: %(user)s, PASSWORD: %(pw)s",
                user=username, pw=password)
        return 'Discard'

    def _loginSuccess(self, ial):
        """
        """
        interface, protocol, logout = ial
        self.protocol = protocol
        self.logout = logout
        self.state = 'Command'

        # TODO is this the way forward?
        #self.protocol = protocol.LoggingServerProtocol(
        #    protocol.HoneyPotInteractiveProtocol, self)
        #self.protocol.makeConnection(protocol)
        #protocol.makeConnection(session.wrapProtocol(self.protocol))

        protocol.makeConnection(self.transport)
        self.transport.protocol = protocol

class HoneyPotTelnetFactory(protocol.ServerFactory):

    def __init__(self, cfg):
        self.cfg = cfg

    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        for dblog in self.dbloggers:
            dblog.logDispatch(*msg, **args)
        for output in self.output_plugins:
            output.logDispatch(*msg, **args)

    def startFactory(self):
        """
        """
        # The banner to serve
        honeyfs = self.portal.realm.cfg.get('honeypot', 'contents_path')
        issuefile = honeyfs + "/etc/issue.net"
        self.banner = file(issuefile).read()

        # Interactive protocols are kept here for the interact feature
        self.sessions = {}

        # For use by the uptime command
        self.starttime = time.time()

        # Load db loggers
        self.dbloggers = []
        for x in self.cfg.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            try:
                dblogger = __import__( 'cowrie.dblog.{}'.format(engine),
                    globals(), locals(), ['dblog']).DBLogger(self.cfg)
                log.addObserver(dblogger.emit)
                self.dbloggers.append(dblogger)
                log.msg("Loaded dblog engine: {}".format(engine))
            except:
                log.err()
                log.msg("Failed to load dblog engine: {}".format(engine))

        # Load output modules
        self.output_plugins = []
        for x in self.cfg.sections():
            if not x.startswith('output_'):
                continue
            engine = x.split('_')[1]
            try:
                output = __import__( 'cowrie.output.{}'.format(engine),
                    globals(), locals(), ['output']).Output(self.cfg)
                log.addObserver(output.emit)
                self.output_plugins.append(output)
                log.msg("Loaded output engine: {}".format(engine))
            except:
                log.err()
                log.msg("Failed to load output engine: {}".format(engine))

        # hook protocol
        self.protocol = lambda: TelnetTransport(HoneyPotTelnetProtocol,
                                                self.portal)

        protocol.ServerFactory.startFactory(self)

    def stopFactory(self):
        """
        """
        for output in self.output_plugins:
            output.stop()
        protocol.ServerFactory.stopFactory(self)

class MyTelnet(StatefulTelnetProtocol):

    def connectionMade(self):
        # TODO send motd like SSH
        self.sendLine("\nLogin successful.")

    def lineReceived(self, line):
        self.transport.write("I received %r from you\r\n" % (line,))

#     def makeProtocol(self):
#         # FIXME port to realm/portal
#         #user = CowrieUser("root", server.CowrieServer(args[0]))
#         
#         serverProtocol = insults.ServerProtocol(
#             HoneyPotInteractiveProtocol, self)
#         serverProtocol.makeConnection(protocol)
#         protocol.makeConnection(session.wrapProtocol(serverProtocol))
#         return serverProtocol
#     
# 
#     def buildProtocol(self, addr):
#         pass
#         """
#         Create an instance of the server side of the Telnet protocol.
# 
#         @type addr: L{twisted.internet.interfaces.IAddress} provider
#         @param addr: The address at which the server will listen.
# 
#         @rtype: L{cowrie.core.HoneyPotTelnetTransport}
#         @return: The built transport.
#         """
# 
#         t = HoneyPotTelnetTransport()
# 
#         t.supportedPublicKeys = list(self.privateKeys.keys())
# 
#         for _moduli in _modulis:
#             try:
#                 self.primes = primes.parseModuliFile(_moduli)
#                 break
#             except IOError as err:
#                 pass
# 
#         if not self.primes:
#             ske = t.supportedKeyExchanges[:]
#             ske.remove('diffie-hellman-group-exchange-sha1')
#             t.supportedKeyExchanges = ske
#             log.msg("No moduli, disabled diffie-hellman-group-exchange-sha1")
# 
#         # Reorder supported ciphers to resemble current openssh more
#         t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr',
#             'aes128-cbc', '3des-cbc', 'blowfish-cbc', 'cast128-cbc',
#             'aes192-cbc', 'aes256-cbc']
#         t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
#         t.supportedMACs = ['hmac-md5', 'hmac-sha1']
# 
#         t.factory = self
#         return t
# 
# 
# 
# class HoneyPotTelnetTransport(transport.SSHServerTransport, TimeoutMixin):
#     """
#     """
# 
#     def connectionMade(self):
#         """
#         Called when the connection is made from the other side.
#         We send our version, but wait with sending KEXINIT
#         """
#         self.transportId = uuid.uuid4().hex[:8]
# 
#         log.msg(eventid='COW0001',
#            format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(sessionno)s]',
#            src_ip=self.transport.getPeer().host, src_port=self.transport.getPeer().port,
#            dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
#            id=self.transportId, sessionno=self.transport.sessionno)
# 
#         self.transport.write('{}\r\n'.format(self.ourVersionString))
#         self.currentEncryptions = transport.SSHCiphers('none', 'none', 'none', 'none')
#         self.currentEncryptions.setKeys('', '', '', '', '', '')
#         self.setTimeout(120)
# 
# 
#     def sendKexInit(self):
#         """
#         Don't send key exchange prematurely
#         """
#         if not self.gotVersion:
#             return
#         transport.SSHServerTransport.sendKexInit(self)
# 
# 
#     def dataReceived(self, data):
#         """
#         First, check for the version string (SSH-2.0-*).  After that has been
#         received, this method adds data to the buffer, and pulls out any
#         packets.
# 
#         @type data: C{str}
#         """
#         self.buf = self.buf + data
#         if not self.gotVersion:
#             if not '\n' in self.buf:
#                 return
#             self.otherVersionString = self.buf.split('\n')[0].strip()
#             if self.buf.startswith('SSH-'):
#                 self.gotVersion = True
#                 remoteVersion = self.buf.split('-')[1]
#                 if remoteVersion not in self.supportedVersions:
#                     self._unsupportedVersionReceived(remoteVersion)
#                     return
#                 i = self.buf.index('\n')
#                 self.buf = self.buf[i+1:]
#                 self.sendKexInit()
#             else:
#                 self.transport.write('Protocol mismatch.\n')
#                 log.msg('Bad protocol version identification: %s' % (self.otherVersionString,))
#                 self.transport.loseConnection()
#                 return
#         packet = self.getPacket()
#         while packet:
#             messageNum = ord(packet[0])
#             self.dispatchMessage(messageNum, packet[1:])
#             packet = self.getPacket()
# 
#         # Later versions seem to call sendKexInit again on their own
#         if twisted.version.major < 11 and \
#                 not self._hadVersion and self.gotVersion:
#             self.sendKexInit()
#             self._hadVersion = True
# 
# 
#     def ssh_KEXINIT(self, packet):
#         """
#         """
#         k = getNS(packet[16:], 10)
#         strings, rest = k[:-1], k[-1]
#         (kexAlgs, keyAlgs, encCS, encSC, macCS, macSC, compCS, compSC, langCS,
#             langSC) = [s.split(',') for s in strings]
#         log.msg(eventid='COW0009', version=self.otherVersionString,
#             kexAlgs=kexAlgs, keyAlgs=keyAlgs, encCS=encCS, macCS=macCS,
#             compCS=compCS, format='Remote SSH version: %(version)s')
# 
#         return transport.SSHServerTransport.ssh_KEXINIT(self, packet)
# 
# 
#     def timeoutConnection(self):
#         """
#         """
#         log.msg( "Authentication Timeout reached" )
#         self.transport.loseConnection()
# 
# 
#     def setService(self, service):
#         """
#         Remove login grace timeout
#         """
#         if service.name == "ssh-connection":
#             self.setTimeout(None)
#         transport.SSHServerTransport.setService(self, service)
# 
# 
#     def connectionLost(self, reason):
#         """
#         This seems to be the only reliable place of catching lost connection
#         """
#         self.setTimeout(None)
#         if self.transport.sessionno in self.factory.sessions:
#             del self.factory.sessions[self.transport.sessionno]
#         transport.SSHServerTransport.connectionLost(self, reason)
#         self.transport.connectionLost(reason)
#         self.transport = None
#         log.msg(eventid='COW0011', format='Connection lost')
# 
# 
#     def sendDisconnect(self, reason, desc):
#         """
#         http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
#         Workaround for the "bad packet length" error message.
# 
#         @param reason: the reason for the disconnect.  Should be one of the
#                        DISCONNECT_* values.
#         @type reason: C{int}
#         @param desc: a descrption of the reason for the disconnection.
#         @type desc: C{str}
#         """
#         if not 'bad packet length' in desc:
#             transport.SSHServerTransport.sendDisconnect(self, reason, desc)
#         else:
#             self.transport.write('Packet corrupt\n')
#             log.msg('[SERVER] - Disconnecting with error, code %s\nreason: %s'
#                 % (reason, desc))
#             self.transport.loseConnection()
# 
# 
# 
# class ConnectionWrapper(object):
#     
#     def __init__(self, transport):
#         self.transport = transport
#         
#     
# class TelnetShell(recvline.RecvLine):
#     """Simple echo protocol.
# 
#     Accepts lines of input and writes them back to its connection.  If
#     a line consisting solely of \"quit\" is received, the connection
#     is dropped.
#     """
#     
#     # FIXME hardcoded servername
#     #ps = ("root@svr03:/# ", "...")
#     ps = ("Username: ", "...")
#     sessionCounter = 0x1000000 #hack - they should not interfere with session numbers of ssh sessions
#     
#     def __init__(self, *args, **kwargs):
#         # FIXME port to realm/portal
#         #user = CowrieUser("root", server.CowrieServer(args[0]))
#         
#         #self.honeypot = HoneyPotInteractiveProtocol(user)
#         self.shell = None
#         self.username = None
#         self.password = None
#         pass
# 
#     def lineReceived(self, line):
#         #shitty state machine
#         if self.username is None:
#             self.username = line
#             self.ps = ("Password: ", "...")
#             self.terminal.write("Password: ")
#         elif self.password is None:
#             self.password = line
#             self.factory.logDispatch(TelnetShell.sessionCounter, 'login attempt [%s/%s] succeeded' % (self.username, self.password))
#             # FIXME hardcoded servername
#             self.ps = ("root@svr03:/# ", "...")
#             self.terminal.write("root@svr03:/# ")
#         elif not self.shell:
#             session = HoneyPotSSHSession()
#             self.terminal.transport.session = session
#             self.terminal.transport.transport.sessionno = TelnetShell.sessionCounter #fffuuu almost global variable
#             TelnetShell.sessionCounter += 1
#             self.terminal.transport.session.conn = ConnectionWrapper(self.terminal.transport)
#             #self.honeypot.terminal = self.terminal
#             #self.shell = HoneyPotShell(self.honeypot)
#         
#         if self.shell:
#             self.shell.lineReceived(line)
