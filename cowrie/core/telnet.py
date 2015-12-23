import ConfigParser
import time

from twisted.internet import protocol
from twisted.manhole import telnet
from twisted.conch import recvline
from twisted.conch.telnet import TelnetTransport, TelnetBootstrapProtocol, TelnetProtocol
from twisted.conch.insults import insults
from twisted.conch.ssh import session
from twisted.python import log, components

from cowrie.core import server
from cowrie.core.honeypot import HoneyPotShell
from cowrie.core.protocol import HoneyPotInteractiveProtocol, LoggingServerProtocol
from cowrie.core.ssh import CowrieUser, HoneyPotSSHSession, SSHSessionForCowrieUser


#session - HoneyPotAvatar
#HoneyPotBaseProtocol.terminal - LoggingServerProtocol
#HoneyPotBaseProtocol.terminal.transport - SSHSessionProcessProtocol
#HoneyPotBaseProtocol.terminal.transport.session - HoneyPotSSHSession
#HoneyPotBaseProtocol.terminal.transport.session.conn - twisted.conch.ssh.connection.SSHConnection
#HoneyPotBaseProtocol.terminal.transport.session.conn.transport - HoneyPotTransport

class ConnectionWrapper(object):
    
    def __init__(self, transport):
        self.transport = transport
        
    
class TelnetShell(recvline.RecvLine):
    """Simple echo protocol.

    Accepts lines of input and writes them back to its connection.  If
    a line consisting solely of \"quit\" is received, the connection
    is dropped.
    """
    
    # FIXME hardcoded servername
    #ps = ("root@svr03:/# ", "...")
    ps = ("Username: ", "...")
    sessionCounter = 0x1000000 #hack - they should not interfere with session numbers of ssh sessions
    
    def __init__(self, *args, **kwargs):
        # FIXME port to realm/portal
        #user = CowrieUser("root", server.CowrieServer(args[0]))
        
        #self.honeypot = HoneyPotInteractiveProtocol(user)
        self.shell = None
        self.username = None
        self.password = None
        pass

    def lineReceived(self, line):
        #shitty state machine
        if self.username is None:
            self.username = line
            self.ps = ("Password: ", "...")
            self.terminal.write("Password: ")
        elif self.password is None:
            self.password = line
            self.factory.logDispatch(TelnetShell.sessionCounter, 'login attempt [%s/%s] succeeded' % (self.username, self.password))
            # FIXME hardcoded servername
            self.ps = ("root@svr03:/# ", "...")
            self.terminal.write("root@svr03:/# ")
        elif not self.shell:
            session = HoneyPotSSHSession()
            self.terminal.transport.session = session
            self.terminal.transport.transport.sessionno = TelnetShell.sessionCounter #fffuuu almost global variable
            TelnetShell.sessionCounter += 1
            self.terminal.transport.session.conn = ConnectionWrapper(self.terminal.transport)
            #self.honeypot.terminal = self.terminal
            #self.shell = HoneyPotShell(self.honeypot)
        
        if self.shell:
            self.shell.lineReceived(line)

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
        self.protocol = lambda: TelnetTransport(TelnetBootstrapProtocol,
                                                insults.ServerProtocol, 
                                                TelnetShell, (self.cfg))

        protocol.ServerFactory.startFactory(self)


    def stopFactory(self):
        """
        """
        for output in self.output_plugins:
            output.stop()
        protocol.ServerFactory.stopFactory(self)

    def makeProtocol(self):
        # FIXME port to realm/portal
        #user = CowrieUser("root", server.CowrieServer(args[0]))
        
        serverProtocol = insults.ServerProtocol(
            HoneyPotInteractiveProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))
        return serverProtocol
    
    def buildProtocol(self, addr):
        # FIXME hardcoded things
        print('New connection: %s:%s (%s:%s) [session: %d]' % \
            (addr.host, addr.port, "127.0.0.1", 6023, TelnetShell.sessionCounter))
        return protocol.ServerFactory.buildProtocol(self, addr)
        t = TelnetProtocol()
        #t.factory = self
        #return t
