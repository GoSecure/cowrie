# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet User Session management for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from twisted.conch.telnet import StatefulTelnetProtocol

from cowrie.core import pwd
from cowrie.core import protocol
from cowrie.insults import insults

class HoneyPotTelnetSession(StatefulTelnetProtocol):

    def __init__(self, username, server):
        self.username = username
        self.server = server
        self.cfg = self.server.cfg

        try:
            pwentry = pwd.Passwd(self.cfg).getpwnam(self.username)
            self.uid = pwentry["pw_uid"]
            self.gid = pwentry["pw_gid"]
            self.home = pwentry["pw_dir"]
        except:
            self.uid = 1001
            self.gid = 1001
            self.home = '/home'

        self.environ = {
            'LOGNAME': self.username,
            'USER': self.username,
            'HOME': self.home,
            'TMOUT': '1800'}

        if self.uid==0:
            self.environ['PATH']='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        else:
            self.environ['PATH']='/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'

        # required because HoneyPotBaseProtocol relies on avatar.avatar.home
        self.avatar = self

    def connectionMade(self):
        # TODO send motd like SSH
        self.sendLine("\nLogin successful.")

        self.protocol = insults.LoggingTelnetServerProtocol(
                protocol.HoneyPotInteractiveTelnetProtocol, self)
        #self.protocol.makeConnection(processprotocol)
        self.protocol.makeConnection(self.transport)
        #processprotocol.makeConnection(session.wrapProtocol(self.protocol))

        # working in transport
        #protocol.makeConnection(self.transport)
        #self.transport.protocol = insults.LoggingServerProtocol(
        #        cproto.HoneyPotInteractiveProtocol, self)

    def lineReceived(self, line):
        self.transport.write("I received %r from you\r\n" % (line,))

    # TODO do I need to implement connectionLost?

    def logout(self):
        """
        """
        log.msg('avatar {} logging out'.format(self.username))
