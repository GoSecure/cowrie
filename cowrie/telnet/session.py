# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet User Session management for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from twisted.conch.telnet import StatefulTelnetProtocol

class HoneyPotTelnetSession(StatefulTelnetProtocol):

    def connectionMade(self):
        # TODO send motd like SSH
        self.sendLine("\nLogin successful.")

    def lineReceived(self, line):
        self.transport.write("I received %r from you\r\n" % (line,))
