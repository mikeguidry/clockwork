clockwork
general framework for creating robots, worms, and backdoors

The overall system is to be modular in design.  This allows several variations during compile time.  It gives any module the ability to
take advantage of the clockwork network i/o structure.  Each module's netowrking is handled before giving the data off to the module for
processing.  It gives the ability to different tasks during methods such as reading, and writing to the socket.  This is useful for
encryption handling.  The application then gets another call after for processing incoming, and outgoing queues.  Anything that the module
queues for outgoing would pass through the outgoing filter.   It has one last ability to modify the data before it comes back into the
writing function for possible encryption procssing.  The incoming is where the module would literally process the information before
it gets trashed by the framework.  Modules can notify the framework that the full size of the expected communication isn't met yet
due to packet fragmentation and to keep the information in memory until its prepared.  This concludes the base operations.  Everything
that goes any further should be within a module, and called periodically with timers.  

There are optional 'spy functions' that can be attached to a module.  It means that the functions chosen inside of the pointer list are
used immediately before the actual functions.  This allows another function to directly manipulate a different moduile without having
to perform a lot of different tests, and hacks.

Fully functionable modules at the moment:
httpd - web server to distribute content
fakename - renames the process for 'ps' (changes every 5 minutes)
portscan - scans for ports and then dumps them to another module
telnet - brute forces port 23 scans for downloading/executing from httpd

Almost completed:
botlink - bots communicate to distribute peers, and stay resilent
-
pymodules:
  irc client
  irc server
  These will be used to distribute bot messages such as peers, etc across several servers.  The port scanning
  seed can be used to ensure bots on particular dates connect to specific open IRC servers found during a scan.
  The seeds are calculated the same therefore the bots will find the same IRC servers and be able to communicate.
  The bots communicate, and end up on correct botlink networks.
   
   
   
Module IDs
Modules need IDs so that botlink, IRC, and other methods can direct messages into a module to be processed as if its
any other connection.


IDs used: (its up to the module to accept or reject.. so having an ID doesnt ensure it recieves messages)
portscan - 1
botlink - 2
telnet - 3
httpd - 4
dos - 5
data - 6
bitcoin - 50
  alt   - later figure them out.. 50+
dns - 7
irc server - 8
irc client - 9

fakename - 12