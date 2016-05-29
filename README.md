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
