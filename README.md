# mcclp

The point of this software is to connect to a number of crypto currencies and blindly distribute messages.  It will
help the network have distribution nodes, and allow analysis, etc.  SPV nodes work pretty much the same except they
actually have wallets attached.  It will be pretty simple to dump transactions, or use these networks as C&C for
other tasks.  I'm starting it in a modular way where you could easily copy one note, and create connections to other
currencies.

I'll leave a function that will allow easy modification for raw reading of transactions, or messages so it can be used
in whatever way possible by integrating with other code.

I'll support a few objectives: monitor all transactions, gather node information,
attack crypto currencies, and aggregation of log data

Nodes information: good for attempting to find where transactions are coming from, or to
attack the currencies

Log data:
helps whenever a transaction ended up being double spent (to remove it) or if it wasnt completed, so you can keep
historic information and also keep information on all TX that dont quite make it into the merkle tree
I'll add zeroMQ later to automate this

Attacking:
can kill all cryptocurrencies in a single swoop

I'm going to create a docker container to setup my nodes for this.. and it can easily be used as a C&C
if you compile the code solely and put it inside of a backdoor, or worm
