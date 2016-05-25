all:
	gcc -o mcclp mcclp.cpp list.cpp utils.cpp modules/httpd/httpd.cpp  modules/portscan/portscan.cpp modules/telnet/telnet.cpp -I/mnt/c/code/hack/mcclp -I/mnt/c/code/hack/mcclp/modules/bitcoin -I/mnt/c/code/hack/mcclp/modules/portscan modules/fakename/fakename.cpp  modules/data/data.cpp  modules/portscan/ipgen.cpp -ldl
