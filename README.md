HowTo
======
Long long time ago when there was no wfuzz( or maybe I did not it), I was using access diver as a main tool to find(via bruteforce) existing file and directories on HTTP servers.
Unfortunatelly access diver was quiet old and had limitations like, lack of https support or better support for recognision fake response (e.g  all response with code 200).
That's why I decided to create upgraded python version of this project.

Usage
======

                     -----------------------
                   /  pyAccessDiver [>->]  /
                   -----------------------
    Options:
    -h Help. Print this menu.
    -d Delay in sec runned at the end of each thread.
    -p Proxy (e.g [username@password:]http:proxy.com:31337). Available types of proxies [http/socks4/5]
    -c Path to file contains common paths
    -f Method of recognition whether page/path is fake:
               [0]:<Content length in bytes>
               [1]:<MAGIC sing(s) in site content>
    -l Chose type of logs: Available types [simple , csv]
    -r Turn off handle of redirections. Now each redirectio is treating like a 404 code.
    -v level : [0]Print information about only positive results (e.g 200).
               [1]Print information about all attemptions
               [2]The same like [1] but additionally u get informations about all datails related with connections.
    -b Login:pass for BasicAuthentication
    -t Set max number of simultaneously runned threads (default=5)
    <host>