__author__="Icewall"

import threading
import urllib2
import time
import socks
import sys
import getopt

class MyHTTPRedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):        
        return None
    http_error_301 = http_error_303 = http_error_307 = http_error_302
    
class CLogger:
#Class Logger is resposible of (for this moment) priting all informations
#about done actions and their results on standard stdout in chose format e.g csv.

    def __init__(self,type="simple",level=0):
        """
        Set up proper function "pointer" related with concrete format
        """
        # ehm declaration __function field is not neccessary but it looks better in that way:P
        self.__functions = {"csv":CLogger.__csv,"simple":CLogger.__simple}# fill it with reference and keys to proper logging functions
        self.__level = int(level)
        self.__log = None# function "pointer"
        self.__positiveCode = [200,403,401]
        self.setType(type)

    def log(self,host,code):        
        if (self.__level == 0 and code in self.__positiveCode) or (self.__level >= 1):
            self.__log(host,code)

    def setLevel(self,level):        
        self.__level = level
    
    def setType(self,type):
        if self.__functions.has_key(type):
            self.__log = self.__functions[type]
        else:
            self.__log = self.__functions["simple"]
            
    @staticmethod
    def __csv(host,code):
        print "%s,%s" % (host,code)

    @staticmethod
    def __simple(host,code):
        print "Host %s : Code %s" % (host,code)
        
class CRequest(threading.Thread):
        __host = None
        __semaphore = None
        __Log    = None
        __opener = None        
        __delay  = 0        
        __checkerParam   = None
        __checkerRoutine = None   
        
        def __init__(self,path):
            CRequest.__checkers = {
                          0:self.__contentLength,
                          1:self.__contentMagic
                          }
            threading.Thread.__init__(self)
            self.__path = path.rstrip()#remove new line chars

        def run(self):
            fullURL = "%s%s" %(CRequest.getHost(),self.__path)#ofc I assume that user passed config file formated in proper way
            try:
                #CRequest.getLogger().log( fullURL,CRequest.getOpener().open( fullURL ).code )
                response = CRequest.getOpener().open( fullURL )
                #check whether returned seemingly code is really positive code
                if self.isFake(response):
                #All fake site will end with 404 status code
                    CRequest.getLogger().log( fullURL,"404" )
                else:
                    CRequest.getLogger().log( fullURL,code)
                
            except urllib2.URLError,error:
                CRequest.getLogger().log(fullURL,error)
            #delay thread exit if some delay is set
            CRequest.runDelay()
            #release semaphore
            CRequest.getSemaphore().release()

        @classmethod
        def setSemaphore(cls,semaphore):
            cls.__semaphore = semaphore

        @classmethod
        def getSemaphore(cls):
            return cls.__semaphore

        @classmethod
        def setHost(cls,host):
            cls.__host = host

        @classmethod
        def getHost(cls):
            return cls.__host

        @classmethod
        def setLogger(cls,logger):
            cls.__Log = logger

        @classmethod
        def getLogger(cls):
            return cls.__Log

        @classmethod
        def setOpener(cls,opener):
            cls.__opener = opener
            cls.__opener.add_handler( urllib2.HTTPDefaultErrorHandler() )
            cls.__opener.add_handler( urllib2.HTTPErrorProcessor() )

        @classmethod
        def getOpener(cls):
            return cls.__opener      

        @classmethod
        def setDelay(cls,delay):
            cls.__delay = delay

        @classmethod
        def runDelay(cls):
            if cls.__delay > 0:
                time.sleep(cls.__delay)
        
        @classmethod
        def setChecker(cls,params):
            if len(params) != 2:
                print "Checker params aren't correct"
                sys.exit(0)
            params = params.split(":")
            cls.__checkerParam = params[1]
            cls.__checkerRoutine = cls.__checkers[int(params[0])]
            
        @classmethod
        def getChecker(cls):
            return cls.__checkerRoutine
        
        def isFake(self,response):
            if CRequest.getChecker() == None:
                return False
            return CRequest.getChecker(response)
        
        #checkers routines
        def __contentLength(self,response):
            return len(response.read()) == int(CRequest.__checkerParam)
        
        def __contentMagic(self,response):
            return response.read().find(CRequest.__checkerParam) >= 0
                
class CAccessDiver:
    
    def __init__(self,args):
        #Declaration of logger class
        CRequest.setLogger(CLogger())
        CRequest.setOpener(urllib2.OpenerDirector())        
        self.__semaphore = threading.BoundedSemaphore(1)
        CRequest.setSemaphore(self.__semaphore)
        self.__host = None       
        self.__config = None
        self.__debugLevel = None
        #default handlers installed when user didn't choose non-standard ones
        self.__defaultHandlers = {"HTTPRedirect":urllib2.HTTPRedirectHandler(),
                                  "HTTPHandler":urllib2.HTTPHandler()
                                 }
        #Declaration of dictionary contains references on proper methods related with concrete option
        self.__optMethods = {"-p":self.__setProxy,
                             "-c":self.__setConfig,
                             "-l":self.__setLogType,
                             "-r":self.__setRedirection,                             
                             "-b":self.__setBasicAuthentication,
                             "-v":self.__setDebugLevel,
                             "-t":self.__setMaxThreads,
                             "-d":self.__setDelay,
                             "-f":self.__setChecker
                             }
        #Declaration of proxy types
        self.__proxyTypes = {"http":socks.PROXY_TYPE_HTTP,"socks4":socks.PROXY_TYPE_SOCKS4,"socks5":socks.PROXY_TYPE_SOCKS5}
        #TODO: make some trick for using https proxy,,,simple,,,don't use then socks just use urllib2 standard proxy handle

        #Parse passed arguments
        self.__parseArgs(args)

    def __parseArgs(self,args):
        optlist,args = getopt.getopt(args,"hp:l:c:rv:t:d:f:")
        #first check whether -h parameter appears and whether user put a host arg
        if ('-h','') in optlist or not len(args):
            CAccessDiver.menu()
            sys.exit(0)
        #self.__host = args[0]
        CRequest.setHost(args[0])

        for o,p in optlist:
            self.__optMethods[o](p)

    def scan(self):
        #install all default handlers if they exist
        self.__installDefaultHandlers()
        #iterate over all lines in config file and build requests
        #path format: PATH_TO_VULN_FILE:PATH_TO_VULN_FILE_ARGS:RFI/LFI/empty
        for args in self.__config:
            self.__semaphore.acquire()
            CRequest(args).run()

    def __setConfig(self,path):
        try:
            self.__config = file(path,'r')
        except:
            print "Config file doesn't exist %s " % path
            sys.exit(0)

    def __setProxy(self,proxy):
        print proxy
        proxy = proxy.split(":")
        if len(proxy) < 3 or proxy[len(proxy)-3] not in self.__proxyTypes:
            print "!!!Exception!!!: -p ",proxy
            sys.exit(0)
        #set up proxy settings
        if len(proxy) == 3:
            socks.setdefaultproxy(self.__proxyTypes[proxy[0]],
                                  addr=proxy[1],
                                  port=proxy[2]
                                  )
        else:#we assume that 4:P if not ,,,,what a pity
            socks.setdefaultproxy(self.__proxyTypes[proxy[1]],
                                  username=proxy[0].split("@")[0],
                                  password=proxy[0].split("@")[1],
                                  addr=proxy[2],
                                  port=proxy[3]
                                    )

        socket.socket = socks.socksocket

    def __setLogType(self,type):
        CRequest.getLogger().setType(type)

    def __setDebugLevel(self,level):
        level = int(level)
        CRequest.getLogger().setLevel(level)
        CRequest.getOpener().add_handler( urllib2.HTTPHandler(debuglevel=level/2) )
        #remove default handler
        self.__defaultHandlers.pop("HTTPHandler")

    def __setBasicAuthentication(self,args):
        args = args.split(":")
        if len(args) != 2:
            print "Bad format of user and password for BasicAuthentication"
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None,self.__host, args[0], args[1])
        CRequest.getOpener().add_handler( urllib2.HTTPBasicAuthHandler(password_mgr) )

    def __setRedirection(self,nop):#nop is only here to don't mess with argmunets checkings
        CRequest.getOpener().add_handler( MyHTTPRedirectHandler() )
        self.__defaultHandlers.pop("HTTPRedirect")
    
    def __setMaxThreads(self,max):
        self.__semaphore = threading.BoundedSemaphore(int(max))
        CRequest.setSemaphore(self.__semaphore)

    def __installDefaultHandlers(self):
        for handler in self.__defaultHandlers.values():
            CRequest.getOpener().add_handler( handler )

    def __setDelay(self,delay):
        CRequest.setDelay( delay )

    def __setChecker(self,params):
        CRequest.setChecker( params )
        
    @staticmethod
    def menu():
        print \
"""
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
"""

        
if __name__ == "__main__":
    AccessDiver = CAccessDiver(sys.argv[1:])
    AccessDiver.scan()
    
    
