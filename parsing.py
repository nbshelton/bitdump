import argparse

DEFAULT_DELAY=0
MAX_THREADS=1

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

        parser.add_argument('--shell', help=argparse.SUPPRESS)

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
