# bitdump
A tool to extract database data from a blind SQL injection vulnerability -- i.e., one that displays success or failure in some way, but does not actually print any data from the database. Note that this tool will not *find* the vulnerabilities for you; it is assumed one has already been found. This tool will only exploit a given vulnerability to extract data.

### When *not* to use bitdump
Since bitdump has to extract data 1 bit at a time, it is an extremely slow method of reading data. You should probably first check to see if the data may be obtained by other means.

## Usage

`bitdump.py url success attackfield [otherfield, [otherfield ...]]`

  * `url` is the vulnerable injection endpoint.
  * `success` is a string that is **_only_** present in a response from a successful query (i.e., one that returns at least one row). This string must *not* be present in responses from malformed or unsuccessful (empty-result) queries. bitdump uses this string to determine its 1 bit of data per query.
  * `attackfield` is the name of the vulnerable field. For example, if the url is vulnerable to sql injection in the "username" field, then this should be "username".
  * `otherfield` is any other field that must be present in the request in order for it to be successful. By default, all of these fields' values will be set to "" (an empty string). To assign a different value, use `field:value`.
      
      For example, to assign "root" to parameter "username", use `username:root`
          
#####Flags

Bitdump additionally supports the following optional flags:

  * `-h` will print basic usage information.
      
    Alias: `--help`

  * `-o [OUTFILE]` will print the results of the dump to OUTFILE upon completion.
      
    Alias: `--outfile`, `--out`

  * `-d [DELAY]` will pause for DELAY ms before sending each query.
      
    Alias: `--delay`
  
  * `-t` will only dump available table names, not their structure or contents.
      
    Alias: `--tables_only`
  
  * `-T [TABLE]` will only dump the contents of TABLE. To specify the table's schema, prepend with a period: SCHEMA.TABLE. If no schema is specified, the current (default) will be used.
      
    Alias: `--dump_table`
  
    * `-w [WHERE]` will add WHERE as a where clause when dumping the contents of TABLE. Requires `-T`.
        
      Alias: `--where`

    * `--fieldeq [FIELD] [VALUE]` will only dump records in which FIELD equals VALUE. Requires `-T`.
    
      See Also:
      * `--fieldlike` (FIELD LIKE %VALUE%)
      * `--fieldlt` (FIELD < VALUE)
      * `--fieldgt` (FIELD > VALUE)
      * `--fieldlte` (FIELD <= VALUE)
      * `--fieldgte` (FIELD >= VALUE)
  
  * `-v` is used to indicate the amount of logging output to display while running the script, from `-v` to `-vvv`. If no verbose flag is given, no logging output will be displayed (but the final database structure will still be printed when the script completes).
      
    Alias: `--verbose`
