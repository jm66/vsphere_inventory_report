vsphere_inventory_report
========================

Full vSphere inventory report

```
./vss_inventory_report.py -h
usage: vss_inventory_report.py [-h] -s SERVER -u USERNAME [-p PASSWORD] -c
                               DCNAME [-D DIRECTORY] [-f FILENAME] [-v] [-d]
                               [-l LOGFILE] [-V]

Report full vShere inventory to a CSV file

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        The vCenter or ESXi server to connect to
  -u USERNAME, --user USERNAME
                        The username with which to connect to the server
  -p PASSWORD, --password PASSWORD
                        The password with which to connect to the host. If not
                        specified, the user is prompted at runtime for a
                        password
  -c DCNAME, --dc DCNAME
                        The datacenter name you wish to report
  -D DIRECTORY, --dir DIRECTORY
                        Write CSV to a specific directory. Default /tmp
  -f FILENAME, --filename FILENAME
                        File name. Default vsphere-inventory.csv
  -v, --verbose         Enable verbose output
  -d, --debug           Enable debug output
  -l LOGFILE, --log-file LOGFILE
                        File to log to (default = stdout)
  -V, --version         show program's version number and exit
```

More info in my [blog] (http://jose-manuel.me/2014/02/vsphere-full-inventory-report-vsphere_inventory_report-py) 
