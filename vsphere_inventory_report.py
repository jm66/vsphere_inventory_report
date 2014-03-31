#!/usr/bin/python
import logging, sys, re, getpass, argparse, pprint, csv, time
from pysphere import MORTypes, VIServer, VITask, VIProperty, VIMor, VIException
from pysphere.vi_virtual_machine import VIVirtualMachine
from pysphere.resources import VimService_services as VI

def sizeof_fmt(num):
    for x in ['bytes','KB','MB']:
        num /= 1024.0
    return "%3.5f" % (num)

def get_vm_permissions(auth_manager, vm_mor, request):
    vm_mor_type = "VirtualMachine"
    _this = request.new__this(auth_manager)
    _this.set_attribute_type(auth_manager.get_attribute_type())
    request.set_element__this(_this)
    entity = request.new_entity(vm_mor)
    entity.set_attribute_type(vm_mor_type)
    request.set_element_entity(entity)
    request.set_element_inherited(True)
    response = server._proxy.RetrieveEntityPermissions(request)
    permissions = response._returnval
    perm_array = [(p.Principal, p.RoleId) for p in permissions]
    return perm_array

def write_report(vms_info, csvfile, dirname, c):
    
    for val in vms_info.values():
        c.writerow([val['Folder'], val['vm'], val['numCPU'], val['MBmemory'], val['diskCapacity'], val['diskCommitted'],val['ESXihost'], val['datastores'], 
                    val['vmConfig'], val['networks'], val['netids'], val['vmOS'], val['vmTools'], val['vmPower'], val['vmDNS'], val['Note'],
                    val['cpuReservationMhz'], val['cpuLimitMhz'], val['memReservationMB'], val['memLimitMB'], val['HardDisks'],
                    val['CDdrive'], val['snapshots'], val['Permissions'] ])

def create_vm_dict():
    vm = {'vmId': None, 'vm': None, 'numCPU': None, 'MBmemory': None, 'vmConfig': None, 'Note': None, 'vmOS': None, 'vmDNS': None, 
          'vmPower': None, 'vmTools': None, 'cpuReservationMhz': None, 'cpuLimitMhz': None, 'memReservationMB': None, 'memLimitMB': None,
          'diskCapacity': None, 'networks': None, 'datastores': None, 'netids': None, 'snapshots': None, 'CDdrive': None,
          'ESXihost': None, 'HardDisks': None, 'diskCapacity': None, 'diskCommitted': None, 'Folder': None, 'Permissions': None} 
    return vm
    
def create_csv_header():
    csv_header = ["Folder", "vmName", "numCPU", "MBmemory", "GBstorage", "GBcommitted", "ESXhost", "datastores", "vmConfig", "NICs",
              "NetIDs", "vmOS", "vmTools", "vmPower", "vmDNS", "Note", 
              "cpuReservationMhz", "cpuLimitMhz", "memReservationMB", "memLimitMB", 
              "HardDisks", "CDdrive", "Snapshots", "vmPermissions"]
    return csv_header

def create_vm_props():
    properties = ['name','config.hardware.device', 'config.hardware.numCPU',
              'config.hardware.memoryMB', 'config.files.vmPathName',
              'runtime.host', 'config.version', 'summary.runtime.powerState',
              'config.annotation', 'config.guestFullName', 'guest.hostName',
              'guest.toolsVersion', 'guest.disk', 'guest.net',
              'resourceConfig.cpuAllocation.reservation',
              'resourceConfig.cpuAllocation.limit',
              'resourceConfig.memoryAllocation.reservation',
              'resourceConfig.memoryAllocation.limit',
              'datastore', 'snapshot', 'layoutEx.file', 'storage.perDatastoreUsage'] 
    return properties

def create_me_props():
    return ['name', 'parent'] 

def get_dvp_dict(datacenters, datacentername, server):
    dvpgs = {}
    # GET INITIAL PROPERTIES AND OBJECTS
    dcmor = [k for k,v in datacenters if v==datacentername][0]
    dcprops = VIProperty(server, dcmor)
    
    # networkFolder managed object reference
    nfmor = dcprops.networkFolder._obj
    dvpg_mors = server._retrieve_properties_traversal(property_names=['name','key'], from_node=nfmor, obj_type='DistributedVirtualPortgroup')
    
    # building dictionary with the DVS
    for dvpg in dvpg_mors:
      mor = dvpg.Obj 
      entity = {} 
      for p in dvpg.PropSet:
        entity[p.Name]=p.Val
      dvpgs[mor] = entity
    
    return dvpgs
    
def get_path(entity, entities_info): 
    parent = entity.get('parent') 
    display_name = "%s" % (entity['name']) 
    if parent and parent in entities_info: 
        return get_path(entities_info[parent], entities_info) + " > " + display_name 
    return display_name 
    
def get_paths_dict(server, properties2):
    entities_info = {}
    paths = {}
    # getting managed entities
    props2 = server._retrieve_properties_traversal(property_names=properties2, obj_type='ManagedEntity')

    # building a dictionary with the Managed Entities info
    for prop in props2: 
        mor = prop.Obj 
        entity = {'id':mor, 'name':None, 'parent':None,'type':mor.get_attribute_type()} 
        for p in prop.PropSet: 
            entity[p.Name] = p.Val 
        entities_info[mor] = entity
    
    
    # building dictionary with VMs vs path 
    for entity in entities_info.itervalues(): 
        if entity['type'] == "VirtualMachine":
               paths[entity['id']] = {'id': entity['id'], 'path':get_path(entity, entities_info)}

    return paths

def set_dir(directory):
        if directory:
                return directory
        else:
                logger.info('Using default directory /tmp')
                return '/tmp'

def getDateSuffix():
  return '_'+time.strftime("%Y-%m-%d")

def set_filename(filename):
        if filename:
                return filename + getDateSuffix()
        else:
                logger.info('Using default filename vsphere-inventory')
                return 'vsphere-inventory' + getDateSuffix()

def get_args():
	# Creating the argument parser
	parser = argparse.ArgumentParser(description="Report full vShere inventory to a CSV file")
	parser.add_argument('-s', '--server', nargs=1, required=True, help='The vCenter or ESXi server to connect to', dest='server', type=str)
	parser.add_argument('-u', '--user', nargs=1, required=True, help='The username with which to connect to the server', dest='username', type=str)
	parser.add_argument('-p', '--password', nargs=1, required=False, help='The password with which to connect to the host. If not specified, the user is prompted at runtime for a password', dest='password', type=str)
	parser.add_argument('-c', '--dc', nargs=1, required=True, help='The datacenter name you wish to report', dest='dcname', type=str)
	parser.add_argument('-D', '--dir', required=False, help='Write CSV to a specific directory. Default /tmp', dest='directory', type=str)
	parser.add_argument('-f', '--filename', required=False, help='File name. Default vsphere-inventory.csv', dest='filename', type=str)
	parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
	parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
	parser.add_argument('-l', '--log-file', nargs=1, required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
	parser.add_argument('-V', '--version', action='version', version="%(prog)s (version 0.2)")

	args = parser.parse_args()
	return args

def get_vms_dict(server, properties, paths, hosts_dict, datastores_dict, dvpgs):
    vms_info = {}
    # getting VMs info
    props = server._retrieve_properties_traversal(property_names=properties, obj_type='VirtualMachine') 

    #build a dictionary with the VMs info 
    for prop in props: 
        mor = prop.Obj 
        vm = create_vm_dict()
        for p in prop.PropSet: 
            vm['vmId'] = mor
            if p.Name == "name":
                 vm['vm'] = p.Val
            elif p.Name == "config.hardware.numCPU":
                 vm['numCPU'] = p.Val
            elif p.Name == "config.hardware.memoryMB":
                vm['MBmemory'] = p.Val
            elif p.Name == "config.files.vmPathName":
                vm['vmConfig'] = p.Val
            elif p.Name == "config.annotation":
                vm['Note']= p.Val
            elif p.Name == "config.guestFullName":
                vm['vmOS'] = p.Val
            elif p.Name == "guest.hostName":
                vm['vmDNS'] = p.Val
            elif p.Name == "summary.runtime.powerState":
                vm['vmPower'] = p.Val
            elif p.Name == "guest.toolsVersion":
                vm['vmTools'] = p.Val
            elif p.Name == "resourceConfig.cpuAllocation.reservation":
                vm['cpuReservationMhz'] = p.Val
            elif p.Name == "resourceConfig.cpuAllocation.limit":
                vm['cpuLimitMhz'] = p.Val
            elif p.Name == "resourceConfig.memoryAllocation.reservation":
                vm['memReservationMB'] = p.Val
            elif p.Name == "resourceConfig.memoryAllocation.limit":
                vm['memLimitMB'] = p.Val
            elif p.Name == "guest.net":
                netids = {}
                for nic in getattr(p.Val, "GuestNicInfo", []):
                    netids[getattr(nic,  'MacAddress', None)] = getattr(nic, 'IpAddress', None)
                vm['netids'] = netids
            elif p.Name == "config.hardware.device":
                cdroms = []
                # macs = []
                nets = {}
                for data in p.Val.VirtualDevice:
                    if data.typecode.type[1] == "VirtualCdrom" and data.Connectable.Connected:
                        cdroms.append(data.DeviceInfo.Summary)
                    elif data.typecode.type[1] in ["VirtualE1000", "VirtualE1000e", "VirtualPCNet32", "VirtualVmxnet", "VirtualVmxnet3", "VirtualVmxnet2"]:
                        # NetIDs
                        # macs.append(getattr(data, "MacAddress", 'NA'))
                        # Getting DV switch vs NIcs
                        niclabel = data.DeviceInfo.Label
                        port = None
                        port = getattr(data.Backing, "Port", None)
                        if port: 
                            dvpid = getattr(port, "PortgroupKey", "NA")
                            nets [niclabel] = [v['name'] for k, v in dvpgs.items() if k == dvpid]
                        else: 
                            nets [niclabel] = 'NA'
                vm['CDdrive'] = cdroms
                vm['networks'] = nets
                # already populated
                # if vm['netids'] is None:
                # vm['netids']= macs
            elif p.Name == "guest.disk":
                 hddsum = 0
                 for data in getattr(p.Val, "GuestDiskInfo", []):
                     hddsum +=  int(getattr(data , "Capacity", 0))
                 vm['diskCapacity'] = sizeof_fmt(hddsum)
            elif p.Name == "datastore":
                datastores = []
                for data in getattr(p.Val, "_ManagedObjectReference"):
                    datastores.append([v for k, v in datastores_dict if k == data])
                vm["datastores"] = datastores
            elif p.Name == "storage.perDatastoreUsage":
                committed = 0
                for data in getattr(p.Val, "VirtualMachineUsageOnDatastore", []):
                    committed += getattr(data , "Committed", 0)
                vm['diskCommitted'] = sizeof_fmt(committed)
            elif p.Name == "snapshot":
                snapshots = []
                for data in getattr(p.Val, "_rootSnapshotList"):
                    snapshot_str = str(getattr(data,"Id")) + "; " + str(getattr(data,"Name")) + "; " + str(getattr(data,"Description")) + "; " + str(getattr(data, "CreateTime"))
                    snapshots.append(snapshot_str)
                vm["snapshots"] = snapshots
            elif p.Name == "runtime.host":
                vm["ESXihost"] = [v for k, v in hosts_dict if k == p.Val]
            elif p.Name == "layoutEx.file":
                files = []
                for data in getattr(p.Val, "VirtualMachineFileLayoutExFileInfo"):
                  if getattr(data, 'Type') in ["diskDescriptor","diskExtent"]:
                        files.append(getattr(data, 'Name'))
                vm['HardDisks'] = files
            else:
                vm[p.Name] = p.Val 
        vms_info[mor] = vm 

    # adding paths to vms
    for vm_info in vms_info.values():
        for path in paths.values():
            if vm_info.get('vmId') == path.get('id'):
               vm_info['Folder'] = path.get('path')

    # Getting and Setting VM permission
    request = VI.RetrieveEntityPermissionsRequestMsg()
    auth_manager = server._do_service_content.AuthorizationManager

    for vm_info in vms_info.values():
        vm_info['Permissions'] = get_vm_permissions(auth_manager, vm_info.get('vmId'), request)

    return vms_info

# Parsing values
args = get_args()
argsdict = vars(args)
servervctr 	= args.server[0]
username 	= args.username[0]
dcname	 	= args.dcname[0]
verbose		= args.verbose
debug		= args.debug
log_file	= None
password 	= None
directory   = args.directory
filename    = args.filename

if args.password:
	password = args.password[0]

if args.logfile:
        log_file = args.logfile[0]

# Logging settings
if debug:
	log_level = logging.DEBUG
elif verbose:
	log_level = logging.INFO
else:
	log_level = logging.WARNING
	
# Initializing logger
if log_file:
    logfile = log_file + getDateSuffix() + '.log' 
    logging.basicConfig(filename=logfile,format='%(asctime)s %(levelname)s %(message)s',level=log_level)
    logger = logging.getLogger(__name__)
else:
	logging.basicConfig(filename=log_file,format='%(asctime)s %(levelname)s %(message)s',level=log_level)
	logger = logging.getLogger(__name__)
logger.debug('logger initialized')

# CSV configuration
csvfile = set_filename(filename)
dirname = set_dir(directory)
csv_header = create_csv_header()
c = None
try:
    logger.debug('Setting up CSV file %s/%s.csv' % (dirname, csvfile))
    c = csv.writer(open(dirname+"/"+csvfile+".csv", "wb"), quoting=csv.QUOTE_ALL)
    c.writerow(csv_header)
    logger.info('Successfully created CSV file %s/%s.csv' % (dirname, csvfile))
except IOException as inst:
    logger.error(inst)
    logger.error('Due to previous errors, program will exit')
    sys.exti()

# Asking Users password for server
if password is None:
	logger.debug('No command line password received, requesting password from user')
        password = getpass.getpass(prompt='Enter password for vCenter %s for user %s: ' % (servervctr,username))

# Connecting to server
logger.info('Connecting to server %s with username %s' % (servervctr,username))

server = VIServer()
try:
	logger.debug('Trying to connect with provided credentials')
	server.connect(servervctr,username,password)
	logger.info('Connected to server %s' % servervctr)
	logger.debug('Server type: %s' % server.get_server_type())
	logger.debug('API version: %s' % server.get_api_version())
except VIException as ins:
	logger.error(ins)
	logger.debug('Loggin error. Program will exit now.')
	sys.exit()
	
if dcname is None:
    logger.error('No datacenter name. Progam will exit now.')
    sys.exit()

# Setting up properties
logger.debug('Getting properties to query')

properties  = create_vm_props()
logger.debug('First set of properties: %s' %properties) 

properties2 = create_me_props()
logger.debug('Second set of properties: %s' %properties2)

# Dictionaries and additional variables configuration              
vms_info = {} 
hosts_dict = None
datastores_dict = None
dvpgs = {}
paths = {}
props = None

# hosts, datastores, dvpgs, paths and vms 
try:
    hosts_dict = server.get_hosts().items()
    logger.debug('Host dictionary generated with size %d' % (len(hosts_dict)))
    
    datastores_dict = server.get_datastores().items()
    logger.debug('Datastores dictionary generated with size %d' % (len(datastores_dict)))
    
    datacenters = server.get_datacenters().items()
    logger.debug('Datacenters dictionary generated with size %d' % (len(datacenters)))
    
    dvpgs = get_dvp_dict(datacenters, dcname, server)
    logger.debug('Distributed Virtual Portgroup dictionary generated with size %d' % (len(dvpgs)))
    
    paths = get_paths_dict(server, properties2)
    logger.debug('VM Paths dictionary generated with size %d' % (len(paths)))
    logger.info('Pre-required dictionaries were successfully gotten: Hosts (%s), Datastores (%s), Datacenters(%s), DVPG(%s) and VM Paths(%s)' %(len(hosts_dict), len(datastores_dict), len(datacenters), len(dvpgs), len(paths)))
    
    logger.info('Building main Virtual Machine properties dictionary. This might take a few minutes.')
    vms_info = get_vms_dict(server, properties, paths, hosts_dict, datastores_dict, dvpgs)
    logger.debug('VM main dictionary generated with size %d' %(len(vms_info)))
    
    # Disconnecting from server
    logger.info('Terminating server %s session' % servervctr)
    server.disconnect()
    
except VIException as inst:
    logger.error(inst)
    logger.error('An unexpected error occurred. Program will exit')
    sys.exit()

# CSV report
try:
    logger.debug('Writting report to %s/%s.csv' % (dirname, csvfile))
    write_report(vms_info, csvfile, dirname, c)
    logger.info('Successfully written CSV report %s/%s.csv' % (dirname, csvfile))
except IOException as inst:
    logger.error(inst)
    logger.error('An unexpected error occurred. Program will exit')
    sys.exit()
