#from __future__ import annotations #TODO

import asyncio
from pyzabbix import ZabbixAPI, ZabbixAPIException
from pysnmp.hlapi import ObjectIdentity, ObjectType, UsmUserData
import pysnmp.hlapi.asyncio as hlapi
from pysnmp.smi import builder, view, rfc1902, error
from pysnmp.error import PySnmpError

import json
import pathlib
import logging
from collections import defaultdict
import re

from const import (OIDS)

#prevent the issue with EventLoopPolicy on Windows 10
import platform
if platform.system()=='Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] - %(message)s",
)
LOG = logging.getLogger(__name__)

class SnmpView():
    def __init__(self, config):
        self._host = config['ip']
        self._port = config['port']
        self._oids =  tuple()
        self._snmp_engine = hlapi.SnmpEngine()
        #TODO: use file keys
        self._usm_data = UsmUserData('bootstrap', authKey=config['protocol']['auth_key'], privKey=config['protocol']['priv_key'])
        #hostname is resolved to ip
        self._transport = hlapi.UdpTransportTarget((self._host, self._port))
        self.req_args = [self._snmp_engine, self._usm_data, self._transport, hlapi.ContextData()]
    
            
    @classmethod        
    def _to_oid_str(cls, *obj):
        #convert oid to numeric format string
        if len(obj)>1 or not '.' in obj[0]:
            return SnmpView.snmp_var_build(*obj)
        else:
            return obj[0]
            
    @classmethod
    def snmp_var_build (cls, *oid):
        mibBuilder = builder.MibBuilder()
        mibView = view.MibViewController(mibBuilder)
        mibVar = ObjectIdentity(*oid)
        mibVar.resolveWithMib(mibView)
        return mibVar
   
    async def get_single(self, *oid):
        errorIndication, errorStatus, errorIndex, varBinds = await hlapi.getCmd(
                *self.req_args,
                ObjectType(ObjectIdentity(*oid)),
                lookupNames=True, lookupValues=True
                #lexicographicMode=True,
            )
        if errorIndication:
            logging.error(f'Failed to get {oid} : {errorIndication}')
            return False
        elif errorStatus:
            logging.error(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
            #TODO: raise user error
            return False
        else:    
            return varBinds
     
    async def get_single_value(self, *oid):
        varBinds = await self.get_single(*oid)
        _, val = varBinds[0]
        return val
     
    async def snmp_walk_async(self, *oid):
        oid=SnmpView._to_oid_str(*oid)
        
        #increment last number
        #1.3.6.1.2.1.25.6 -> 1.3.6.1.2.1.25.7
        right_node_oid = f'{str(oid)[:-1]}{int(str(oid)[-1])+1}'
        #print (f' CMR {oid[:-1]}    aaa  {int(oid[-1])+1}'   )
    

        while True:
            #TODO: except
            errorIndication, errorStatus, errorIndex, varBinds = await hlapi.nextCmd(
                *self.req_args,
                ObjectType(ObjectIdentity(oid)),
                #lexicographicMode=True,
            )
            oid, _ = varBinds[0][0]
            
            #compare strings 1.3.6.1.2.1.25.4.1.1.1.1 > 1.3.6.1.2.1.25.3.3.1.5.53
            if str(oid) >= right_node_oid:
                break
                
            if errorIndication:
                logging.error(f'Failed to get {oid} : {errorIndication}')
                break
            elif errorStatus:
                logging.error(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')

                break
            else:    
                yield varBinds
        
        async def snmp_get_bulk(self, *oid):
            #TODO: extend ObjectType to list
            errorIndication, errorStatus, errorIndex, varBinds = await bulkCmd(
                *self.req_args,
                ObjectType(ObjectIdentity(oid)),
            #lexicographicMode=True,
            )
            yield varBinds 
        
        
class Host():
    
    
    def __init__(self, host_cfg, pylld_cfg, zapi):
        self.host = host_cfg['ip']
        self.port = host_cfg['port']
        self.dnsname = host_cfg['hostname']
        self.snmp_view=SnmpView(host_cfg)
        self.sysName=str()
        self.zapi=zapi
        self.fs_filter=pylld_cfg['filter_fs_names']
        self.hstgrp=pylld_cfg['hostgrp']
        self.postfx=pylld_cfg['posfix']
        self.protocol=host_cfg['protocol']
        self.hstname=str()
        #self.zbx_snmp_community=zbx_snmp_community
        
        
    async def refresh(self):
        
        #TODO: create tasks
        #strgVar = SnmpView.snmp_var_build("HOST-RESOURCES-MIB", "hrStorage")
        #print (strgVar)
        self.sysName = str(await self.snmp_view.get_single_value("SNMPv2-MIB", "sysName", 0))
        self.systemLocation = str(await self.snmp_view.get_single_value("SNMPv2-MIB", "sysLocation", 0))
        self.systemDescription = str(await self.snmp_view.get_single_value("SNMPv2-MIB", "sysDescr", 0))
        self.upTime = await self.snmp_view.get_single_value("SNMPv2-MIB", "sysUpTime", 0)
        self.hstname=f'{self.sysName}_{self.postfx}'
        
        logging.info(f'HOST: {self.sysName} on {self.systemLocation} Uptime: {self.upTime} {self.systemDescription}')
        
        fixed_disk_OID = SnmpView.snmp_var_build("HOST-RESOURCES-TYPES", "hrStorageFixedDisk")
        ram_OID = SnmpView.snmp_var_build("HOST-RESOURCES-TYPES", "hrStorageRam")
        
        #u = await self.snmp_view.snmp_walk_async("HOST-RESOURCES-MIB", "hrStorageType")
        
        disks=defaultdict(int)
        rams=defaultdict(int)
        async for i in self.snmp_view.snmp_walk_async("HOST-RESOURCES-MIB", "hrStorageType"):
            for varBind in i:
                oid,val = varBind[0]
                disk_entry_id = tuple(oid)[-1]
                #add only "FixedDisk"
                if fixed_disk_OID == val:
                    disks[disk_entry_id]
                    
                #add only "Ram"
                if ram_OID == val:
                    rams[disk_entry_id]
                #print (disk_entry_id, val)
        
        
        #delete linux /dev /sys /run /proc "FixedDisk" from list
        async for i in self.snmp_view.snmp_walk_async("HOST-RESOURCES-MIB", "hrStorageDescr"):
            for varBind in i:
                oid,val = varBind[0]
                disk_entry_id = tuple(oid)[-1]
                if disk_entry_id in disks and re.match(self.fs_filter,str(val)):
                    del(disks[disk_entry_id])
        #TODO: futures tasks
        
        print(f'DISKS: {len(disks)}')
        print(f'RAMS: {len(rams)}') 
        self.create_host_group()
        self.create_host()
    
    @property
    def host_group_id(self):
        try:
            grp_exists=self.zapi.hostgroup.get(filter = {"name": self.hstgrp}, output=['groupid'])
            if grp_exists:
                return grp_exists[0]['groupid']
        except ZabbixAPIException as e:
            logging.error(f'Error create host: {e}')
        return False
    
    @property
    def host_id(self):
        try:
            hst_exists=self.zapi.host.get(filter = {"name": self.hstname}, output=['hostid'])
            if hst_exists:
                return hst_exists[0]['hostid']
        except ZabbixAPIException as e:
            logging.error(f'Error create host: {e}')
        return False
    
    def create_host_group(self, overwrite=False):
        try:
            #self.zapi.hostgroup.exists
            if self.host_group_id:
                if overwrite:
                    #if group contain host, we cannot delete it
                    self.zapi.hostgroup.delete(groupid=self.host_group_id)
                else:
                    return False

            self.zapi.hostgroup.create(
                name=self.hstgrp
            )
        except ZabbixAPIException as e:
            logging.error(f'Error create host group: {e}')
    
    def create_host(self, overwrite=True):   
        #Check if host already present
        
                  
        try:
            #self.zapi.host.exists
            if self.host_id:
                if overwrite:
                    self.zapi.host.delete(hostid=self.host_id)
                else:
                    return False
  
            if self.protocol['version']!=3:
                raise ValueError(f'SNMP version not implement yet')
            self.zapi.host.create(
                host=self.hstname,
                interfaces=[{'type': 2,'main': 1,'useip': 1,'ip': self.host,'dns': self.dnsname, 'port': self.port, 
                'details': {
                'version': 3, 'bulk': 1,  'securitylevel': 2, 'authpassphrase': self.protocol['auth_key'],
                'authprotocol': 0, 'privpassphrase': self.protocol['priv_key'], 'privprotocol': 0}}],             
                groups={'groupid': self.host_group_id},
                macros=[{'macro': '{$SCRIPT_NAME}', 'value': 'test.py'}],
                #template={'templateid':dns_template_id},
                inventory_mode=-1
            )
            
            
        except ZabbixAPIException as e:
            logging.error(f'Error create host: {e}')
               
async def main(config):

    #TODO: add self signed certificate support
    #session = requests.Session()
    #session.verify = False

    tasks=[]
    with ZabbixAPI("http://127.0.0.1:8080") as zapi:
        zapi.session.verify = False
        zapi.login(api_token=config['zabbix']['api_token'])
        for hst in config['hosts']:
            dns=Host(hst, config['pylld'], zapi=zapi)
            #await dns.refresh()
            tasks.append(dns.refresh())
        await asyncio.gather(*tasks)
    #TODO: memory cleainig (weakref?)

with open("config.json", "r") as f:
    config = json.load(f)

if __name__ == "__main__":
    
    asyncio.run(main(config))