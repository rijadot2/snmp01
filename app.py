# -*- coding: utf-8 -*-
from __future__ import print_function
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, jsonify, render_template
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd
)
from pysnmp.proto.rfc1902 import Integer, Integer32, Gauge32, Counter64, OctetString, TimeTicks

# ------------------ Config ------------------
COMMUNITY = 'Binvis0'
SNMP_PORT = 161
SNMP_TIMEOUT = 1
SNMP_RETRIES = 1

IF_INDEX = 10148  # interface index

# OIDs
OID_IFDESCR = '1.3.6.1.2.1.2.2.1.2'
OID_IFSPEED = '1.3.6.1.2.1.2.2.1.5'
OID_IFALIAS = '1.3.6.1.2.1.31.1.1.1.18'
OID_IFHCIN  = '1.3.6.1.2.1.31.1.1.1.6'
OID_IFHCOUT = '1.3.6.1.2.1.31.1.1.1.10'

INTERVAL = 1  # seconds between counter samples
MAX_WORKERS = 10  # threads

# --------------------------------------------
app = Flask(__name__)

def _parse_val(val):
    if isinstance(val, (Integer, Integer32, Gauge32, Counter64)):
        try:
            return int(val)
        except Exception:
            return int(val.prettyPrint())
    if isinstance(val, (OctetString,)):
        return val.prettyPrint()
    if isinstance(val, TimeTicks):
        try:
            return int(val)
        except Exception:
            return int(val.prettyPrint())
    return val.prettyPrint()

def snmp_get(ip, oid_with_index):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(COMMUNITY, mpModel=0),
            UdpTransportTarget((ip, SNMP_PORT), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES),
            ContextData(),
            ObjectType(ObjectIdentity(oid_with_index))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return None
        for name, val in varBinds:
            return _parse_val(val)
    except Exception:
        return None
    return None

def read_ip_list(path='listip.txt'):
    ips = []
    try:
        with open(path, 'r') as f:
            content = f.read()
    except IOError:
        return ips
    raw = content.replace(',', '\n').splitlines()
    for line in raw:
        ip = line.strip()
        if ip:
            ips.append(ip)
    return ips

def compute_mbps(diff_bytes, seconds):
    if diff_bytes < 0:
        diff_bytes = (2**64 - 1) + diff_bytes + 1
    bits = diff_bytes * 8.0
    return (bits / (seconds * 1000000.0))

def poll_one_ip(ip):
    ifdescr_oid = OID_IFDESCR + '.%d' % IF_INDEX
    ifalias_oid = OID_IFALIAS + '.%d' % IF_INDEX
    ifspeed_oid = OID_IFSPEED + '.%d' % IF_INDEX
    ifin_oid = OID_IFHCIN + '.%d' % IF_INDEX
    ifout_oid = OID_IFHCOUT + '.%d' % IF_INDEX

    ifdescr = snmp_get(ip, ifdescr_oid)
    ifalias = snmp_get(ip, ifalias_oid)
    ifspeed = snmp_get(ip, ifspeed_oid)

    in1 = snmp_get(ip, ifin_oid)
    out1 = snmp_get(ip, ifout_oid)

    if in1 is None or out1 is None:
        return {
            'ip': ip,
            'ifDescr': ifdescr or '',
            'ifAlias': ifalias or '',
            'ifSpeed': ifspeed or '',
            'in_mbps': None,
            'out_mbps': None,
            'ok': False
        }

    time.sleep(INTERVAL)

    in2 = snmp_get(ip, ifin_oid)
    out2 = snmp_get(ip, ifout_oid)

    if in2 is None or out2 is None:
        return {
            'ip': ip,
            'ifDescr': ifdescr or '',
            'ifAlias': ifalias or '',
            'ifSpeed': ifspeed or '',
            'in_mbps': None,
            'out_mbps': None,
            'ok': False
        }

    diff_in = in2 - in1
    diff_out = out2 - out1

    in_mbps = compute_mbps(diff_in, INTERVAL)
    out_mbps = compute_mbps(diff_out, INTERVAL)

    return {
        'ip': ip,
        'ifDescr': ifdescr or '',
        'ifAlias': ifalias or '',
        'ifSpeed': ifspeed or '',
        'in_mbps': round(in_mbps, 4),
        'out_mbps': round(out_mbps, 4),
        'ok': True
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/traffic')
def api_traffic():
    ips = read_ip_list('listip.txt')
    results = []

    if not ips:
        return jsonify({'data': results})

    futures = []
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        for ip in ips:
            futures.append(executor.submit(poll_one_ip, ip))
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass
    finally:
        executor.shutdown(wait=True)

    try:
        results.sort(key=lambda x: x.get('ip', ''))
    except Exception:
        pass

    return jsonify({'data': results})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
