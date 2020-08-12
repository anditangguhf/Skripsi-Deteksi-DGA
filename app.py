from flask import Flask, render_template, request
from flask_socketio import SocketIO, send, emit
import json
import os
import pyshark as ps
import mysql.connector as mc
import datetime
import time

app = Flask(__name__)
socketio = SocketIO(app)

constants = {
    "URL": "http://localhost:5000/",
    "MAIN_INTERFACE": "enp5s0",
    "BPF_FILTER": 'udp port 53'
}

dns_dict = { # taken from https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
    'query_class': {
        '0': 'Reserved',
        '1': 'Internet (IN)',
        '3': 'Chaos (CH)',
        '4': 'Hesiod (HS)',
        '254': 'QCLASS NONE',
        '255': 'QCLASS * (ANY)'
    },
    'query_type': {
        '1': "A (a host address)",
        '2': "NS (an authoritative name server)",
        '3': "MD (a mail destination (OBSOLETE - use MX))",
        '4': "MF (a mail forwarder (OBSOLETE - use MX))",
        '5': "CNAME (the canonical name for an alias)",
        '6': "SOA (marks the start of a zone of authority)",
        '7': "MB (a mailbox domain name (EXPERIMENTAL))",
        '8': "MG (a mail group member (EXPERIMENTAL))",
        '9': "MR (a mail rename domain name (EXPERIMENTAL))",
        '10': "NULL (a null RR (EXPERIMENTAL))",
        '11': "WKS (a well known service description)",
        '12': "PTR (a domain name pointer)",
        '13': "HINFO (host information)",
        '14': "MINFO (mailbox or mail list information)",
        '15': "MX (mail exchange)",
        '16': "TXT (text strings)",
        '17': "RP (for Responsible Person)",
        '18': "AFSDB (for AFS Data Base location)",
        '19': "X25 (for X.25 PSDN address)",
        '20': "ISDN (for ISDN address)",
        '21': "RT (for Route Through)",
        '22': "NSAP (for NSAP address, NSAP style A record)",
        '23': "NSAP-PTR (for domain name pointer, NSAP style)",
        '24': "SIG (for security signature)",
        '25': "KEY (for security key)",
        '26': "PX (X.400 mail mapping information)",
        '27': "GPOS (Geographical Position)",
        '28': "AAAA (IP6 Address)",
        '29': "LOC (Location Information)",
        '30': "NXT (Next Domain (OBSOLETE))",
        '31': "EID (Endpoint Identifier)",
        '32': "NIMLOC (Nimrod Locator)",
        '33': "SRV (Server Selection)",
        '34': "ATMA (ATM Address)",
        '35': "NAPTR (Naming Authority Pointer)",
        '36': "KX (Key Exchanger)",
        '37': "CERT (CERT)",
        '38': "A6 (A6 (OBSOLETE - use AAAA))",
        '39': "DNAME (DNAME)",
        '40': "SINK (SINK)",
        '41': "OPT (OPT)",
        '42': "APL (APL)",
        '43': "DS (Delegation Signer)",
        '44': "SSHFP (SSH Key Fingerprint)",
        '45': "IPSECKEY (IPSECKEY)",
        '46': "RRSIG (RRSIG)",
        '47': "NSEC (NSEC)",
        '48': "DNSKEY (DNSKEY)",
        '49': "DHCID (DHCID)",
        '50': "NSEC3 (NSEC3)",
        '51': "NSEC3PARAM (NSEC3PARAM)",
        '52': "TLSA (TLSA)",
        '53': "SMIMEA (S/MIME cert association)",
        '55': "HIP (Host Identity Protocol)",
        '56': "NINFO (NINFO)",
        '57': "RKEY (RKEY)",
        '58': "TALINK (Trust Anchor LINK)",
        '59': "CDS (Child DS)",
        '60': "CDNSKEY (DNSKEY(s) the Child wants reflected in DS)",
        '61': "OPENPGPKEY (OpenPGP Key)",
        '62': "CSYNC (Child-To-Parent Synchronization)",
        '63': "ZONEMD (message digest for DNS zone)",
        '99': "SPF",
        '100': "UINFO",
        '101': "UID",
        '102': "GID",
        '103': "UNSPEC",
        '104': "NID",
        '105': "L32",
        '106': "L64",
        '107': "LP",
        '108': "EUI48 (an EUI-48 address)",
        '109': "EUI64 (an EUI-64 address)",
        '249': "TKEY (Transaction Key)",
        '250': "TSIG (Transaction Signature)",
        '251': "IXFR (incremental transfer)",
        '252': "AXFR (transfer of an entire zone)",
        '253': "MAILB (mailbox-related RRs (MB, MG or MR))",
        '254': "MAILA (mail agent RRs (OBSOLETE - see MX))",
        '255': "* (A request for some or all records the server has available)",
        '256': "URI (URI)",
        '257': "CAA (Certification Authority Restriction)",
        '258': "AVC (Application Visibility and Control)",
        '259': "DOA (Digital Object Architecture)",
        '260': "AMTRELAY (Automatic Multicast Tunneling Relay)",
        '32768': "TA (DNSSEC Trust Authorities)",
        '32769': "DLV (DNSSEC Lookaside Validation (OBSOLETE))",
        '65535': "Reserved"
    },
    'rcode': {
        '0':"NoError (No Error)",
        '1':"FormErr (Format Error)",
        '2':"ServFail (Server Failure)",
        '3':"NXDomain (Non-Existent Domain)",
        '4':"NotImp (Not Implemented)",
        '5':"Refused (Query Refused)",
        '6':"YXDomain (Name Exists when it should not)",
        '7':"YXRRSet (RR Set Exists when it should not)",
        '8':"NXRRSet (RR Set that should exist does not)",
        '9':"NotAuth (Server Not Authoritative for zone)/NotAuth (Not Authorized)",
        '10':"NotZone (Name not contained in zone)",
        '11':"DSOTYPENI (DSO-TYPE Not Implemented)",
        '16':"BADVERS (Bad OPT Version)/BADSIG (TSIG Signature Failure)",
        '17':"BADKEY (Key not recognized)",
        '18':"BADTIME (Signature out of time window)",
        '19':"BADMODE (Bad TKEY Mode)",
        '20':"BADNAME (Duplicate key name)",
        '21':"BADALG (Algorithm not supported)",
        '22':"BADTRUNC (Bad Truncation)",
        '23':"BADCOOKIE (Bad/missing Server Cookie)",
        '65535':"Reserved (can be allocated by Standards Action)"
    },
    'flags': {
        'QR': {'0': 'Query', '1': 'Response'},
        'OPCODE': {'0': 'Query', '1': 'IQuery (Inverse Query)', '2': 'Status', '4': 'Notify', '5': 'Update'},
        'AA': {'0': 'Non-authoritative', '1': 'Is authoritative'},
        'TC': {'0': 'Not truncated', '1': 'Message truncated'},
        'RD': {'0': 'Recursion not desired', '1': 'Recursion desired'},
        'RA': {'0': 'Recursion query support not available', '1': 'Recursion query support available'},
        'Z': {'0': 'Reserved'},
        'AD': {'0': 'Answer/authority portion was not authenticated by the server'},
        'CD': {'0': 'Unacceptable'},
        'RCODE': {
            '0':"NoError (No Error)",
            '1':"FormErr (Format Error)",
            '2':"ServFail (Server Failure)",
            '3':"NXDomain (Non-Existent Domain)",
            '4':"NotImp (Not Implemented)",
            '5':"Refused (Query Refused)",
            '6':"YXDomain (Name Exists when it should not)",
            '7':"YXRRSet (RR Set Exists when it should not)",
            '8':"NXRRSet (RR Set that should exist does not)",
            '9':"NotAuth (Server Not Authoritative for zone)/NotAuth (Not Authorized)",
            '10':"NotZone (Name not contained in zone)",
            '11':"DSOTYPENI (DSO-TYPE Not Implemented)",
            '16':"BADVERS (Bad OPT Version)/BADSIG (TSIG Signature Failure)",
            '17':"BADKEY (Key not recognized)",
            '18':"BADTIME (Signature out of time window)",
            '19':"BADMODE (Bad TKEY Mode)",
            '20':"BADNAME (Duplicate key name)",
            '21':"BADALG (Algorithm not supported)",
            '22':"BADTRUNC (Bad Truncation)",
            '23':"BADCOOKIE (Bad/missing Server Cookie)",
            '65535':"Reserved (can be allocated by Standards Action)"
        }
    }
}

capture_dict = {
    'start_time': "",
    'end_time': "",
}

packets = {}

UPLOAD_PATH = os.getcwd() + '/static/uploads/'

db = mc.connect(
    host='localhost',
    user='',
    passwd='',
    database=''
)
cursor = db.cursor()

@app.route('/')
def index():
    return render_template('index.html', title='Home', constants=constants)


@app.route('/live')
def live():
    summaries = []
    packets = []
    filenames = []
    cursor = db.cursor()
    cursor.execute("SELECT * FROM _capture_tables ORDER BY id DESC")
    tables = cursor.fetchall() # 0 = id, 1 = packets, 2 = summary
    for t in tables:
        split = t[1].split("_")
        raw_timestamp = split[2] + "_" + split[3]
        timestamp = datetime.datetime.strptime(raw_timestamp, "%Y%m%d_%H%M%S%f")
        packets.append(t[1])
        summaries.append(t[2])
        filenames.append(timestamp)
    return render_template('live.html', title='Live Capture', constants=constants, len=len(tables), packets=packets,
                           summaries=summaries, filenames=filenames)


@app.route('/pcap')
def pcap():
    filenames = []
    summaries = []
    packets = []
    cursor = db.cursor()
    cursor.execute("SELECT * FROM _upload_tables ORDER BY id DESC")
    tables = cursor.fetchall() # 0 = id, 1 = packets, 2 = summary, 3 = filename
    print(tables)
    for t in tables:
        packets.append(t[1])
        summaries.append(t[2])
        filenames.append(t[3])
    return render_template('pcap.html', title='Analyze PCAP', constants=constants, len=len(tables), packets=packets,
                           summaries=summaries, filenames=filenames)


@app.route('/uploader', methods=["POST"])
def uploader():
    file = request.files.get('pcap')
    filename = file.filename
    # print(filename)
    if os.path.exists(UPLOAD_PATH + filename):
        result = {
            'status' : -1,
            'msg' : "Upload failed. Uploaded file: " + filename + " exists / has been analyzed!"
        }
    else:
        current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S%f")[:-4]
        file.save(os.path.join(UPLOAD_PATH, filename))

        # analyze pcap here
        cap = ps.FileCapture(UPLOAD_PATH + filename, display_filter="dns")

        cursor = db.cursor()

        # initialize tables
        tables = _create_table(current_time, 'upload', cursor, filename)

        # process packet data
        packets = _process_packet_data(cap)

        # insert to db
        _insert_to_table(tables, packets, db, cursor)

        # return tables json to front
        summary = _get_summary(tables['sum'], cursor)

        cursor.execute("SELECT arrival_time FROM " + tables['pkt'] + " ORDER BY arrival_time ASC LIMIT 1")
        first_packet_time = cursor.fetchone()[0]
        cursor.execute("SELECT arrival_time FROM " + tables['pkt'] + " ORDER BY arrival_time DESC LIMIT 1")
        last_packet_time = cursor.fetchone()[0]

        result = {
            'status': 1,
            'tables': tables,
            'timestamp': current_time,
            'filename': filename,
            'summary': summary,
            'first_packet_time': first_packet_time,
            'last_packet_time': last_packet_time
        }
    return json.dumps(result)

@app.route('/_history', methods=['POST'])
def _show_history():
    table = request.form['val']
    split = table.split("_")
    cursor = db.cursor()
    summary = _get_summary(table, cursor)
    prefix = split[0]
    if prefix == "capture":
        filename = split[2] + "_" + split[3]
    elif prefix == "upload":
        cursor.execute("SELECT filename FROM _upload_tables WHERE summary=%s", (table,))
        filename = cursor.fetchone()[0]

    table_packet = split[0] + "_packets_" + split[2] + "_" + split[3]
    cursor.execute("SELECT arrival_time FROM " + table_packet + " ORDER BY arrival_time ASC LIMIT 1")
    first_packet_time = cursor.fetchone()[0]
    cursor.execute("SELECT arrival_time FROM " + table_packet + " ORDER BY arrival_time DESC LIMIT 1")
    last_packet_time = cursor.fetchone()[0]

    result = {
        'prefix': prefix,
        'timestamp': split[2] + "_" + split[3],
        'summary': summary,
        'filename': filename,
        'first_packet_time': first_packet_time,
        'last_packet_time': last_packet_time
    }
    return json.dumps(result)

@app.route('/_all_history', methods=['POST'])
def _show_all_history():
    cursor = db.cursor(dictionary=True)
    # get table history based on prefix
    prefix = request.form['prefix']
    # table = prefix + "all_history"
    query_table = "_"+ prefix + "tables"
    get_tables = ("SELECT * FROM " + query_table)
    cursor.execute(get_tables)
    records = cursor.fetchall();

    result = {}
    for r in records:
        tbl_split = r['summary'].split("_") # 0 = type, 1 = table_type, 2 = date, 3 = time
        timestamp = tbl_split[2] + "_" + tbl_split[3]
        get_summary = ("SELECT * FROM " + r['summary'])
        cursor.execute(get_summary)
        if prefix == "upload_":
            result[r['filename']] = {
                'timestamp': timestamp,
                'summary': cursor.fetchall()
            }
        elif prefix == "capture_":
            result[timestamp] = {
                'timestamp': timestamp,
                'summary': cursor.fetchall()
            }
    return result


@app.route('/<page_type>/details/<timestamp>/<id>')
def details(page_type, timestamp, id):
    # set prefix for table name
    prefix = ''
    if page_type == 'pcap':
        prefix = 'upload_'
    elif page_type == 'live':
        prefix = 'capture_'

    # get the summary from the table
    cursor = db.cursor(dictionary=True)
    summary_name = prefix + "summary_" + timestamp
    summary = _get_summary_single(summary_name, id, cursor)
    summary['packet_ids'] = json.loads(summary['packet_ids'])
    summary['times_queried'] = len(summary['packet_ids'])

    # also get packets from the table, using packet_ids owned
    packet_table_name = prefix + "packets_" + timestamp
    pkt_res = _get_packets(packet_table_name, summary['packet_ids'], cursor)
    packets = pkt_res['records']

    return render_template('details.html', title='Details', page_type=page_type, timestamp=timestamp, id=id, constants=constants,
                           summary=summary, packets=packets, dns_dict=dns_dict)


@socketio.on('message')
def handle_capture(msg):
    global packets
    global capture_dict
    """
        function to handle capture messages and actions
        receive and send message over socketio
    """
    try:
        msg = json.loads(msg)
        action = msg['act']
        if action == "start":
            capture_dict['start_time'] = datetime.datetime.now().strftime("%Y%m%d_%H%M%S%f")[:-4]
            dump = {
                'type': 'start',
                'value': capture_dict['start_time']
            }
            emit('capture', json.dumps(dump))

            mi = constants["MAIN_INTERFACE"]
            bpf = constants["BPF_FILTER"]
            cap = ps.LiveCapture(mi, bpf_filter=bpf)
            packets = {}
            for pkt in cap:
                if pkt.highest_layer == 'DNS':
                    frame = pkt.frame_info
                    eth = pkt.eth
                    try:
                        ip = pkt.ip
                    except AttributeError as e:
                        ip = pkt.ipv6
                    udp = pkt.udp
                    dns = pkt.dns

                    layer_info = {}
                    layer_info['frame'] = frame._all_fields
                    layer_info['eth'] = eth._all_fields
                    layer_info['ip'] = ip._all_fields
                    layer_info['udp'] = udp._all_fields
                    layer_info['dns'] = dns._all_fields

                    dns_type = ""

                    if udp.srcport == '53':
                        # Response
                        dns_type = "Response"
                        for key in dns._all_fields.keys():
                            if key == 'dns.response_to':
                                response_to = dns._all_fields[key]
                                packets[response_to]['flags'] = dns.flags
                                packets[response_to]['rcode'] = dns.flags_rcode
                                packets[response_to]['layer_info']['response'] = json.dumps(layer_info)
                                # print("DNS Response of: " + dns.qry_name + " | RCODE: " + dns.flags_rcode)
                    elif udp.dstport == '53':
                        dns_type = "Query"
                        frame_num = frame.number
                        packets[frame_num] = {}
                        packets[frame_num]['flags'] = ""
                        packets[frame_num]['rcode'] = ""
                        packets[frame_num]['layer_info'] = {'query': "", 'response': ""}
                        packets[frame_num]['arrival_time'] = str(pkt.sniff_time)
                        packets[frame_num]['epoch_time'] = frame.time_epoch
                        packets[frame_num]['src_ip'] = ip.src
                        packets[frame_num]['src_port'] = udp.srcport
                        packets[frame_num]['dst_ip'] = ip.dst
                        packets[frame_num]['dst_port'] = udp.dstport
                        packets[frame_num]['trans_id'] = dns.id
                        packets[frame_num]['query_name'] = dns.qry_name
                        packets[frame_num]['query_type'] = dns.qry_type
                        packets[frame_num]['query_class'] = int(dns.qry_class, 16)
                        packets[frame_num]['layer_info']['query'] = json.dumps(layer_info)
                        # print("DNS Query of: " + dns.qry_name + " | Src IP: " + ip.src)

        elif action == "end":
            capture_dict['end_time'] = datetime.datetime.now().strftime("%Y%m%d_%H%M%S%f")[:-4]

            # when end save to db then pass to front end
            cursor = db.cursor()

            # initialize tables
            tables = _create_table(capture_dict['start_time'], 'capture', cursor)

            # insert to db
            _insert_to_table(tables, packets, db, cursor)

            # return tables json to front
            summary = _get_summary(tables['sum'], cursor)
            # print(summary)

            result = {
                'type': 'end',
                'tables': tables,
                'summary': summary,
                'start_time': capture_dict['start_time'],
                'end_time': capture_dict['end_time']
            }
            emit('capture', json.dumps(result))

    except ValueError as e:
        print("Not a json object, just a String")
        print("Message: " + msg)


def _process_packet_data(cap):
    packets = {}

    print("Processing packet data...")

    for pkt in cap:
        if pkt.highest_layer == 'DNS':
            frame = pkt.frame_info
            eth = pkt.eth
            try:
                ip = pkt.ip
            except AttributeError as e:
                ip = pkt.ipv6
            udp = pkt.udp
            dns = pkt.dns

            layer_info = {}
            layer_info['frame'] = frame._all_fields
            layer_info['eth'] = eth._all_fields
            layer_info['ip'] = ip._all_fields
            layer_info['udp'] = udp._all_fields
            layer_info['dns'] = dns._all_fields

            dns_type = ""

            if udp.srcport == '53':
                # Response
                dns_type = "Response"
                for key in dns._all_fields.keys():
                    if key == 'dns.response_to':
                        response_to = dns._all_fields[key]
                        packets[response_to]['flags'] = dns.flags
                        packets[response_to]['rcode'] = dns.flags_rcode
                        packets[response_to]['layer_info']['response'] = json.dumps(layer_info)
                        # print("DNS Response of: " + dns.qry_name + " | RCODE: " + dns.flags_rcode)
            elif udp.dstport == '53':
                dns_type = "Query"
                frame_num = frame.number
                packets[frame_num] = {}
                packets[frame_num]['flags'] = ""
                packets[frame_num]['rcode'] = ""
                packets[frame_num]['layer_info'] = {'query': "", 'response': ""}
                packets[frame_num]['arrival_time'] = str(pkt.sniff_time)
                packets[frame_num]['epoch_time'] = frame.time_epoch
                packets[frame_num]['src_ip'] = ip.src
                packets[frame_num]['src_port'] = udp.srcport
                packets[frame_num]['dst_ip'] = ip.dst
                packets[frame_num]['dst_port'] = udp.dstport
                packets[frame_num]['trans_id'] = dns.id
                packets[frame_num]['query_name'] = dns.qry_name
                packets[frame_num]['query_type'] = dns.qry_type
                packets[frame_num]['query_class'] = int(dns.qry_class, 16)
                packets[frame_num]['layer_info']['query'] = json.dumps(layer_info)
                # print("DNS Query of: " + dns.qry_name + " | Src IP: " + ip.src)

    return packets

def _create_table(name, type, cursor, filename=None):
    """
        Function to create table for 'packets' or 'domains'
        :param name: the name of the table to be created
        :param type: type of the table, whether it's triggered from 'capture'/'upload'
        :param cursor: db's cursor object
        :return tables
    """
    # create table packets
    tbl_pkt = type + '_packets_' + name
    create1 = ("CREATE TABLE " + tbl_pkt +  " ( `id` INT NOT NULL AUTO_INCREMENT , `arrival_time` TEXT NULL , "
               "`epoch_time` TEXT NULL , `trans_id` TEXT NULL , `src_ip` TEXT NULL , `src_port` TEXT NULL , `dst_ip` TEXT NULL , "
               "`dst_port` TEXT NULL , `query_name` TEXT NULL , `query_type` TEXT NULL , `query_class` TEXT NULL , `flags` TEXT NULL , "
               "`rcode` TEXT NULL , `layer_info` TEXT NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB;")

    print("Creating table {}: ".format(tbl_pkt))
    cursor.execute(create1)


    # create table summary
    tbl_sum = type + '_summary_' + name
    create2 = ("CREATE TABLE " + tbl_sum + " ( `id` INT NOT NULL AUTO_INCREMENT , `name` TEXT NULL , `packet_ids` TEXT NULL , "
               "`count_nxdomain` INT NOT NULL DEFAULT '0' , `is_dga` TINYINT(1) NOT NULL DEFAULT '-1' COMMENT '-1 = Non-DGA, "
                                           "1 = DGA' , PRIMARY KEY (`id`)) ENGINE = InnoDB;")

    print("Creating table {}: ".format(tbl_sum))
    cursor.execute(create2)

    tables = "_" + type + "_tables"
    if filename is None:
        insert1 = ("INSERT INTO " + tables + " (`packet`, `summary`) VALUES (%s, %s);")
        values1 = (tbl_pkt, tbl_sum)
    else:
        insert1 = ("INSERT INTO " + tables + " (`packet`, `summary`, `filename`) VALUES (%s, %s, %s);")
        values1 = (tbl_pkt, tbl_sum, filename)

    cursor.execute(insert1, values1)
    id = cursor.lastrowid

    result = {
        "id": id,
        "pkt": tbl_pkt,
        "sum": tbl_sum
    }

    return result

def _insert_to_table(tables, packets, db, cursor):
    """
    :param tables: Dictionary of tables
    :param packet: the packets to be inserted
    :param db: the db
    :param cursor: db's cursor object
    :return:
    """

    print("Inserting packets to tables...")

    for pkt in packets:
        query_packet = ("INSERT INTO " + tables['pkt'] + " (arrival_time, epoch_time, trans_id, src_ip, src_port, dst_ip, dst_port, query_name, "
                                                         "query_class, query_type, flags, rcode, layer_info) VALUES (%s, %s, %s, %s, %s, %s, "
                                                         "%s, %s, %s, %s, %s, %s, %s)")
        packet_values = (packets[pkt]['arrival_time'], packets[pkt]['epoch_time'], packets[pkt]['trans_id'], packets[pkt]['src_ip'],
                         packets[pkt]['src_port'], packets[pkt]['dst_ip'], packets[pkt]['dst_port'], packets[pkt]['query_name'],
                         packets[pkt]['query_class'], packets[pkt]['query_type'], packets[pkt]['flags'], packets[pkt]['rcode'],
                         json.dumps(packets[pkt]['layer_info']))
        cursor.execute(query_packet, packet_values)
        packet_id = cursor.lastrowid
        rcode = packets[pkt]['rcode']

        # check if domain exists in summary
        check_query = ("SELECT * FROM " + tables['sum'] + " WHERE `name` = %s")
        check_values = (packets[pkt]["query_name"],)
        cursor.execute(check_query, check_values)
        record = cursor.fetchone()
        # print(record)

        if cursor.rowcount == 0:  ## if not then insert
            count_nxdomain = 0
            if rcode == '3':
                count_nxdomain = 1
            query_domain = ("INSERT INTO " + tables['sum'] + " (`name`, `packet_ids`, `count_nxdomain`) VALUES (%s, %s, %s);")
            packet_ids = [packet_id]
            domain_values = (packets[pkt]["query_name"], json.dumps(packet_ids), count_nxdomain)
            cursor.execute(query_domain, domain_values)
            summary_id = cursor.lastrowid

            # add to all_history
            sum_split = tables['sum'].split("_")
            tbl_history = "_" + sum_split[0] + "_all_history"
            query_history = ("INSERT INTO " +tbl_history+ " (`table_id`, `summary_id`) VALUES (%s, %s);")
            history_values = (tables['id'], summary_id)
            cursor.execute(query_history, history_values)

        else:  ## if yes then update packet_ids
            packet_ids = json.loads(record[2])
            packet_ids.append(packet_id)

            # get count_nxdomain from summary if rcode == '3'
            count_nxdomain = 0
            is_dga = -1
            if rcode == '3':
                get_count = ("SELECT count_nxdomain FROM " + tables['sum'] + " WHERE `name` = %s;")
                cursor.execute(get_count, (packets[pkt]["query_name"],))
                count_res = cursor.fetchone()
                count_nxdomain = int(count_res[0]) + 1

                # also set is_dga if count > 2
                if count_nxdomain > 2:
                    is_dga = 1

            # then update
            query_domain = ("UPDATE " + tables['sum'] + " SET `packet_ids` = %s , `count_nxdomain` = %s , `is_dga` = %s WHERE `name` = %s;")
            domain_values = (json.dumps(packet_ids), count_nxdomain, is_dga, packets[pkt]["query_name"])
            cursor.execute(query_domain, domain_values)

        db.commit()

    print("Inserting finished.")

def _get_summary(table, cursor):
    query = ("SELECT * FROM " + table)
    cursor.execute(query)
    records = cursor.fetchall()
    # print(records)
    result = []
    for r in records:
        data = {
            'id': r[0],
            'name': r[1],
            'packet_ids': json.loads(r[2]),
            'count_nxdomain': r[3],
            'is_dga': r[4]
        }
        result.append(data)
    return result

def _get_summary_single(table, id, cursor):
    query = ("SELECT * FROM " + table + " WHERE id = %s;")
    cursor.execute(query, (id,))
    r = cursor.fetchone()
    return r

def _get_packets(table, ids, cursor):
    in_ids = ", ".join([str(id) for id in ids])
    query = ("SELECT * FROM " + table + " WHERE id IN (" + in_ids + ");")
    cursor.execute(query)
    records = cursor.fetchall()
    result = {
        'columns': cursor.column_names,
        'records': records
    }
    return result

if __name__ == '__main__':
    # app.run()
    socketio.run(app)
