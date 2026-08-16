#!/usr/bin/env python3
import json, os, time
from collections import OrderedDict
import geoip2.database

# Rutas
STATE_FILE = "/var/lib/wounds_counters/state.json"
PROM_FILE = "/var/lib/node_exporter/textfile_collector/dionaea_events_total.prom"
DIONAEA_LOG = "/var/log/dionaea_events.json"
COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
GEOIP_DB = "/usr/local/share/GeoIP/GeoLite2-City.mmdb"

DIONAEA_PORTS = [21, 135, 445, 1433, 1723, 1883, 3306, 5060, 5061, 27017, 11211, 42]
COWRIE_PORTS = (22, 23)
GEO_RELEVANT_EVENTS = {
    "cowrie.login.failed", "cowrie.login.success", "cowrie.command.input",
    "cowrie.client.kex", "cowrie.direct-tcpip.request",
}

# Cargar estado
state = {}
if os.path.exists(STATE_FILE):
    with open(STATE_FILE) as f:
        try: state = json.load(f)
        except: pass

now = time.time()
if "honeypot_start_time" not in state:
    state["honeypot_start_time"] = now

# Lector GeoIP
geo_reader = None
if os.path.exists(GEOIP_DB):
    geo_reader = geoip2.database.Reader(GEOIP_DB)

def get_coords(ip):
    """Devuelve (lat, lon) redondeados a 2 decimales, o (None, None) si falla."""
    if not geo_reader:
        return None, None
    try:
        resp = geo_reader.city(ip)
        return round(resp.location.latitude, 2), round(resp.location.longitude, 2)
    except:
        return None, None

def update_total(key, cur):
    last = state.get(f"{key}_last", 0)
    total = state.get(f"{key}_total", 0)
    if cur < last:
        total += cur
    else:
        total += (cur - last)
    state[f"{key}_last"] = cur
    state[f"{key}_total"] = total
    return total

def read_jsonl(path):
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            try:
                yield json.loads(line.strip())
            except:
                continue

metrics = []
current_geo = {}

# ============================================================
# Dionaea: una sola pasada del log completa todos los contadores
# ============================================================
d_port_counts = {p: 0 for p in DIONAEA_PORTS}
d_unique_ips = {p: set() for p in DIONAEA_PORTS}
d_unknown_count = 0
d_malware_count = 0

for ev in read_jsonl(DIONAEA_LOG):
    dst = ev.get("dst_port")
    src = ev.get("src_ip")

    if dst is None:
        d_unknown_count += 1
    elif dst in d_port_counts:
        d_port_counts[dst] += 1
        if src:
            d_unique_ips[dst].add(src)

    if ev.get("eventid") == "dionaea.download.complete":
        d_malware_count += 1

    if dst is not None and src:
        lat, lon = get_coords(src)
        if lat is not None:
            key = f"{lat},{lon}"
            current_geo[key] = current_geo.get(key, 0) + 1

d_conn_totals = {}
for p in DIONAEA_PORTS:
    total = update_total(f"d_conn_{p}", d_port_counts[p])
    d_conn_totals[p] = total
    metrics.append(f'dionaea_total_events{{port="{p}"}} {total}')

d_unknown_total = update_total("d_conn_unknown", d_unknown_count)
metrics.append(f'dionaea_total_events{{port="unknown"}} {d_unknown_total}')

malware_total = update_total("malware", d_malware_count)
metrics.append(f'dionaea_malware_download_total {malware_total}')

for port in DIONAEA_PORTS:
    key = f"uniq_d_{port}"
    stored = set(state.get(key, []))
    stored.update(str(ip) for ip in d_unique_ips[port])
    state[key] = list(stored)
    metrics.append(f'crowdsec_unique_ips_total{{port="{port}"}} {len(stored)}')

# ============================================================
# Cowrie: una sola pasada del log completa todos los contadores
# ============================================================
c_port_counts = {p: 0 for p in COWRIE_PORTS}
c_unique_ips = {p: set() for p in COWRIE_PORTS}
bf_ssh = lg_ssh = bf_tel = lg_tel = cmd_exec = 0
creds_events = []
cmds_events = []

for ev in read_jsonl(COWRIE_LOG):
    eventid = ev.get("eventid")
    dst = ev.get("dst_port")
    src = ev.get("src_ip")
    protocol = ev.get("protocol")

    if dst in c_port_counts:
        c_port_counts[dst] += 1
        if src:
            c_unique_ips[dst].add(src)

    if eventid == "cowrie.login.failed":
        if protocol == "ssh": bf_ssh += 1
        elif protocol == "telnet": bf_tel += 1
    elif eventid == "cowrie.login.success":
        if protocol == "ssh": lg_ssh += 1
        elif protocol == "telnet": lg_tel += 1
        entry = OrderedDict()
        for field in ("username", "password", "src_ip", "timestamp"):
            entry[field] = ev.get(field, "")
        creds_events.append(entry)

    if eventid == "cowrie.command.input":
        cmd_exec += 1
        entry = OrderedDict()
        for field in ("input", "src_ip", "timestamp"):
            entry[field] = ev.get(field, "")
        cmds_events.append(entry)

    if eventid in GEO_RELEVANT_EVENTS and src:
        lat, lon = get_coords(src)
        if lat is not None:
            key = f"{lat},{lon}"
            current_geo[key] = current_geo.get(key, 0) + 1

c_conn_totals = {}
for p in COWRIE_PORTS:
    total = update_total(f"c_conn_{p}", c_port_counts[p])
    c_conn_totals[p] = total
    metrics.append(f'cowrie_total_events{{port="{p}"}} {total}')

bf_ssh_total = update_total("c_bf_22", bf_ssh)
lg_ssh_total = update_total("c_lg_22", lg_ssh)
bf_tel_total = update_total("c_bf_23", bf_tel)
lg_tel_total = update_total("c_lg_23", lg_tel)
metrics.append(f'cowrie_login_failed_total{{port="22"}} {bf_ssh_total}')
metrics.append(f'cowrie_login_success_total{{port="22"}} {lg_ssh_total}')
metrics.append(f'cowrie_login_failed_total{{port="23"}} {bf_tel_total}')
metrics.append(f'cowrie_login_success_total{{port="23"}} {lg_tel_total}')

cmd_exec_total = update_total("cmd_exec", cmd_exec)
metrics.append(f'cowrie_command_exec_total {cmd_exec_total}')

for port in COWRIE_PORTS:
    key = f"uniq_c_{port}"
    stored = set(state.get(key, []))
    stored.update(str(ip) for ip in c_unique_ips[port])
    state[key] = list(stored)
    metrics.append(f'crowdsec_unique_ips_total{{port="{port}"}} {len(stored)}')

# ============================================================
# Geo events acumulados
# ============================================================
geo_state = state.get("geo_events", {})
for key, count in current_geo.items():
    geo_state[key] = geo_state.get(key, 0) + count
state["geo_events"] = geo_state

for key, total in geo_state.items():
    lat, lon = key.split(",")
    metrics.append(f'wounds_geo_events_total{{lat="{lat}", lon="{lon}"}} {total}')

# ============================================================
# Últimas credenciales y comandos (persistentes, últimos 20)
# ============================================================
if creds_events:
    state["last_creds"] = creds_events[-20:]
for i, c in enumerate(reversed(state.get("last_creds", []))):
    metrics.append(
        f'wounds_credential{{index="{i}", username="{c.get("username","")}", '
        f'password="{c.get("password","")}", src_ip="{c.get("src_ip","")}", '
        f'timestamp="{c.get("timestamp","")}"}} 1'
    )

if cmds_events:
    state["last_cmds"] = cmds_events[-20:]
for i, c in enumerate(reversed(state.get("last_cmds", []))):
    metrics.append(
        f'wounds_command{{index="{i}", input="{c.get("input","")}", '
        f'src_ip="{c.get("src_ip","")}", timestamp="{c.get("timestamp","")}"}} 1'
    )

# ============================================================
# Métricas del motor (compatibilidad con dashboards existentes)
# ============================================================
total_events = (
    bf_ssh_total + lg_ssh_total + bf_tel_total + lg_tel_total + cmd_exec_total + malware_total
    + sum(d_conn_totals.values())
    + sum(c_conn_totals.values())
)
metrics.append(f'crowdsec_parsed_lines_total {total_events}')
metrics.append(f'crowdsec_bucket_overflow_total {total_events}')
metrics.append(f'crowdsec_lines_poured_total {total_events}')
metrics.append('crowdsec_version_info{version="v1.7.7-debian-pragmatic-amd64-027974f2"} 1')
metrics.append(f'crowdsec_uptime_seconds {int(now - state["honeypot_start_time"])}')

# Escribir archivo Prometheus
os.makedirs(os.path.dirname(PROM_FILE), exist_ok=True)
with open(PROM_FILE, 'w') as f:
    f.write('\n'.join(metrics) + '\n')

# Guardar estado
os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
with open(STATE_FILE, 'w') as f:
    json.dump(state, f, indent=2)

print(f"Contadores actualizados. parsed_lines={total_events}")
