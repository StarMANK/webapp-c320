# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for, session, flash
import telnetlib
import time
from functools import wraps
from threading import Lock
import atexit
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(24) # Secure secret key

# Connection management
connections = {}
connection_lock = Lock()

# Clean up connections on exit
def cleanup_connections():
    with connection_lock:
        for user_id, tn in connections.items():
            try:
                tn.write(b"exit\n")
                tn.close()
            except:
                pass

atexit.register(cleanup_connections)

def clean_ansi(text):
    # Hapus semua karakter ANSI / escape
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def send_command(tn, command, prompt='#', timeout=0.5, max_wait=10):
    tn.write(command.encode('ascii') + b"\n")
    output = ""
    buffer = ""
    start_time = time.time()

    while True:
        time.sleep(timeout)
        chunk = tn.read_very_eager().decode('utf-8', errors='ignore')
        buffer += chunk

        # Bersihkan karakter aneh
        clean = clean_ansi(chunk)
        output += clean

        if '--More--' in clean:
            tn.write(b' ')
        elif prompt in clean and time.time() - start_time > 1:
            break

        # Timeout protection
        if time.time() - start_time > max_wait:
            break

    return output

# Decorator to check login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Telnet connection
def connect_olt(ip, username, password):
    try:
        tn = telnetlib.Telnet(ip, timeout=10)
        tn.read_until(b'Username:')
        tn.write(username.encode('ascii') + b'\n')
        tn.read_until(b'Password:')
        tn.write(password.encode('ascii') + b'\n')
        tn.read_until(b'#')

        # Kirim terminal length 0 untuk disable pagination
        tn.write(b"terminal length 0\n")
        time.sleep(0.5)
        tn.read_very_eager() # Bersihkan buffer sisa

        return tn
    except Exception as e:
        flash(f"Failed to connect: {str(e)}", 'error')
        return None

# Konstanta
MIN_VLAN = 16
MAX_VLAN = 100
MIN_SVLAN = 200
MAX_SVLAN = 1000
MIN_ONU_ID = 1
MAX_ONU_ID = 127

def send_configuration_to_olt(slot, port, onu_id, name, description, vlan, svlan):
    # TODO: Implementasi kirim konfigurasi ke OLT via telnet atau API
    # Ini contoh stub yang bisa kamu ganti dengan logika asli
    print(f"Configuring OLT: slot={slot}, port={port}, onu_id={onu_id}, name={name}")
    return True

# Get Telnet session
def get_telnet_connection(user_id):
    with connection_lock:
        return connections.get(user_id)

# Send command via Telnet
def send_command(tn, command, expect=b'#', wait=0.5):
    try:
        tn.write(command.encode('ascii') + b'\n')
        time.sleep(wait)
        return tn.read_very_eager().decode('utf-8', errors='ignore')
    except Exception as e:
        raise Exception(f"Connection error: {str(e)}")

# ROUTES

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.form.get('ip')
        username = request.form.get('username')
        password = request.form.get('password')

        tn = connect_olt(ip, username, password)
        if tn:
            user_id = str(time.time())

            with connection_lock:
                if 'user_id' in session:
                    old_id = session['user_id']
                    if old_id in connections:
                        try:
                            connections[old_id].write(b"exit\n")
                            connections[old_id].close()
                        except:
                            pass
                        del connections[old_id]

                connections[user_id] = tn
                session['user_id'] = user_id
                session['olt_ip'] = ip
                session['olt_username'] = username
                session['olt_connected'] = True

            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan_onu', methods=['GET', 'POST'])
@login_required
def scan_onu():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            output = send_command(tn, 'show gpon onu uncfg')
            return render_template('scan_onu.html', output=output)
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    return render_template('scan_onu.html')

@app.route('/register_onu', methods=['GET', 'POST'])
@login_required
def register_onu():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            frame = request.form.get('frame')
            ont_id = request.form.get('ont_id')
            sn = request.form.get('sn')
            onu_type = request.form.get('onu_type')

            send_command(tn, 'conf t')
            send_command(tn, f'interface gpon-olt_{frame}')
            send_command(tn, f'onu {ont_id} type {onu_type} sn {sn}')
            send_command(tn, 'exit')

            flash(f"ONU {sn} successfully registered on GPON {frame}", 'success')
            return redirect(url_for('register_onu'))
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('register_onu.html')
@app.route('/setup_onu', methods=['GET', 'POST'])
@login_required
def setup_onu():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            frame = request.form.get('frame')
            name = request.form.get('name')
            desc = request.form.get('desc')
            vlan = request.form.get('vlan')

            send_command(tn, 'conf t')
            send_command(tn, f'interface gpon-onu_1/1/{frame}')
            send_command(tn, f'name {name}')
            send_command(tn, f'description {desc}')
            send_command(tn, 'tcont 1 profile default')
            send_command(tn, 'gemport 1 tcont 1')
            send_command(tn, f'service-port 1 vport 1 user-vlan {vlan} vlan {vlan}')
            send_command(tn, 'exit')

            flash(f"ONU {name} setup successfully", 'success')
            return redirect(url_for('setup_onu'))
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('setup_onu.html')

@app.route('/setup_wan', methods=['GET', 'POST'])
@login_required
def setup_wan():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            frame = request.form.get('frame')
            vlan = request.form.get('vlan')
            username = request.form.get('username')
            password = request.form.get('password')

            send_command(tn, 'conf t')
            send_command(tn, f'pon-onu-mng gpon-onu_1/1/{frame}')
            send_command(tn, f'service pppoe gemport 1 vlan {vlan}')
            send_command(tn, f'wan-ip mode pppoe username {username} password {password} vlan-profile vlan{vlan} host 1')
            send_command(tn, 'exit')

            flash(f"ONU {frame} WAN setup successfully", 'success')
            return redirect(url_for('setup_wan'))
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('setup_wan.html')

@app.route('/monitor_power_port', methods=['GET', 'POST'])
@login_required
def monitor_power_port():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            port = request.form.get('port')
            command = f"show pon power onu-rx gpon-olt_1/1/{port}"
            
            tn.write(command.encode('ascii') + b'\n')
            time.sleep(1)
            
            output = b""
            while True:
                data = tn.read_very_eager()
                output += data
                if b'--More--' in data:
                    tn.write(b' ')
                    time.sleep(0.5)
                elif b'#' in data:
                    break

            lines = output.decode('utf-8', errors='ignore').splitlines()
            results = []
            
            for line in lines:
                line = line.strip()
                if not line or "Onu" in line or "---" in line or command in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    results.append({'onu': parts[0], 'rx_power': parts[1]})

            return render_template('monitor_power_port.html', results=results, port=port)
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('monitor_power_port.html')

@app.route('/monitor_power_user', methods=['GET', 'POST'])
@login_required
def monitor_power_user():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))

    onu_list = []
    selected_onu = None
    result = None

    try:
        # Ambil daftar semua ONU dari "show gpon onu state"
        onu_state_output = send_command(tn, "show gpon onu state", wait=2)

        for line in onu_state_output.splitlines():
            line = line.strip()
            if not line or line.startswith("OnuIndex") or line.startswith("---") or "ONU Number" in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            onu_index = parts[0]
            admin_state = parts[1]
            if admin_state.lower() == "enable":
                onu_list.append(f"gpon-onu_{onu_index}")

        if request.method == 'POST':
            selected_onu = request.form.get('onu_select')
            if selected_onu:
                cmd = f"show pon power attenuation {selected_onu}"
                output = send_command(tn, cmd, wait=2)

                rx_power = "N/A"
                tx_power = "N/A"
                rx_pattern = re.compile(r'Rx\s*:? *(-?\d+\.?\d*)\s*\(?dbm\)?', re.IGNORECASE)
                tx_pattern = re.compile(r'Tx\s*:? *(-?\d+\.?\d*)\s*\(?dbm\)?', re.IGNORECASE)

                for line in output.splitlines():
                    rx_match = rx_pattern.search(line)
                    tx_match = tx_pattern.search(line)
                    if rx_match:
                        rx_power = rx_match.group(1)
                    if tx_match:
                        tx_power = tx_match.group(1)

                result = {
                    "onu": selected_onu,
                    "rx_power": rx_power,
                    "tx_power": tx_power
                }

    except Exception as e:
        flash(f"Terjadi kesalahan: {str(e)}", "error")
        return redirect(url_for('monitor_power_user'))

    return render_template('monitor_power_user.html', onu_list=onu_list, result=result, selected_onu=selected_onu)

@app.route('/delete_onu', methods=['GET', 'POST'])
@login_required
def delete_onu():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            param = request.form.get('param')

            # split the parameter to get port and ont_id
            port, ont_id = param.split(':')

            send_command(tn, 'conf t')
            send_command(tn, f'interface gpon-olt_1/1/{port}')
            result = send_command(tn, f'no onu {ont_id}')
            
            return render_template('delete_onu.html', result=result)
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('delete_onu.html')

@app.route('/olt_onu_detail', methods=['GET', 'POST'])
@login_required
def olt_onu_detail():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))

    onu_list = []

    try:
        onu_state_output = send_command(tn, "show gpon onu state", wait=2)
        for line in onu_state_output.splitlines():
            line = line.strip()
            if not line or line.startswith("OnuIndex") or line.startswith("---") or "ONU Number" in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            onu_index = parts[0]
            admin_state = parts[1]
            if admin_state.lower() == "enable":
                full_onu_id = f"gpon-onu_{onu_index}" # Tambahkan prefix
                onu_list.append(full_onu_id)
    except Exception as e:
        flash(f"Gagal ambil data ONU: {str(e)}", "error")

    output = None
    onu_id = None

    if request.method == 'POST':
        onu_id = request.form.get('onu_id')
        if onu_id:
            try:
                command = f"show gpon onu detail-info {onu_id}"
                output = send_command(tn, command)
                if not output.strip():
                    output = "Data tidak ditemukan atau ONU ID salah."
            except Exception as e:
                flash(str(e), 'error')
                return redirect(url_for('olt_onu_detail'))

    return render_template('check_detail_user.html', onu_list=onu_list, output=output, onu_id=onu_id)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        with connection_lock:
            if user_id in connections:
                try:
                    connections[user_id].write(b"exit\n")
                    connections[user_id].close()
                except:
                    pass
                del connections[user_id]

    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)