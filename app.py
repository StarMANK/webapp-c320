from flask import Flask, render_template, request, redirect, url_for, session, flash
import telnetlib
import time
from functools import wraps
from threading import Lock
import atexit

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key

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

# Decorator to check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def connect_olt(ip, username, password):
    try:
        tn = telnetlib.Telnet(ip, timeout=10)
        tn.read_until(b'Username:')
        tn.write(username.encode('ascii') + b'\n')
        tn.read_until(b'Password:')
        tn.write(password.encode('ascii') + b'\n')
        tn.read_until(b'#')
        return tn
    except Exception as e:
        flash(f"Failed to connect: {str(e)}", 'error')
        return None

def get_telnet_connection(user_id):
    with connection_lock:
        return connections.get(user_id)

def send_command(tn, command, expect=b'#', wait=0.5):
    try:
        tn.write(command.encode('ascii') + b'\n')
        time.sleep(wait)
        return tn.read_very_eager().decode('utf-8', errors='ignore')
    except Exception as e:
        raise Exception(f"Connection error: {str(e)}")

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.form.get('ip')
        username = request.form.get('username')
        password = request.form.get('password')
        
        tn = connect_olt(ip, username, password)
        if tn:
            # Generate unique user ID for this session
            user_id = str(time.time())
            
            with connection_lock:
                # Close any existing connection for this user
                if 'user_id' in session:
                    old_id = session['user_id']
                    if old_id in connections:
                        try:
                            connections[old_id].write(b"exit\n")
                            connections[old_id].close()
                        except:
                            pass
                        del connections[old_id]
                
                # Store new connection
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

@app.route('/monitor_power', methods=['GET', 'POST'])
@login_required
def monitor_power():
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

            return render_template('monitor_power.html', results=results, port=port)
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('monitor_power.html')

@app.route('/check_user', methods=['GET', 'POST'])
@login_required
def check_user():
    tn = get_telnet_connection(session['user_id'])
    if not tn:
        flash("Connection lost. Please login again.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            param = request.form.get('param')

            send_command(tn, 'conf t')
            result = send_command(tn, f'show pon power onu-rx gpon-onu_1/1/{param}')
            
            return render_template('check_user.html', result=result)
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('check_user.html')

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
            onu_id = request.form.get('onu_id')

            send_command(tn, 'conf t')
            send_command(tn, f'interface gpon-olt_1/1/{param}')
            result = send_command(tn, f'no onu {onu_id}')
            
            return render_template('delete_onu.html', result=result)
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('login'))
    
    return render_template('delete_onu.html')

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
    app.run(debug=True)