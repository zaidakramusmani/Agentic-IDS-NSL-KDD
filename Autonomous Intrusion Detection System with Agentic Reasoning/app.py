from flask import Flask, request, render_template, send_file, jsonify
import pandas as pd
import joblib, os, time, threading, json, random
from pyngrok import ngrok
from explain import generate_explanation

app = Flask(__name__)

# CONFIGURATION
NGROK_TOKEN = "YOUR_NGROK_TOKEN_HERE" 
os.makedirs("uploads", exist_ok=True)
os.makedirs("results", exist_ok=True)

# GLOBALS FOR SIMULATION
pipeline = None  # Initialize to None
live_packets = []
high_risk_log = []
threat_memory = []
_live_lock = threading.Lock()
_memory_lock = threading.Lock()
simulation_running = False
simulation_thread = None

# LOAD MODEL SAFELY
model_path = os.path.join("model", "pipeline.pkl")
if os.path.exists(model_path):
    try:
        pipeline = joblib.load(model_path)
        print("--- Model loaded successfully! ---")
    except Exception as e:
        print(f"--- Error loading model file: {e} ---")
else:
    print(f"--- Critical Error: {model_path} not found. Run train.py first. ---")

EXPECTED = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent",
    "hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

# AGENT CONSTANTS
CONTEXT_WINDOW = 40
ESCALATION_COUNT = 10
MEMORY_FEATURES = ["src_bytes","dst_bytes","count","srv_count","dst_host_count"]

def safe_int(v):
    try: return int(float(v))
    except: return 0

def agent_decision_and_reasoning(prediction, context_window, numeric_signature):
    pred = str(prediction).lower()
    severity, base, action = "low", 20, "Normal Monitoring"
    reason_lines = [f"Model predicted: {pred.upper()}"]

    if pred in ["u2r", "r2l"]:
        severity, base, action = "high", 85, "ALERT: Immediate Isolation Required"
    elif pred in ["dos", "probe"]:
        severity, base, action = "medium", 50, "WARNING: Throttling Active"

    high_count = sum(1 for p in context_window if p.get('severity') in ('high','medium'))
    if high_count >= ESCALATION_COUNT and severity != "high":
        severity, base, action = "high", 80, "ESCALATION: Sustained Attack Pattern"
        reason_lines.append(f"Escalated due to {high_count} previous events.")

    risk_score = int(max(0, min(100, base + random.uniform(-3, 3))))
    suggestions = ["Monitor source IP"] if severity=="low" else ["Isolate Host", "Capture PCAP"]
    return action, severity, risk_score, "\n".join(reason_lines), suggestions

def simulate_live(df, delay, mode):
    global simulation_running, live_packets, pipeline
    
    # Safety Check: If model isn't loaded, stop simulation
    if pipeline is None:
        print("Simulation Error: Pipeline variable is None. Prediction aborted.")
        simulation_running = False
        return

    idx = 0
    while simulation_running:
        try:
            row = df.iloc[idx]
            X_input = row[EXPECTED].copy().to_frame().T
            
            # Predict
            pred = pipeline.predict(X_input)[0]
            
            # Agent Logic
            num_sig = {k: safe_int(row.get(k, 0)) for k in MEMORY_FEATURES}
            with _live_lock:
                context = list(live_packets[-CONTEXT_WINDOW:])
            
            action, sev, risk, reas, sugg = agent_decision_and_reasoning(pred, context, num_sig)
            
            pkt = {
                "protocol_type": str(row.get("protocol_type","")),
                "service": str(row.get("service","")),
                "flag": str(row.get("flag","")),
                "src_bytes": safe_int(row.get("src_bytes",0)),
                "dst_bytes": safe_int(row.get("dst_bytes",0)),
                "prediction": str(pred),
                "severity": sev,
                "risk_score": risk,
                "reasoning": reas,
                "suggestions": sugg,
                "explanation": generate_explanation(row.to_dict(), pred),
                "ts": int(time.time())
            }

            with _live_lock:
                live_packets.append(pkt)
                if len(live_packets) > 200: live_packets.pop(0)
                if sev == "high": high_risk_log.append(pkt)
            
            idx = (idx + 1) % len(df)
            time.sleep(delay)
        except Exception as e:
            print(f"Error in simulation loop: {e}")
            break

@app.route("/", methods=["GET","POST"])
def index():
    global simulation_running, simulation_thread
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            path = os.path.join("uploads", "input.csv")
            f.save(path)
            df = pd.read_csv(path)
            simulation_running = True
            simulation_thread = threading.Thread(target=simulate_live, args=(df, 2, "seq"), daemon=True)
            simulation_thread.start()
    return render_template("index.html")

@app.route("/live")
def live():
    with _live_lock:
        return jsonify(list(reversed(live_packets)))

@app.route("/download/high_risk_log.csv")
def download():
    pd.DataFrame(high_risk_log).to_csv("results/high_risk_log.csv", index=False)
    return send_file("results/high_risk_log.csv", as_attachment=True)

if __name__ == "__main__":
    if NGROK_TOKEN and NGROK_TOKEN != "YOUR_NGROK_TOKEN_HERE":
        try:
            ngrok.set_auth_token(NGROK_TOKEN)
            public_url = ngrok.connect(5000).public_url
            print(" * Public URL:", public_url)
        except Exception as e:
            print(f" * Ngrok failed: {e}")
    else:
        print(" * No Ngrok token found. Running in local mode only.")
    
    app.run(port=5000, debug=False)