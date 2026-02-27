import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Ensure directories exist
os.makedirs("model", exist_ok=True)

DATA_PATH = "data/KDDTrain+.txt" # Place this file in your project folder
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack_name_str", "difficulty_score"
]

print("Loading NSL-KDD dataset...")
try:
    df = pd.read_csv(DATA_PATH, names=COLUMNS, header=None)
except FileNotFoundError:
    print(f"Error: {DATA_PATH} not found. Please place it in the project folder.")
    exit()

df["label"] = df["attack_name_str"].astype(str).str.strip().str.rstrip(".")

def map_attack(lbl):
    lbl = lbl.lower()
    dos = {"back","land","neptune","pod","smurf","teardrop","apache2","udpstorm","processtable","mailbomb"}
    probe = {"satan","ipsweep","nmap","portsweep","mscan","saint"}
    r2l = {"ftp_write","guess_passwd","imap","phf","spy","warezclient","warezmaster","multihop","snmpguess","snmpgetattack","httptunnel","sendmail","xlock","xsnoop"}
    u2r = {"buffer_overflow","loadmodule","perl","rootkit","sqlattack","xterm","ps"}
    if lbl == "normal": return "Normal"
    if lbl in dos: return "DoS"
    if lbl in probe: return "Probe"
    if lbl in r2l: return "R2L"
    if lbl in u2r: return "U2R"
    return "Other"

df["category"] = df["label"].apply(map_attack)
FEATURES = COLUMNS[:41]
X = df[FEATURES].copy()
y = df["category"].copy()

cat_cols = X.select_dtypes(include=['object']).columns.tolist()
num_cols = X.select_dtypes(exclude=['object']).columns.tolist()

preprocessor = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_cols),
    ("num", StandardScaler(), num_cols),
])

pipeline = Pipeline([
    ("pre", preprocessor),
    ("clf", RandomForestClassifier(n_estimators=120, random_state=42, n_jobs=-1, class_weight='balanced'))
])

print("Training model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
pipeline.fit(X_train, y_train)

print("\nEvaluation Report:")
print(classification_report(y_test, pipeline.predict(X_test), zero_division=0))

joblib.dump(pipeline, "model/pipeline.pkl")
print("\nModel saved to model/pipeline.pkl")