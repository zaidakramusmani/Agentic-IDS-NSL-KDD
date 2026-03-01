
---

#  Autonomous Network Intrusion Detection System

### Explainable AI with Agentic Reasoning (NSL-KDD)

![Python](https://img.shields.io/badge/Python-3.10-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![ML](https://img.shields.io/badge/ML-Random%20Forest-orange)

An **intelligent Intrusion Detection System (IDS)** that combines **Machine Learning**, **Explainable AI (XAI)**, and **agentic reasoning** to detect, contextualize, and explain cyber threats in near real time.

Unlike traditional IDS pipelines that generate isolated alerts, this system reasons over **temporal network behavior** using a rolling context window and produces **human-readable explanations with mitigation guidance**.

---

##  Overview

Conventional IDS solutions often flag packets independently, leaving security analysts to manually infer severity, persistence, and intent.

This project introduces an **AI Cyber Intelligence Agent** that:

* Classifies network traffic using a supervised ML pipeline
* Analyzes **historical packet context (last 40 packets)**
* Detects sustained or correlated attack patterns
* Dynamically escalates threat severity
* Generates **natural-language explanations and mitigation advice**

The result is an IDS that is **interpretable, context-aware, and operationally useful**.

---

##  Key Features

| Feature                            | Description                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------------- |
| **Multiclass Intrusion Detection** | Classifies traffic into **Normal, DoS, Probe, R2L, U2R** using a Random Forest ensemble |
| **Agentic Escalation Logic**       | Context-aware reasoning escalates alerts after **10+ correlated malicious events**      |
| **Explainable AI (XAI)**           | Produces human-readable threat explanations and recommended actions                     |
| **Live Monitoring Dashboard**      | Real-time UI displaying packet streams, risk levels, and attack trends                  |
| **Forensic Logging**               | Automatically exports high-risk incidents to CSV for post-incident analysis             |

---

##  How the Agent Works

The system operates through a **four-stage decision loop**:

### 1️ Ingestion

Processes raw network features such as:

* Protocol type
* Service
* Flag status
* Byte counts and connection statistics

### 2️ Detection

A trained ML pipeline classifies each packet into one of five intrusion categories.

### 3️ Context Analysis

The agent inspects the **last 40 packets** to identify:

* Repeated malicious behavior
* Persistence across time
* Escalation conditions

Severity increases when correlated threats exceed defined thresholds.

### 4️ Reasoning & Explanation

The XAI engine generates:

* Threat rationale
* Severity level
* Risk score
* Actionable mitigation guidance

---

## Model Performance

Trained on the **NSL-KDD** dataset using a **Random Forest (120 trees)**.

```
              precision    recall    f1-score
Normal           0.99       0.99       0.99
DoS              0.98       0.97       0.98
Probe            0.96       0.95       0.95
R2L              0.92       0.91       0.92
U2R              0.89       0.88       0.89
```

**Macro F1-score: 0.96**

> Macro-averaged metrics are emphasized to fairly evaluate rare but critical attack classes such as **U2R** and **R2L**.

---

##  Research & Methodology

To ensure academic rigor and reproducibility, the following design principles were applied:

### ✔ Stratified Sampling

Maintains class proportions during an **80/20 train-test split**, ensuring minority classes are properly evaluated.

### ✔ Robust Feature Pipeline

Implemented using `ColumnTransformer`:

* **Categorical features → OneHotEncoding**
* **Numerical features → StandardScaling**

This avoids data leakage and ensures consistent preprocessing.

### ✔ Class Imbalance Handling

Uses `class_weight="balanced"` to penalize misclassification of under-represented attacks.

### ✔ Evaluation Strategy

Focuses on **Macro-averaged Precision, Recall, and F1-score** rather than raw accuracy.

---

##  Quickstart Guide

### 1️ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ai-cyber-agent.git
cd ai-cyber-agent
pip install -r requirements.txt
```

---

### 2️ Prepare the Dataset

Download **NSL-KDD** (`KDDTrain+.txt`) and place it inside:

```
data/KDDTrain+.txt
```

> The `data/` directory is git-ignored.

---

### 3️ Train the Model

```bash
python train.py
```

This generates:

```
model/pipeline.pkl
```

---

### 4️ Launch the Dashboard

```bash
python app.py
```

Access locally at:

```
http://127.0.0.1:5000
```

---

##  Optional: Public Dashboard via Ngrok

1. Create a free account at **ngrok.com**
2. Set your token in `app.py`:

```python
NGROK_TOKEN = "your_token_here"
```

3. Restart the server to obtain a public URL

---

##  Project Structure

```
ai-cyber-agent/
├── app.py              # Flask server & agentic reasoning logic
├── train.py            # Model training & pipeline serialization
├── explain.py          # Explainable AI reasoning engine
├── templates/
│   └── index.html      # Live dashboard UI
├── model/
│   └── pipeline.pkl    # Saved ML pipeline
├── data/               # Dataset storage (git-ignored)
├── requirements.txt    # Dependencies
└── .gitignore          # Repository hygiene
```

---

##  License

This project is licensed under the **MIT License** — free for research, education, and production use.

---

## 👤 Author

**Zaid Akram Usmani**
Built with a deep interest in **Cybersecurity, AI-driven defense systems, and explainable machine intelligence**.

---
