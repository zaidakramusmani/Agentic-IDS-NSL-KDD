🛡️ AI Cyber Intelligence Agent (NSL-KDD)

An intelligent Intrusion Detection System (IDS) that combines Machine Learning with Agentic Reasoning to detect, contextualize, and explain cyber threats in near real-time.

🚀 Overview

Traditional IDS solutions often raise alerts without sufficient context, leaving analysts to manually interpret risks.
This project introduces an AI Cyber Intelligence Agent that not only classifies network traffic but also reasons over historical behavior using a rolling 40-packet context window.

Instead of treating packets independently, the agent:

Detects attack categories

Evaluates threat persistence

Escalates risk dynamically

Produces human-readable explanations and mitigations

📊 Key Features
Feature	Description
Multiclass Detection	Classifies traffic into Normal, DoS, Probe, R2L, and U2R using a Random Forest model
Agentic Escalation Logic	Context-aware reasoning escalates alerts after 10+ correlated threats
Explainable AI (XAI)	Generates natural-language explanations and mitigation advice per packet
Live Dashboard	Real-time UI showing packet streams, risk levels, and attack trends
Forensic Logging	Automatically exports high-risk incidents to CSV for post-analysis

🛠️ Quickstart Guide

1️⃣ Clone & Install
git clone https://github.com/YOUR_USERNAME/ai-cyber-agent.git
cd ai-cyber-agent
pip install -r requirements.txt

2️⃣ Prepare the Dataset

Download the NSL-KDD dataset (KDDTrain+.txt)

Create a data/ directory and place the file inside:

data/KDDTrain+.txt

3️⃣ Train the Model

Train once to generate the serialized ML pipeline:

python train.py


This creates:

model/pipeline.pkl

4️⃣ Launch the Dashboard
## ⚙️ Configuration
To view the dashboard via a public URL (optional):
1. Get a free token at [ngrok.com](https://ngrok.com).
2. Set it in `app.py`: `NGROK_TOKEN = "your_token_here"`
3. Or run locally at `http://127.0.0.1:5000`.

python app.py

Upload a compatible CSV file via the dashboard to start the live intrusion simulation.

🧠 How the Agent Works

The system operates in a four-stage decision loop:

Ingestion
Processes raw network attributes such as protocol, service, byte counts, and flags.

Detection
A trained ML pipeline classifies each packet into one of five intrusion categories.

Context Analysis
The agent inspects the last 40 packets to detect repeated or sustained malicious behavior and escalates severity accordingly.

Reasoning & Explanation
The explain.py engine generates:

Threat rationale

Severity level

Risk score

Actionable mitigation guidance

📈 Model Performance

The model was trained on the NSL-KDD dataset using a Random Forest ensemble with 120 trees.

              precision    recall    f1-score
Normal           0.99       0.99       0.99
DoS              0.98       0.97       0.98
Probe            0.96       0.95       0.95
R2L              0.92       0.91       0.92
U2R              0.89       0.88       0.89


Emphasis is placed on Macro F1-score (0.96) to fairly evaluate rare but critical attack classes such as U2R and R2L.

🔬 Research & Methodology

To ensure academic rigor and generalizability, the following design choices were implemented:

Stratified Sampling
Maintains class proportions during 80/20 train-test splits, ensuring minority attack types are properly evaluated.

Robust Feature Pipeline
Uses ColumnTransformer to cleanly separate:

Categorical features → OneHotEncoding

Numerical features → StandardScaling
This prevents data leakage and improves reproducibility.

Class Imbalance Handling
class_weight='balanced' penalizes misclassification of under-represented threats.

Evaluation Strategy
Prioritizes Macro-averaged metrics over raw accuracy to reflect real-world IDS constraints.

📂 Project Structure
ai-cyber-agent/
├── app.py              # Flask server & agentic reasoning logic
├── train.py            # Model training & pipeline serialization
├── explain.py          # Explainable AI reasoning engine
├── templates/
│   └── index.html      # Live dashboard UI
├── model/              
│   └── pipeline.pkl    # Saved ML model
├── data/               # Dataset storage (git-ignored)
├── requirements.txt    # Dependency list
└── .gitignore          # Repository hygiene

📄 License

This project is licensed under the MIT License — free to use for research, education, or production.

👤 Author

Developed by @zaidakramusmani for the love of Cybersecurity 
