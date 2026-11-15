# 🛡️ CyberAI Assistant

### AI-Powered Cybersecurity SOC Platform

CyberAI Assistant is a personal cybersecurity project designed to support security log analysis, threat assessment, incident investigation, and SOC monitoring using Python, Streamlit, and locally hosted AI with Ollama.

The project focuses on defensive cybersecurity, Blue Team operations, and beginner-friendly security investigation.

## 🚀 Features

### 1. AI Cybersecurity Chat
- AI-powered cybersecurity assistance
- Uses Llama 3.2 through Ollama
- Supports SOC, network security, log analysis, and incident response topics

### 2. Security Log Analyzer
- Upload `.log` and `.txt` files
- Detect failed login attempts
- Identify suspicious IP addresses
- Display security metrics and charts
- Calculate SHA-256 file hashes

### 3. Threat Assessment
- Risk score calculation
- Threat level classification
- Attack classification
- Event timeline generation

### 4. SOC Dashboard
- Investigation statistics
- Failed login metrics
- Suspicious IP overview
- Threat level distribution
- Risk score trends

### 5. Investigation & Reporting
- Investigation history using SQLite
- AI-assisted investigation reports
- PDF security reports

### 6. SOC Case Management
- Open, Investigating, and Resolved case statuses
- Analyst assignment
- Analyst notes
- Case status monitoring

### 7. Live SOC Monitor
- Live security monitoring
- Automatic refresh
- Security activity overview

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming |
| Streamlit | Web application interface |
| Ollama | Local AI model runtime |
| Llama 3.2 | AI language model |
| Pandas | Data processing |
| SQLite | Investigation and case storage |
| ReportLab | PDF report generation |
| Git & GitHub | Version control |

## 📂 Project Structure

```text
CyberAI-Assistant/
│
├── app.py
├── main.py
├── database.py
├── live_monitor.py
├── log_analyzer.py
├── README.md
└── .gitignore
```

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.12
- Ollama
- Git

### Step 1: Clone the repository

```bash
git clone https://github.com/mdwasim33/CyberAI-Assistant.git
```

### Step 2: Enter the project directory

```bash
cd CyberAI-Assistant
```

### Step 3: Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it on macOS/Linux:

```bash
source .venv/bin/activate
```

### Step 4: Install dependencies

```bash
pip install streamlit pandas ollama reportlab
```

### Step 5: Install and run the AI model

Install Ollama from:

https://ollama.com/

Download Llama 3.2:

```bash
ollama pull llama3.2
```

Make sure Ollama is running.

### Step 6: Launch the application

```bash
python -m streamlit run app.py
```

The application will open in your browser.

## 🗺️ Project Roadmap

### Phase 1 — Core SOC Platform
- AI Chat
- Security Log Analyzer
- Threat Assessment
- SOC Dashboard
- Investigation History
- PDF Reporting
- SOC Case Management
- Live SOC Monitoring

**Status: Completed**

### Phase 2 — Advanced SOC Features
- Threat Intelligence Integration
- MITRE ATT&CK Mapping
- Advanced Alert Management
- Incident Response Recommendations

**Status: Planned**

### Phase 3 — AI & Machine Learning
- Machine Learning-based Threat Detection
- Advanced Anomaly Detection
- Intelligent Security Analytics

**Status: Planned**

### Phase 4 — Professional Platform
- Public Demo Deployment
- Improved User Experience
- Enhanced Security and Scalability

**Status: Planned**

## 🔐 Security Notice

This project is intended for educational and defensive cybersecurity purposes.

- Use only logs and systems you are authorized to analyze.
- Do not upload confidential or real production security logs to a public demo.
- Local AI functionality requires Ollama and the Llama 3.2 model.
- This project is under active development and is not a replacement for a production SOC or SIEM platform.

## 👨‍💻 Author

**Md Wasim**

Cybersecurity | Blue Team | SOC Operations | AI in Cybersecurity

GitHub: https://github.com/mdwasim33

---

⭐ If you find this project interesting, consider starring the repository!

*Building. Learning. Securing.*
