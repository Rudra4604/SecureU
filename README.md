# Cyber Security Website Checker using Machine Learning

A modern, web-based vulnerability scanner and threat defense tool. This project uses a hybrid approach, combining **Active Cybersecurity Heuristics** with **Machine Learning & NLP Analysis** to provide a dual-layered assessment of any target website.

## 🚀 Project Overview
The "Cyber Security Website Checker" aims to identify potential risks and malicious intents of given URLs in real-time. It evaluates URLs based on their structural payload, infrastructure configurations (SSL/Headers), and content risks using advanced Natural Language Processing.

## ✨ Features (50% Cyber / 50% ML)

### 🔐 Cybersecurity Features
1. **SSL / TLS Certificate Validation**: Validates the presence of HTTPS and checks if the underlying SSL certificate is valid.
2. **HTTP Security Headers Check**: Audits responses for crucial protection headers (e.g., CSP, HSTS, X-Frame-Options, X-XSS-Protection).
3. **Passive Vulnerability Scan**: Passively crawls page content to identify potential XSS and SQL Injection vectors.
4. **URL Heuristics**: Analyzes the structural integrity of the URL (e.g., excessive length, IP address masking, multiple subdomains).
5. **Infrastructure Availability**: Tracks status codes, request timeouts, and overall latency.

### 🤖 Machine Learning Features
1. **URL Intent Classifier (Logistic Regression)**: Predicts malicious intent based on feature vectors extracted from the target URL.
2. **Intelligent Recommendation Engine**: A content-based heuristic filter that proposes actionable fixes depending on the specific combination of threats detected.

---

## ⚙️ System Workflow
1. **Input Phase**: User enters a target URL into the modern Dashboard.
2. **Orchestration**: The Flask Backend simultaneously dispatches requests to the Cybersecurity Engine and ML Pipeline.
3. **Cyber Assessment**: Executes connection handshakes, HTTP header parsing, and regex-based vulnerability scanning.
4. **ML Inference**: URL features are scaled and passed through the saved Logistic Regression model for binary classification.
5. **Scoring Engine**: Evaluates the disparate data sources to assign an aggregate threat score out of 100.
6. **Output Generation**: Renders a comprehensive, glassmorphism-styled metrics dashboard and produces a downloadable artifact report.

---

## 🧠 Algorithms Explanation

### 1. Logistic Regression Model
Our primary classifier uses Logistic Regression to perform binary classification (Safe vs. Malicious). The model relies on four core features: `[URL Length, HTTPS Presence, Special Char Count, IP Masking]`.

**Mathematical Formula:**
Logistic Regression uses the Sigmoid function to squash values between 0 and 1:
$$ P(Y=1 | X) = \frac{1}{1 + e^{-(\beta_0 + \beta_1x_1 + \beta_2x_2 + \dots + \beta_nx_n)}} $$
Where:
- $P(Y=1 | X)$ is the probability of the URL being malicious.
- $\beta_0$ is the intercept/bias.
- $\beta_n$ are the learned weights for their respective features ($x_n$).

If the probability $P \ge 0.5$, it is labeled "Malicious", else "Safe".

### 2. TF-IDF (Term Frequency-Inverse Document Frequency)
Used to actively gauge phishing language and urgency markers in the HTML content without relying on fixed rigid strings alone.

**Mathematical Formula:**
$$ \text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \text{IDF}(t, D) $$
Where:
- **TF (Term Frequency)**: $ \text{TF}(t, d) = \frac{\text{Count of term } t \text{ in document } d}{\text{Total terms in document } d} $
- **IDF (Inverse Document Frequency)**: $ \text{IDF}(t, D) = \log\left(\frac{\text{Total documents in corpus } N}{\text{Documents containing term } t}\right) $

A higher combined score indicates suspicious linguistic intent characteristic of Social Engineering.

---

## 🛠️ Installation Steps

1. **Clone the Directory**
   Ensure you have downloaded or cloned this project folder to your local machine.

2. **Set up the Environment** (Optional but Recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   The project requires the libraries outlined in the requirements file.
   ```bash
   pip install -r "requirements (1).txt"
   ```
   *(Note: Ensure requirements include `flask`, `scikit-learn`, `requests`, `numpy`, and `beautifulsoup4`)*

---

## 💻 How to Run

1. **Ensure ML Models are Ready**
   If `models/model.pkl` and `models/scaler.pkl` do not exist, run the training script first:
   ```bash
   python train_model.py
   ```

2. **Start the Flask Backend**
   ```bash
   python app.py
   ```

3. **Access the Application**
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

---

## 📊 Example Output
Upon scanning a target like `http://example.com`:
- **Security Score**: `85/100 (Safe)`
- **ML Engine**: `Safe (98.4% Confidence)`
- **Infrastructure**: `Missing HSTS Header`
- **Output Report Formats**: Displays interactive UI progress bars and a downloadable `.txt` report breakdown.

---

## 🔮 Future Enhancements
- Integrations with VirusTotal / Shodan APIs for Threat Intelligence Enrichment.
- Deployment via Docker containers for universal setup.
- Advanced ML integration using Deep Learning (LSTM / Transformers) for superior heuristic evasion detection.
- PDF Report generation for business compliance contexts.
