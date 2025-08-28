





Overview

Phishing attacks are one of the most common cybersecurity threats, often delivered through malicious URLs designed to trick users. Traditional detection methods rely on string-based features, which can be easily manipulated by attackers.

This project introduces a graph-based machine learning approach that models URLs, IP addresses, and domain servers as interconnected nodes in a graph. Using Loopy Belief Propagation (LBP), the system performs probabilistic inference to detect phishing URLs more effectively.


---

✨ Features

✅ Graph construction of URLs, IPs, and authoritative name servers

✅ Loopy Belief Propagation (LBP) for probabilistic inference

✅ Higher accuracy compared to rule-based and feature-only models

✅ Scalable for real-time phishing detection



---

🛠 Tech Stack

Programming Language: Python

Framework: Flask (for web interface, optional)

Libraries: Scikit-learn, NetworkX, Pandas, NumPy

Database (if used): MySQL / SQLite



---

⚙️ How It Works

1. Extract features from given URLs.


2. Build a graph structure with URLs, IP addresses, and domains as nodes.


3. Apply Loopy Belief Propagation to propagate beliefs across the graph.


4. Classify URLs as Phishing or Legitimate based on probability scores.




---

🚀 How to Run

1. Clone the repository

git clone https://github.com/Madiha-Naaz/PHISHING-DETECTION-USING-ML-AND-LOOPY-BELIEF-PROPOGATION.git

cd PHISHING-DETECTION-USING-ML-AND-LOOPY-BELIEF-PROPOGATION


2. Create and activate virtual environment

python -m venv env

source env/bin/activate # On Linux/Mac

env\Scripts\activate      # On Windows


3. Install dependencies

pip install -r requirements.txt


4. Run the application

python app.py


5. Open the app in your browser at:

http://127.0.0.1:5000/




---

📊 Results

Improved detection accuracy over traditional URL-based methods

Robust against manipulated or obfuscated phishing URLs

Effective in real-time phishing detection scenarios
