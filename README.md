# 📊 Smart Excel Filtering Assistant

A powerful desktop-based assistant built with **Python** and **Tkinter** to intelligently filter high-risk journal entries in Excel files. It supports natural language queries, multiple filtering criteria, and produces clean reports for audit and finance workflows.

---

## 🚀 Features

- ✅ **Excel Upload & Parsing**
- 🧠 **Conversational Chatbot UI** using Tkinter
- ⏰ **Time-based Filtering** (e.g., entries outside working hours)
- 🔐 **Authorization Filters** (unauthorized or sensitive entries)
- 👤 **Senior Personnel Filter**
- 🔄 **Bypass/Override Detection**
- 📉 **Abnormal Description Detection**
- 🧾 **Sensitive Accounts Filtering**
- ⚠️ **Vague or Missing Descriptions**
- 📄 **Automatic Excel Report Generation**
- 🎯 **High-Risk Detection Engine** (based on 7 criteria)
- 🗣️ **Natural Language Parsing for Time & Keywords**

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Tkinter** (for GUI)
- **Pandas** (for Excel handling)
- **Regex + NLP patterns** (for intent recognition)
- **Dateutil** (for flexible time parsing)
- **OpenPyXL / XlsxWriter** (via `pd.ExcelWriter`)

---

## 📁 Project Structure

Sample-Excel-Filtering/
├── A_Excel_Filtering_Assistant.py # Main script with GUI + logic
├── README.md # Project documentation
└── High_Risk_Report.xlsx # (Generated output, if applicable)


---

## 💡 How It Works

1. **Upload an Excel File** (`.xlsx`)
2. **Interact with the chatbot** using prompts like:
   - _“Show entries outside 9 AM to 5 PM”_
   - _“Filter entries by CFO and Senior Accountant”_
   - _“Detect unauthorized users”_
3. **Bot identifies filters**, applies them, and creates:
   - A filtered Excel output
   - A summary of how many records matched
4. **High-Risk Report** can be generated with one click (7-criteria logic)

---

## 🧪 Installation & Run

```bash
# Clone the repo
git clone https://github.com/alvinkjobi/Sample-Excel-Filtering.git
cd Sample-Excel-Filtering

# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install pandas python-dateutil openpyxl

# Run the assistant
python A_Excel_Filtering_Assistant.py
