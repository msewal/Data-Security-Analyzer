# Generating Fake Data with Python Scripts & Regex
## Create a Virtual Environment
```python
python3 -m venv myenv
```
## Activate the Virtual Environment
```python
source myenv/bin/activate
```

## Install Required Packages
```bash
pip install faker pandas python=docx fpdf openpyxl
```
## Create/Open the python script
```bash
nano generate_fake_data.py
```
## Run the script
```python
from faker import Faker
import pandas as pd
from docx import Document
from fpdf import FPDF

fake = Faker("en_US")  # English locale to avoid special characters

# Number of fake records to generate
num_samples = 100  # Generate data for 100 people

# Generate fake data
data = []
for _ in range(num_samples):
    person = {
        "First Name": fake.first_name(),
        "Last Name": fake.last_name(),
        "National ID": fake.unique.random_number(digits=11, fix_len=True),
        "Phone Number": fake.phone_number(),
        "Email": fake.email(),
        "Credit Card Number": fake.credit_card_number(),
        "IBAN": fake.iban(),
    }
    data.append(person)

df = pd.DataFrame(data)

# **1. Save as JSON**
df.to_json("dummy_data.json", orient="records", indent=4)

# **2. Save as TXT**
with open("dummy_data.txt", "w", encoding="utf-8") as f:
    for row in data:
        f.write(f"{row['First Name']} {row['Last Name']} - ID: {row['National ID']} - Phone: {row['Phone Number']} - Email: {row['Email']} - IBAN: {row['IBAN']}\n")

# **3. Save as CSV**
df.to_csv("dummy_data.csv", index=False, encoding="utf-8")

# **4. Save as DOCX**
doc = Document()
doc.add_heading("Fake Personal Data Set", level=1)
for row in data:
    doc.add_paragraph(f"{row['First Name']} {row['Last Name']} - ID: {row['National ID']} - Phone: {row['Phone Number']} - Email: {row['Email']} - IBAN: {row['IBAN']}")
doc.save("dummy_data.docx")

# **5. Save as PDF**
pdf = FPDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

# Load a font that supports English characters
pdf.set_font("Arial", size=12)

pdf.cell(200, 10, txt="Fake Personal Data Set", ln=True, align="C")
pdf.ln(10)
for row in data:
    pdf.cell(200, 10, txt=f"{row['First Name']} {row['Last Name']} - ID: {row['National ID']} - Phone: {row['Phone Number']} - Email: {row['Email']} - IBAN: {row['IBAN']}", ln=True)
pdf.output("dummy_data.pdf")

# Success message
print("Fake data set has been successfully generated!")
```
## Run the Fake Data Generator
```python
python generate_fake_data.py
```
## Create/Open the Sensitive Data Detection Script
```bash
nano detect_sensitive_data.py
```
## Regex-Based Sensitive Data Detection
```bash
import re
import os
import json
import pandas as pd
from docx import Document

# Files to scan
files_to_scan = [
    "dummy_data.txt",
    "dummy_data.json",
    "dummy_data.csv",
    "dummy_data.docx"
]

# Regex patterns for detecting sensitive information
regex_patterns = {
    "National ID": r"\b\d{11}\b",  # 11-digit National ID
    "Phone Number": r"\b\d{10,11}\b",  # 10-11 digit phone number
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email format
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",  # 13-16 digit credit card
    "IBAN": r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"  # IBAN pattern
}

# Dictionary to store detected data
detected_data = {}

# Function to scan TXT, CSV, and JSON files
def scan_text_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            detected_data[file_path] = {}
            for label, pattern in regex_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    detected_data[file_path][label] = matches
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

# Function to scan DOCX files
def scan_docx_file(file_path):
    try:
        doc = Document(file_path)
        content = "\n".join([para.text for para in doc.paragraphs])
        detected_data[file_path] = {}
        for label, pattern in regex_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                detected_data[file_path][label] = matches
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

# Scan files
for file in files_to_scan:
    if file.endswith(".txt") or file.endswith(".csv") or file.endswith(".json"):
        scan_text_file(file)
    elif file.endswith(".docx"):
        scan_docx_file(file)

# Save detected data as JSON
with open("detected_sensitive_data.json", "w", encoding="utf-8") as f:
    json.dump(detected_data, f, indent=4)

print("Sensitive data detection completed! Results saved in detected_sensitive_data.json")

```
## Run the Sensitive Data Detection Script
```python
python detect_sensitive_data.py
```
## View Detected Data
```bash
cat detected_sensitive_data.json
```





