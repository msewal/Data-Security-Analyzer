#
## View Detected Data
```bash
nano mask_sensitive_data.py
```

## 
```python
import json
import re

# Load detected sensitive data
with open("detected_sensitive_data.json", "r", encoding="utf-8") as f:
    detected_data = json.load(f)

# Function to mask data
def mask_data(data_type, value):
    if data_type == "National ID":
        return "*********" + value[-3:]  # Show last 3 digits
    elif data_type == "Phone Number":
        return "*******" + value[-3:]  # Show last 3 digits
    elif data_type == "Credit Card":
        return "**** **** **** " + value[-4:]  # Show last 4 digits
    elif data_type == "IBAN":
        return value[:2] + "*****************" + value[-3:]  # Show first 2 and last 3
    elif data_type == "Email":
        parts = value.split("@")
        return parts[0][0] + "***@" + parts[1]  # Show first letter and domain
    return value  # If type is not recognized, return as is

# Apply masking
masked_data = {}
for file, data in detected_data.items():
    masked_data[file] = {}
    for data_type, values in data.items():
        masked_data[file][data_type] = [mask_data(data_type, v) for v in values]

# Save masked data
with open("masked_sensitive_data.json", "w", encoding="utf-8") as f:
    json.dump(masked_data, f, indent=4)

print("Sensitive data has been masked and saved in masked_sensitive_data.json")
```

##
```python
python mask_sensitive_data.py
```

##
```python
cat masked_sensitive_data.json
```

##
```python
nano encrypt_sensitive_data.py
```
##
```python
pip install cryptography
```
##
```python
pip list | grep cryptography
```

##
```python
import json
from cryptography.fernet import Fernet

# Generate or load encryption key
try:
    with open("encryption_key.key", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)

cipher_suite = Fernet(key)

# Load detected sensitive data
with open("detected_sensitive_data.json", "r", encoding="utf-8") as f:
    detected_data = json.load(f)

# Encrypt function
def encrypt_data(value):
    return cipher_suite.encrypt(value.encode()).decode()

# Encrypt data
encrypted_data = {}
for file, data in detected_data.items():
    encrypted_data[file] = {}
    for data_type, values in data.items():
        encrypted_data[file][data_type] = [encrypt_data(v) for v in values]

# Save encrypted data
with open("encrypted_sensitive_data.json", "w", encoding="utf-8") as f:
    json.dump(encrypted_data, f, indent=4)

print("Sensitive data has been encrypted and saved in encrypted_sensitive_data.json")
```

##
```python
python encrypt_sensitive_data.py
```

##
```bash
cat encrypted_sensitive_data.json
```

##
```python
python encrypt_sensitive_data.py
```
python encrypt_sensitive_data.py
