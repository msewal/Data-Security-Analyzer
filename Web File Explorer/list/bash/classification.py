import os
import re
from .cmd import isTextFile

def classify_data(path, classification_type="all"):
    """Classify data in files based on patterns"""
    try:
        response = {}
        if not os.path.exists(path):
            response['error'] = True
            response['msg'] = f"Path '{path}' does not exist."
            return response
        
        classifications = {
            'sensitive': 0,
            'personal': 0,
            'financial': 0
        }
        
        # Define patterns for different types of data
        patterns = {
            'sensitive': [
                r'password', r'passwd', r'secret', r'api_key', r'token',
                r'auth', r'credentials', r'private', r'confidential'
            ],
            'personal': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # US Phone
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP Address
                r'\bname\b', r'\baddress\b', r'\bphone\b'
            ],
            'financial': [
                r'\b(?:\d[ -]*?){13,16}\b',  # Credit card-like
                r'\baccount\b', r'\bbank\b', r'\bcredit\b', r'\bdebit\b',
                r'\bpayment\b', r'\binvoice\b', r'\btransaction\b', r'\bbalance\b'
            ]
        }
        
        classified_files = []
        
        # Function to check a file for sensitive data
        def check_file(file_path):
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    file_classifications = {'sensitive': 0, 'personal': 0, 'financial': 0}
                    
                    # Check selected or all classification types
                    types_to_check = [classification_type] if classification_type != "all" else patterns.keys()
                    
                    for data_type in types_to_check:
                        if data_type in patterns:
                            for pattern in patterns[data_type]:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                if matches:
                                    file_classifications[data_type] += len(matches)
                                    classifications[data_type] += len(matches)
                    
                    # Add file to classified files if any matches found
                    if any(count > 0 for count in file_classifications.values()):
                        classified_files.append({
                            'file': file_path,
                            'classifications': file_classifications
                        })
            except Exception as e:
                pass  # Skip files that can't be read
        
        # Process files
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path) and isTextFile(file_path):
                        check_file(file_path)
        elif os.path.isfile(path) and isTextFile(path):
            check_file(path)
        
        # Create summary
        summary = []
        for data_type, count in classifications.items():
            if count > 0:
                summary.append(f"{data_type}: {count}")
        
        response['error'] = False
        response['classifications'] = classifications
        response['classified_files'] = classified_files
        response['summary'] = ", ".join(summary) if summary else "No sensitive data found"
        return response
    except Exception as e:
        response = {}
        response['error'] = True
        response['msg'] = str(e)
        return response 