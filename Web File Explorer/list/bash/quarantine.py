import os
import subprocess
import time

# Create quarantine directory if it doesn't exist
def ensure_quarantine_dir():
    """Ensure the quarantine directory exists"""
    quarantine_dir = os.path.join(os.path.expanduser('~'), 'quarantine')
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    return quarantine_dir

# Quarantine functionality
def quarantine_file(path):
    """Move a suspicious file to quarantine"""
    try:
        response = {}
        if not os.path.exists(path):
            response['error'] = True
            response['msg'] = f"Path '{path}' does not exist."
            return response
        
        if not os.path.isfile(path):
            response['error'] = True
            response['msg'] = f"'{path}' is not a file."
            return response
        
        quarantine_dir = ensure_quarantine_dir()
        filename = os.path.basename(path)
        dest = os.path.join(quarantine_dir, filename)
        
        # If a file with the same name already exists in quarantine, append a timestamp
        if os.path.exists(dest):
            timestamp = int(time.time())
            dest = os.path.join(quarantine_dir, f"{timestamp}_{filename}")
        
        # Move the file to quarantine
        try:
            output = subprocess.run(f"mv {path} {dest}", capture_output=True, text=True, shell=True, check=True).stdout
            response['error'] = False
            response['msg'] = f"File '{filename}' moved to quarantine."
        except subprocess.CalledProcessError as e:
            response['error'] = True
            response['msg'] = e.stderr
        
        return response
    except Exception as e:
        response = {}
        response['error'] = True
        response['msg'] = str(e)
        return response

# Get quarantined files
def get_quarantined_files():
    """Get a list of files in quarantine"""
    try:
        response = {}
        quarantine_dir = ensure_quarantine_dir()
        
        files = []
        for file in os.listdir(quarantine_dir):
            file_path = os.path.join(quarantine_dir, file)
            if os.path.isfile(file_path):
                files.append({
                    'name': file,
                    'path': file_path,
                    'size': os.path.getsize(file_path)
                })
        
        response['error'] = False
        response['files'] = files
        return response
    except Exception as e:
        response = {}
        response['error'] = True
        response['msg'] = str(e)
        return response 