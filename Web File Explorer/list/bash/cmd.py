import os
import time
import subprocess #which is used for running commends in os #kommentleri os'te çalışabilmeyi sağlar 
from datetime import datetime, timedelta

#klasör ve dosyaları listeliyor 
def get_access_frequency(full_path):
    try:
        stats = os.stat(full_path)
        current_time = time.time()
        access_time = stats.st_atime
        modified_time = stats.st_mtime
        
        # Calculate time difference in days
        time_diff = current_time - access_time
        days_diff = time_diff / (24 * 3600)
        
        if days_diff < 1:
            return "Today"
        elif days_diff < 7:
            return "This week"
        elif days_diff < 30:
            return "This month"
        elif days_diff < 90:
            return "Last 3 months"
        elif days_diff < 180:
            return "Last 6 months"
        else:
            return "Older"
    except:
        return "Unknown"

def normalize_path(path):
    """Convert Windows path to Linux path format when running on Linux"""
    if os.name != 'nt':  # If running on Linux
        # Convert Windows path to Linux path
        if path.startswith('C:'):
            path = '/mnt/c' + path[2:]
        elif path.startswith('c:'):
            path = '/mnt/c' + path[2:]
        # Replace backslashes with forward slashes
        path = path.replace('\\', '/')
    return path

def ls(path):
    if not path:
        path = "."  # varsayılan olarak geçerli dizini kullan
    
    # Normalize the path
    path = normalize_path(path)
    
    if os.name == 'nt':
        # Windows ise os.listdir kullan
        entries = os.listdir(path)
        result = []
        for entry in entries:
            full_path = os.path.join(path, entry)
            stats = os.stat(full_path)
            # Format permissions like Linux ls -l
            is_dir = os.path.isdir(full_path)
            perms = "d" if is_dir else "-"
            perms += "rwx" if stats.st_mode & 0o400 else "---"
            perms += "rwx" if stats.st_mode & 0o040 else "---"
            perms += "rwx" if stats.st_mode & 0o004 else "---"
            
            size = stats.st_size
            owner_user = stats.st_uid if hasattr(stats, 'st_uid') else "N/A"
            owner_group = stats.st_gid if hasattr(stats, 'st_gid') else "N/A"
            modified_time = time.strftime("%b %d %H:%M", time.localtime(stats.st_mtime))
            access_freq = get_access_frequency(full_path)
            result.append(f"{perms} 1 {owner_user} {owner_group} {size} {modified_time} {access_freq} {entry}")
        return "\n".join([""] * 2 + result + [""])
    else:
        # Linux sistemlerde normal ls kullan ve access frequency ekle
        try:
            output = subprocess.run(f"ls -lah '{path}'", capture_output=True, text=True, shell=True).stdout
            lines = output.split('\n')
            result = []
            for line in lines[2:-1]:  # Skip total line and empty lines
                parts = line.split()
                if len(parts) >= 9:
                    full_path = os.path.join(path, parts[-1])
                    access_freq = get_access_frequency(full_path)
                    parts.insert(-1, access_freq)  # Insert access frequency before filename
                    result.append(' '.join(parts))
            return "\n".join([""] * 2 + result + [""])
        except Exception as e:
            return f"\n\nError accessing directory: {str(e)}\n"

def pwd(path):
    path = normalize_path(path)
    if os.name == 'nt':
        output = subprocess.run(f"cd {path}; pwd", capture_output=True, text=True, shell=True).stdout
    else:
        output = subprocess.run(f"cd '{path}' && pwd", capture_output=True, text=True, shell=True).stdout
    return output.strip()

#klasör yapmak için 
def mkdir(path):
    try:
        output=subprocess.run(f"mkdir {path}",capture_output=True,text=True,shell=True,check=True).stdout
        # Başarı durumunda bir bildirim oluştur
        mkdir_response = {}
        mkdir_response['error'] = False
        mkdir_response['msg'] = "directory created."
        return mkdir_response
    except subprocess.CalledProcessError as e:
         # Hata durumunda bir hata bildirimi oluştur
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = e.stderr
        return mkdir_response
    
def touch(path):
    try:
        output=subprocess.run(f"touch {path}",capture_output=True,text=True,shell=True,check=True).stdout
        mkdir_response = {}
        mkdir_response['error'] = False
        mkdir_response['msg'] = "file created."
        return mkdir_response
    except subprocess.CalledProcessError as e:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = e.stderr
        return mkdir_response
    
def mv(src, dest):
    try:
        output=subprocess.run(f"mv {src} {dest}",capture_output=True,text=True,shell=True,check=True).stdout
        mkdir_response = {}
        mkdir_response['error'] = False
        mkdir_response['msg'] = "file moved."
        return mkdir_response
    except subprocess.CalledProcessError as e:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = e.stderr
        return mkdir_response
    
def cp(src, dest):
    src_is_dir = os.path.isdir(src)
    dest_is_dir = os.path.isdir(dest)
    if not dest_is_dir:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "destination is not a directory."
        return mkdir_response
    dashR = "-r " if src_is_dir else ""
    try:
        output=subprocess.run(f"cp {dashR}{src} {dest}",capture_output=True,text=True,shell=True,check=True).stdout
        mkdir_response = {}
        mkdir_response['error'] = False
        mkdir_response['msg'] = "file copied."
        return mkdir_response
    except subprocess.CalledProcessError as e:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = e.stderr
        return mkdir_response
    
def chmod(path, mod):
    try:
        output=subprocess.run(f"chmod {mod} {path}",capture_output=True,text=True,shell=True,check=True).stdout
        mkdir_response = {}
        mkdir_response['error'] = False
        mkdir_response['msg'] = "permissions changed."
        return mkdir_response
    except subprocess.CalledProcessError as e:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = e.stderr
        return mkdir_response

def isTextFile(path):
    # read chunk of file
    fh = open(path,'r')
    file_data = fh.read(512)
    fh.close()

    # store chunk length read
    data_length = len(file_data)
    if (not data_length):
        # empty files considered text
        return True

    if ('\x00' in file_data):
        # file containing null bytes is binary
        return False

    # remove all text characters from file chunk, get remaining length
    text_chars = ''.join([chr(code) for code in range(32,127)] + list('\b\f\n\r\t'))
    binary_length = len("".join(c for c in file_data if c not in text_chars))
    print(file_data.replace(text_chars, ""))

    # if percentage of binary characters above 0.3, binary file
    return (
        (float(binary_length) / data_length) < 0.3
    )