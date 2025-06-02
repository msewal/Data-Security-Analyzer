import os
import time
import subprocess #which is used for running commends in os #kommentleri os'te çalışabilmeyi sağlar 
import shutil
import stat

#klasör ve dosyaları listeliyor 
def ls(path):
    if not path:
        path = "."  # varsayılan olarak geçerli dizini kullan
    if os.name == 'nt':
        # Windows ise os.listdir kullan
        entries = os.listdir(path)
        result = []
        for entry in entries:
            full_path = os.path.join(path, entry)
            stats = os.stat(full_path)
            permissions = oct(stats.st_mode)[-3:]
            size = stats.st_size
            owner_user = stats.st_uid if hasattr(stats, 'st_uid') else "N/A"
            owner_group = stats.st_gid if hasattr(stats, 'st_gid') else "N/A"
            modified_time = time.ctime(stats.st_mtime)
            result.append(f"- {permissions} 1 {owner_user} {owner_group} {size} {modified_time} {entry}")
        return "\n".join([""] * 2 + result + [""])
    else:
        # Linux sistemlerde normal ls kullan
        output = subprocess.run(f"ls -lah {path}", capture_output=True, text=True, shell=True).stdout
        return output
#it take a path as an input and executes the "ls -lah" command in the os
#text=True: output should be treated as text
#shell=True: Enables using command directly in the command line.
#capture_output=True: Saves output of the command

def pwd(path):
    output=subprocess.run(f"cd {path}; pwd",capture_output=True,text=True,shell=True).stdout
    return output.strip()
#this command changes to the specified directory and then prints the full path to that directory.
#strip() is used to remove any trailing whitespaces or newline characters.

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


def regex_search_in_file(file_path, pattern):
    import re
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        matches = re.findall(pattern, content)
        return {
            "error": False,
            "matches": matches,
            "count": len(matches)
        }
    except Exception as e:
        return {
            "error": True,
            "msg": str(e)
        }



def malware_scan_file(file_path, signature_file="malware_signatures.txt"):
    import re
    try:
        with open(signature_file, "r", encoding="utf-8") as sigfile:
            patterns = [line.strip() for line in sigfile if line.strip()]

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        matches = []
        for pattern in patterns:
            found = re.findall(pattern, content)
            if found:
                matches.append({
                    "pattern": pattern,
                    "count": len(found)
                })

        return {"error": False, "matches": matches, "total": len(matches)}
    except Exception as e:
        return {"error": True, "msg": str(e)}



import os
import shutil

def quarantine_file(file_path, quarantine_dir="quarantine"):
    try:
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)

        base_name = os.path.basename(file_path)
        dest_path = os.path.join(quarantine_dir, base_name)

        shutil.move(file_path, dest_path)
        return {"error": False, "msg": f"File moved to quarantine: {dest_path}"}
    except Exception as e:
        return {"error": True, "msg": str(e)}



import os
import re

def classify_file(file_path):
    try:
        classifications = {
            "personal": [
                r"[0-9]{11}",               # TC kimlik
                r"[A-Z]{2}\d{2}[A-Z0-9]{16}",  # IBAN
                r"[0-9]{16}",               # Kredi kartı
                r"\b\w+@\w+\.\w+\b",      # E-posta
                r"\+?[0-9]{10,14}"             # Telefon
            ],
            "suspicious": [
                r"eval\(",
                r"base64_decode\(",
                r"<script"
            ]
        }

        results = {
            "path": file_path,
            "categories": [],
            "matches": {},
            "metadata": {}
        }

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for category, patterns in classifications.items():
            for pattern in patterns:
                found = re.findall(pattern, content)
                if found:
                    results["categories"].append(category)
                    if category not in results["matches"]:
                        results["matches"][category] = []
                    results["matches"][category].append({
                        "pattern": pattern,
                        "count": len(found)
                    })

        stat = os.stat(file_path)
        results["metadata"] = {
            "size": stat.st_size,
            "permissions": oct(stat.st_mode)[-3:],
            "last_modified": stat.st_mtime
        }

        append_to_scan_log(results)
        return {"error": False, "result": results}
    except Exception as e:
        return {"error": True, "msg": str(e)}



def append_to_scan_log(entry, log_path="wfe/list/static/scan_logs.json"):
    import json
    try:
        # Var olan kayıtları oku
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
        else:
            logs = []

        # Yeni girdiyi ekle
        logs.append(entry)

        # En fazla 100 kayıt tut (opsiyonel)
        logs = logs[-100:]

        # Dosyaya yaz
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print("Log yazma hatası:", str(e))
