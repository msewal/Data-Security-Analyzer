import os
import time
import subprocess #which is used for running commends in os #kommentleri os'te çalışabilmeyi sağlar 
import shutil
import stat

#klasör ve dosyaları listeliyor 
def ls(path):
    """
    List directory contents
    """
    try:
        items = []
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            items.append({
                'name': item,
                'type': 'directory' if os.path.isdir(item_path) else 'file',
                'path': item_path
            })
        return {'success': True, 'items': items}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def pwd(path):
    output=subprocess.run(f"cd {path}; pwd",capture_output=True,text=True,shell=True).stdout
    return output.strip()
#this command changes to the specified directory and then prints the full path to that directory.
#strip() is used to remove any trailing whitespaces or newline characters.

#klasör yapmak için 
def mkdir(path):
    """
    Create a directory
    """
    try:
        os.makedirs(path, exist_ok=True)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def touch(path):
    """
    Create an empty file
    """
    try:
        with open(path, 'a'):
            os.utime(path, None)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    
def mv(src, dest):
    """
    Move files or directories
    """
    try:
        shutil.move(src, dest)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    
def cp(src, dest):
    """
    Copy files or directories
    """
    try:
        if os.path.isdir(src):
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    
def chmod(path, mode):
    """
    Change file permissions
    """
    try:
        os.chmod(path, int(mode, 8))
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def isTextFile(path):
    """
    Check if a file is a text file
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            f.read(1024)
        return True
    except:
        return False

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
