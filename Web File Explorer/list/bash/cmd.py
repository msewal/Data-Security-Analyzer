import os
import subprocess #which is used for running commends in os #kommentleri os'te çalışabilmeyi sağlar 

#klasör ve dosyaları listeliyor 
def ls(path):
    output=subprocess.run(f"ls -lah {path}",capture_output=True,text=True,shell=True).stdout 
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