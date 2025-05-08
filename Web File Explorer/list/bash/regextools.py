import os
import re
from .cmd import isTextFile

def regex_search(path, pattern):
    """Search files in a directory using regex pattern"""
    try:
        response = {}
        if not os.path.exists(path):
            response['error'] = True
            response['msg'] = f"Path '{path}' does not exist."
            return response

        matches = []
        
        # If path is a directory, search all files in it
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        try:
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read()
                                for match in re.finditer(pattern, content):
                                    matches.append({
                                        'file': file_path,
                                        'start': match.start(),
                                        'end': match.end(),
                                        'match': match.group()
                                    })
                        except Exception as e:
                            pass  # Skip files that can't be read
        # If path is a file, search that file
        elif os.path.isfile(path):
            try:
                with open(path, 'r', errors='ignore') as f:
                    content = f.read()
                    for match in re.finditer(pattern, content):
                        matches.append({
                            'file': path,
                            'start': match.start(),
                            'end': match.end(),
                            'match': match.group()
                        })
            except Exception as e:
                pass  # Skip files that can't be read
        
        response['error'] = False
        response['matches'] = matches
        response['count'] = len(matches)
        return response
    except Exception as e:
        response = {}
        response['error'] = True
        response['msg'] = str(e)
        return response 