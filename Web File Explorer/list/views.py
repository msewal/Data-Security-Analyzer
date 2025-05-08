import os
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from .bash.cmd import ls, pwd, mkdir, cp, mv, touch, chmod, isTextFile, normalize_path
from django.shortcuts import redirect
import json
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import ensure_csrf_cookie

# Import new functionality modules
from .bash.regextools import regex_search
from .bash.malwaretools import malware_scan
from .bash.quarantine import quarantine_file, get_quarantined_files
from .bash.classification import classify_data

def index(request):
    
    context = {}  # prepare the context which will be used to pass data to the template.
    path = request.GET.get("path", "/mnt/c/users/msevv/downloads/")  # Default path for Ubuntu/WSL environment
    
    # Normalize the path
    path = normalize_path(path)
    print(f"DEBUG: Checking path: {path} Exists: {os.path.exists(path)}")  # Add this line
    
    if not os.path.exists(path):
        return render(request, "list/index.html", {
            "list": [],
            "path": path,
            "error": f"'{path}' dizini bulunamadı veya erişilemiyor."
        })

    path = pwd(path) #called to get the full path and updates the variable path.
    result= ls(path) # execute ls command with the wanted path (ls -lah path) and get the result as one whole string
    result_lines= result.split("\n") # split the whole string to lines where each file info is on a separete line
    result_lines= result_lines[2:-1] # get rid of the first two lines of the result (total XX and .) and the last empty line of the result

    files_info = [] # create new array to store each file's information

    # split each line of result_lines to separete arrays / pieces of information
    for line in result_lines:
        parts = line.split()
        if len(parts) < 10:
            continue  # skip malformed lines
        # The filename may contain spaces, so join the rest
        meta = parts[:9]  # permissions, links, owner, group, size, date, time, access frequency
        filename = ' '.join(parts[9:])
        data = meta + [filename]
        files_info.append(data)

    for file in files_info:
        if file[9] == "..":
            file.append(False)
        else:
            full_path = f"{path}/{file[9]}"
            try:
                isText = isTextFile(full_path)
                file.append(isText)
            except Exception:
                file.append(False)

    context["list"] = files_info
    context["path"] = path
 
    return render(request,"list/index.html", context)

def api_mkdir(request):
    try:
        path = request.GET["path"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "path is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = mkdir(path)
    return JsonResponse(mkdir_response)

def api_touch(request):
    try:
        path = request.GET["path"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "path is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = touch(path)
    return JsonResponse(mkdir_response)

def api_mv(request):
    try:
        src = request.GET["src"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "src is not specified."
        return JsonResponse(mkdir_response)
    
    try:
        dest = request.GET["dest"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "dest is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = mv(src, dest)
    return JsonResponse(mkdir_response)

def api_cp(request):
    try:
        src = request.GET["src"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "src is not specified."
        return JsonResponse(mkdir_response)
    
    try:
        dest = request.GET["dest"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "dest is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = cp(src, dest)
    return JsonResponse(mkdir_response)

def api_chmod(request):
    try:
        path = request.GET["path"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "path is not specified."
        return JsonResponse(mkdir_response)
    
    try:
        mod = request.GET["mod"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "mod is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = chmod(path, mod)
    return JsonResponse(mkdir_response)

def edit(request):
    context = {}
    context["texterror"] = False
    context["patherror"] = False
    context["notfounderror"] = False
    try:
        path = request.GET["path"]
        if os.path.exists(path):
            if(os.path.isfile(path) and isTextFile(path)):
                context["path"] = path
                f = open(path, "r")
                lines = f.read()
                context["data"] = lines
            else:
                context["texterror"] = True
        else:
            context["notfounderror"] = True
    except KeyError:
        context["patherror"] = True

    return render(request,"list/edit.html", context)
    
def api_savefile(request):
    if request.method != "POST":
        return redirect("/list")
    else:
        path = request.POST.get('path')
        text = request.POST.get('text')
        f = open(path, 'w')
        f.write(text)
        f.close()
        return redirect(f"/list/edit?path={path}")

# New API endpoint for regex search
def api_regex(request):
    try:
        path = request.GET["path"]
    except KeyError:
        response = {}
        response['error'] = True
        response['msg'] = "path is not specified."
        return JsonResponse(response)
    
    try:
        pattern = request.GET["pattern"]
    except KeyError:
        response = {}
        response['error'] = True
        response['msg'] = "regex pattern is not specified."
        return JsonResponse(response)
    
    search_response = regex_search(path, pattern)
    return JsonResponse(search_response)

# New API endpoint for malware scanning
def api_malware_scan(request):
    try:
        path = request.GET["path"]
    except KeyError:
        response = {}
        response['error'] = True
        response['msg'] = "path is not specified."
        return JsonResponse(response)
    
    scan_type = request.GET.get("type", "quick")
    scan_response = malware_scan(path, scan_type)
    return JsonResponse(scan_response)

# New API endpoint for quarantining files
def api_quarantine(request):
    # If path is provided, quarantine the file
    if "path" in request.GET:
        path = request.GET["path"]
        quarantine_response = quarantine_file(path)
        return JsonResponse(quarantine_response)
    # Otherwise, get the list of quarantined files
    else:
        quarantine_response = get_quarantined_files()
        return JsonResponse(quarantine_response)

# New API endpoint for data classification
@require_http_methods(["POST"])
def api_classify(request):
    try:
        data = json.loads(request.body)
        path = data.get('path')
        classification_type = data.get('type', 'all')  # Default to 'all' if not specified
        
        if not path:
            return JsonResponse({'error': True, 'msg': 'Path is required'})
            
        result = classify_data(path, classification_type)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': True, 'msg': str(e)})

@require_http_methods(["POST"])
def regex_search_view(request):
    try:
        path = request.POST.get('path')
        pattern = request.POST.get('pattern')
        
        if not path or not pattern:
            return JsonResponse({
                'error': True,
                'message': 'Both path and pattern are required'
            })
            
        results = regex_search(path, pattern)
        return JsonResponse({
            'error': False,
            'results': results
        })
    except Exception as e:
        return JsonResponse({
            'error': True,
            'message': str(e)
        })