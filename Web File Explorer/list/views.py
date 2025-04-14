import os
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from .bash.cmd import ls, pwd, mkdir, cp, mv, touch, chmod, isTextFile
from django.shortcuts import redirect


def index(request):
    
    context = {}  # prepare the context which will be used to pass data to the template.
    path = request.GET.get("path", "")  # Get the wanted path from  the information the browser sent (/list?path=XXXXX)
    path = pwd(path) #called to get the full path and updates the variable path.
    result= ls(path) # execute ls command with the wanted path (ls -lah path) and get the result as one whole string
    result_lines= result.split("\n") # split the whole string to lines where each file info is on a separete line
    result_lines= result_lines[2:-1] # get rid of the first two lines of the result (total XX and .) and the last empty line of the result

    files_info = [] # create new array to store each file's information

    # split each line of result_lines to separete arrays / pieces of information
    for line in result_lines:
        data = line.split()
        files_info.append(data) #Appends the list of words (information) to the files_info list.

    for file in files_info:
        if file[8] == "..":
            file.append(False)
        else:
            full_path = f"{path}/{file[8]}"
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