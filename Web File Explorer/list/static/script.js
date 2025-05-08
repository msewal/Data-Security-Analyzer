let body = document.body;
let outerShadow = document.getElementById("outer-shadow");

let mkdirForm = document.getElementById("mkdir-form");
let touchForm = document.getElementById("touch-form");
let cpForm = document.getElementById("cp-form");
let mvForm = document.getElementById("mv-form");
let chmodForm = document.getElementById("chmod-form");
let regexForm = document.getElementById("regex-form");
let malwareScanForm = document.getElementById("malware-scan-form");
let quarantineForm = document.getElementById("quarantine-form");
let classifyForm = document.getElementById("classify-form");

// Initialize display settings for forms
mkdirForm.style.display = "none";
touchForm.style.display = "none";
cpForm.style.display = "none";
mvForm.style.display = "none";
chmodForm.style.display = "none";
regexForm.style.display = "none";
malwareScanForm.style.display = "none";
quarantineForm.style.display = "none";
classifyForm.style.display = "none";

let formMsg = document.getElementById("msg");

// form close btn
let formClose = document.getElementById("close");
formClose.addEventListener("click", () => {
    outerShadow.style.display = "none";
    body.style.overflow = "";
    mkdirForm.style.display = "none";
    touchForm.style.display = "none";
    cpForm.style.display = "none";
    mvForm.style.display = "none";
    chmodForm.style.display = "none";
    regexForm.style.display = "none";
    malwareScanForm.style.display = "none";
    quarantineForm.style.display = "none";
    classifyForm.style.display = "none";
    window.location.reload();
})

// mkdir form
let mkdir_btn = document.getElementById("mkdir")
mkdir_btn.addEventListener("click", () => {
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    mkdirForm.style.display = "block";
})
mkdirForm.addEventListener("submit", e => {
    e.preventDefault();
    let path = document.getElementById("mkdir-path");
    let name = document.getElementById("mkdir-name");
    let mkdirPath = `${path.value}/${name.value}`;
    fetch(`${window.location.origin}/list/api/mkdir/?path=${mkdirPath}`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            msg = `DONE! ${json.msg}`
        }
        formMsg.textContent = msg;
    })
})


// touch form
let touch_btn = document.querySelector("#touch")
touch_btn.addEventListener("click", () => {
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    touchForm.style.display = "block";
})
touchForm.addEventListener("submit", e => {
    e.preventDefault();
    let path = document.getElementById("touch-path");
    let name = document.getElementById("touch-name");
    let touchPath = `${path.value}/${name.value}`;
    fetch(`${window.location.origin}/list/api/touch/?path=${touchPath}`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            msg = `DONE! ${json.msg}`
        }
        formMsg.textContent = msg;
    })
})

// cp form
let cp_src = document.getElementById("cp-src");
let cp_dest = document.getElementById("cp-dest");
let cp_title = document.getElementById("cp-title");
let cp_btns = Array.from(document.querySelectorAll(".cp"))
for (let cp_btn of cp_btns) {
    let src = cp_btn.dataset.path;
    cp_btn.addEventListener("click", () => {
        cp_src.value = src;
        cp_dest.value = src.substring(0, src.lastIndexOf("/")) + "/";
        cp_title.textContent = `Copy file ${src} to:`
        body.style.overflow = "hidden";
        outerShadow.style.display = "flex";
        cpForm.style.display = "block";
    })
}
cpForm.addEventListener("submit", e => {
    e.preventDefault();
    fetch(`${window.location.origin}/list/api/cp/?src=${cp_src.value}&dest=${cp_dest.value}`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            msg = `DONE! ${json.msg}`
        }
        formMsg.textContent = msg;
    })
})

// mv form
let mv_src = document.getElementById("mv-src");
let mv_dest = document.getElementById("mv-dest");
let mv_title = document.getElementById("mv-title");
let mv_btns = Array.from(document.querySelectorAll(".mv"))
for (let mv_btn of mv_btns) {
    let src = mv_btn.dataset.path;
    mv_btn.addEventListener("click", () => {
        mv_src.value = src;
        mv_dest.value = src.substring(0, src.lastIndexOf("/")) + "/";
        mv_title.textContent = `Move file ${src} to:`
        body.style.overflow = "hidden";
        outerShadow.style.display = "flex";
        mvForm.style.display = "block";
    })
}
mvForm.addEventListener("submit", e => {
    e.preventDefault();
    fetch(`${window.location.origin}/list/api/mv/?src=${mv_src.value}&dest=${mv_dest.value}`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            msg = `DONE! ${json.msg}`
        }
        formMsg.textContent = msg;
    })
})

// chmod form
let chmod_path = document.getElementById("chmod-path");
let chmod_mod = document.getElementById("chmod-mod");
let chmod_title = document.getElementById("chmod-title");
let chmod_btns = Array.from(document.querySelectorAll(".chmod"))
for (let chmod_btn of chmod_btns) {
    let path = chmod_btn.dataset.path;
    chmod_btn.addEventListener("click", () => {
        chmod_path.value = path;
        chmod_title.textContent = `Change permissions on file ${path} to:`
        body.style.overflow = "hidden";
        outerShadow.style.display = "flex";
        chmodForm.style.display = "block";
    })
}
chmodForm.addEventListener("submit", e => {
    e.preventDefault();
    fetch(`${window.location.origin}/list/api/chmod/?path=${chmod_path.value}&mod=${chmod_mod.value}`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            msg = `DONE! ${json.msg}`
        }
        formMsg.textContent = msg;
    })
})


// edit file
let edit_buttons = Array.from(document.querySelectorAll(".edit"));
for (let edit_btn of edit_buttons) {
    edit_btn.addEventListener("click", () => {
        window.open(`${window.location.origin}/list/edit?path=${edit_btn.dataset.path}`, '_blank');
    })
}



// show-cp button
let show_cp_btn = document.getElementById("show-cp");
show_cp_btn.addEventListener("click", () => {
    cp_src.value = "";
    cp_dest.value = "";
    cp_title.textContent = `Copy file (manual):`;
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    cpForm.style.display = "block";
});

// show-mv button
let show_mv_btn = document.getElementById("show-mv");
show_mv_btn.addEventListener("click", () => {
    mv_src.value = "";
    mv_dest.value = "";
    mv_title.textContent = `Move file (manual):`;
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    mvForm.style.display = "block";
});

// show-chmod button
let show_chmod_btn = document.getElementById("show-chmod");
show_chmod_btn.addEventListener("click", () => {
    chmod_path.value = "";
    chmod_mod.value = "";
    chmod_title.textContent = `Change permissions (manual):`;
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    chmodForm.style.display = "block";
});

// Regex search functionality
let show_regex_btn = document.getElementById("show-regex");
show_regex_btn.addEventListener("click", () => {
    let regex_pattern = document.getElementById("regex-pattern");
    regex_pattern.value = "";
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    regexForm.style.display = "block";
});
regexForm.addEventListener("submit", e => {
    e.preventDefault();
    let path = document.getElementById("regex-path");
    let pattern = document.getElementById("regex-pattern");
    fetch(`${window.location.origin}/list/api/regex/?path=${path.value}&pattern=${pattern.value}`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            msg = `DONE! Found ${json.matches.length} matches.`
        }
        formMsg.textContent = msg;
    })
});

// Malware scan functionality
let show_malware_scan_btn = document.getElementById("show-malware-scan");
show_malware_scan_btn.addEventListener("click", () => {
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    malwareScanForm.style.display = "block";
});
malwareScanForm.addEventListener("submit", e => {
    e.preventDefault();
    let path = document.getElementById("malware-scan-path");
    let scanType = document.getElementById("scan-type");
    fetch(`${window.location.origin}/list/api/malware-scan/?path=${path.value}&type=${scanType.value}`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            if (json.threats.length > 0) {
                msg = `ALERT! Found ${json.threats.length} potential threats.`
            } else {
                msg = `DONE! No threats found.`
            }
        }
        formMsg.textContent = msg;
    })
});

// Quarantine functionality
let quarantine_path = document.getElementById("quarantine-path");
let quarantine_title = document.getElementById("quarantine-title");
let show_quarantine_btn = document.getElementById("show-quarantine");
show_quarantine_btn.addEventListener("click", () => {
    quarantine_path.value = "";
    quarantine_title.textContent = `View quarantined files:`;
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    quarantineForm.style.display = "block";
    // Load quarantined files
    fetch(`${window.location.origin}/list/api/quarantine/`)
    .then(resp => resp.json())
    .then(json => {
        if (json.error) {
            msg = `ERROR: ${json.msg}`
        } else {
            if (json.files.length > 0) {
                msg = `${json.files.length} files in quarantine.`
            } else {
                msg = `No files in quarantine.`
            }
        }
        formMsg.textContent = msg;
    })
});

// Add quarantine functionality to file context
let quarantine_btns = Array.from(document.querySelectorAll(".quarantine"))
for (let quarantine_btn of quarantine_btns) {
    let path = quarantine_btn.dataset.path;
    quarantine_btn.addEventListener("click", () => {
        quarantine_path.value = path;
        quarantine_title.textContent = `Move file ${path} to quarantine:`;
        body.style.overflow = "hidden";
        outerShadow.style.display = "flex";
        quarantineForm.style.display = "block";
    })
}
quarantineForm.addEventListener("submit", e => {
    e.preventDefault();
    if (quarantine_path.value) {
        fetch(`${window.location.origin}/list/api/quarantine/?path=${quarantine_path.value}`)
        .then(resp => resp.json())
        .then(json => {
            if (json.error) {
                msg = `ERROR: ${json.msg}`
            } else {
                msg = `DONE! File moved to quarantine.`
            }
            formMsg.textContent = msg;
        })
    } else {
        formMsg.textContent = "No file selected for quarantine.";
    }
});

// Data classification functionality
let show_classify_btn = document.getElementById("show-classify");
show_classify_btn.addEventListener("click", () => {
    body.style.overflow = "hidden";
    outerShadow.style.display = "flex";
    classifyForm.style.display = "block";
});
classifyForm.addEventListener("submit", async function(e) {
    e.preventDefault();
    const path = document.getElementById('classify-path').value;
    const type = document.getElementById('classify-type').value;
    
    try {
        const response = await fetch('/list/api/classify/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ path, type })
        });
        
        const result = await response.json();
        
        if (result.error) {
            formMsg.textContent = `ERROR: ${result.msg}`;
        } else {
            let message = 'Classification Results:\n';
            if (result.summary) {
                message += result.summary + '\n\n';
            }
            
            if (result.classified_files && result.classified_files.length > 0) {
                message += 'Files containing sensitive data:\n';
                result.classified_files.forEach(file => {
                    message += `\nFile: ${file.file}\n`;
                    Object.entries(file.classifications).forEach(([type, count]) => {
                        if (count > 0) {
                            message += `- ${type}: ${count} matches\n`;
                        }
                    });
                });
            }
            
            formMsg.textContent = message;
        }
    } catch (error) {
        formMsg.textContent = `Error during classification: ${error.message}`;
    }
});
