let body = document.body;
let outerShadow = document.getElementById("outer-shadow");

let mkdirForm = document.getElementById("mkdir-form");
let touchForm = document.getElementById("touch-form");
let cpForm = document.getElementById("cp-form");
let mvForm = document.getElementById("mv-form");
let chmodForm = document.getElementById("chmod-form");

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



// Regex Tara butonu ve form
const regexForm = document.getElementById("regex-form");
const regexResult = document.getElementById("regex-result");

if (regexForm) {
    regexForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const path = document.getElementById("regex-path").value;
        const pattern = document.getElementById("regex-pattern").value;

        fetch(`/list/api/regex_search/?path=${encodeURIComponent(path)}&pattern=${encodeURIComponent(pattern)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    regexResult.textContent = "Hata: " + data.msg;
                } else {
                    regexResult.textContent = `🔍 ${data.count} eşleşme bulundu:

` + data.matches.join("\n");
                }
            })
            .catch(error => {
                regexResult.textContent = "İstek başarısız: " + error;
            });
    });
}



// ☣️ Malware Tara formu
const malwareForm = document.getElementById("malware-form");
const malwareResult = document.getElementById("malware-result");

if (malwareForm) {
    malwareForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const path = document.getElementById("malware-path").value;

        fetch(`/list/api/malware_scan/?path=${encodeURIComponent(path)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    malwareResult.textContent = "Hata: " + data.msg;
                } else if (data.total > 0) {
                    let output = `☠️ ${data.total} potansiyel tehdit bulundu:\n`;
                    data.matches.forEach(m => {
                        output += `- Pattern: ${m.pattern}, Sayı: ${m.count}\n`;
                    });
                    malwareResult.textContent = output;
                } else {
                    malwareResult.textContent = "✅ Hiçbir zararlı imza bulunamadı.";
                }
            })
            .catch(error => {
                malwareResult.textContent = "İstek başarısız: " + error;
            });
    });
}



// 🛑 Karantinaya Al formu
const quarantineForm = document.getElementById("quarantine-form");
const quarantineResult = document.getElementById("quarantine-result");

if (quarantineForm) {
    quarantineForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const path = document.getElementById("quarantine-path").value;

        fetch(`/list/api/quarantine/?path=${encodeURIComponent(path)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    quarantineResult.textContent = "Hata: " + data.msg;
                } else {
                    quarantineResult.textContent = "✅ " + data.msg;
                }
            })
            .catch(error => {
                quarantineResult.textContent = "İstek başarısız: " + error;
            });
    });
}



// 🧠 Dosya Sınıflandır formu
const classifyForm = document.getElementById("classify-form");
const classifyResult = document.getElementById("classify-result");

if (classifyForm) {
    classifyForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const path = document.getElementById("classify-path").value;

        fetch(`/list/api/classify_file/?path=${encodeURIComponent(path)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    classifyResult.textContent = "Hata: " + data.msg;
                } else {
                    let result = data.result;
                    let output = `📄 Dosya: ${result.path}\n`;
                    output += `🔍 Sınıflar: ${result.categories.join(", ") || "Yok"}\n\n`;

                    output += `📎 Eşleşen Kalıplar:\n`;
                    for (let category in result.matches) {
                        output += `- ${category.toUpperCase()}\n`;
                        result.matches[category].forEach(m => {
                            output += `  • ${m.pattern} (${m.count} eşleşme)\n`;
                        });
                    }

                    output += `\n📊 Metadata:\n`;
                    output += `- Boyut: ${result.metadata.size} byte\n`;
                    output += `- İzinler: ${result.metadata.permissions}\n`;
                    output += `- Değiştirilme: ${new Date(result.metadata.last_modified * 1000).toLocaleString()}\n`;

                    classifyResult.textContent = output;
                }
            })
            .catch(error => {
                classifyResult.textContent = "İstek başarısız: " + error;
            });
    });
}
