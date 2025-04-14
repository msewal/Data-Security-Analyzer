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
