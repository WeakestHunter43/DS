const zipInput =
document.getElementById("zipInput");

const patchBtn =
document.getElementById("patchBtn");

const uidContainer =
document.getElementById("uidContainer");

const log =
document.getElementById("log");

let parsedZip = null;

let uidGroups = {};

let validSlots = {};

// ======================================================
// RULES
// ======================================================

const markerRules = [

{
    name:"SetID",
    from:-10001,
    to:-269001
},

{
    name:"HairID",
    from:-10001,
    to:-269002
},

{
    name:"HeadAdditiveID",
    from:-10001,
    to:-269003
},

{
    name:"FaceID",
    from:-10001,
    to:-269004
},

{
    name:"ChestID",
    from:-10001,
    to:-269005
},

{
    name:"LegsID",
    from:-10001,
    to:-269006
},

{
    name:"FeetID",
    from:-10001,
    to:-269007
},

{
    name:"wSkinIDs",
    from:-10001,
    to:-14056
},

{
    name:"bSkinID",
    from:-10001,
    to:-14075
}

];

// ======================================================
// LOG
// ======================================================

function addLog(t,cls="success"){

    log.innerHTML +=
    `<div class="${cls}">➜ ${t}</div>`;

    log.scrollTop =
    log.scrollHeight;
}

// ======================================================
// STRING TO HEX
// ======================================================

function stringToHex(str){

    return Array
    .from(str)
    .map(c=>

        c.charCodeAt(0)
        .toString(16)
        .padStart(2,"0")

    )
    .join(" ");
}

// ======================================================
// SIGNED VARINT64
// ======================================================

function encodeSignedVarint64(num){

    let value =
    BigInt.asUintN(
        64,
        BigInt(num)
    );

    const out = [];

    while(value >= 0x80n){

        out.push(
            Number(
                (value & 0x7Fn)
                | 0x80n
            )
        );

        value >>= 7n;
    }

    out.push(Number(value));

    return out
    .map(v=>

        v
        .toString(16)
        .padStart(2,"0")

    )
    .join(" ");
}

// ======================================================
// PATCHES
// ======================================================

const markerPatches =

markerRules.map(r=>({

    name:r.name,

    marker:
    stringToHex(r.name),

    search:
    "88 01 " +
    encodeSignedVarint64(r.from),

    replace:
    "88 01 " +
    encodeSignedVarint64(r.to)
}));

// ======================================================
// HEX
// ======================================================

function hexToBytes(hex){

    return hex
    .trim()
    .split(/\s+/)
    .map(x=>parseInt(x,16));
}

// ======================================================
// FIND PATTERN
// ======================================================

function findPattern(
    data,
    pattern,
    start=0
){

    for(
        let i=start;
        i<=data.length-pattern.length;
        i++
    ){

        let ok = true;

        for(
            let j=0;
            j<pattern.length;
            j++
        ){

            if(
                data[i+j] !== pattern[j]
            ){

                ok = false;
                break;
            }
        }

        if(ok)
            return i;
    }

    return -1;
}

// ======================================================
// REPLACE BYTES
// ======================================================

function replaceBytes(
    data,
    oldBytes,
    newBytes
){

    const pos =
    findPattern(
        data,
        Array.from(oldBytes)
    );

    if(pos === -1)
        return data;

    const before =
    Array.from(
        data.slice(0,pos)
    );

    const after =
    Array.from(
        data.slice(
            pos + oldBytes.length
        )
    );

    return new Uint8Array([

        ...before,
        ...newBytes,
        ...after
    ]);
}

// ======================================================
// MD5
// ======================================================

function md5Bytes(buffer){

    const hex =
    SparkMD5.ArrayBuffer.hash(buffer);

    const out =
    new Uint8Array(16);

    for(let i=0;i<16;i++){

        out[i] =
        parseInt(
            hex.substr(i*2,2),
            16
        );
    }

    return out;
}

// ======================================================
// VARINT
// ======================================================

function readVarint(data,pos){

    let result = 0n;

    let shift = 0n;

    let start = pos;

    while(true){

        const b =
        BigInt(data[pos]);

        pos++;

        result |=
        (b & 0x7Fn) << shift;

        if((b & 0x80n) === 0n)
            break;

        shift += 7n;
    }

    return [

        result,
        pos,
        data.slice(start,pos)
    ];
}

function encodeVarint(value){

    let n = BigInt(value);

    const out = [];

    while(n >= 0x80n){

        out.push(
            Number(
                (n & 0x7Fn) | 0x80n
            )
        );

        n >>= 7n;
    }

    out.push(Number(n));

    return new Uint8Array(out);
}

// ======================================================
// UID INFO
// ======================================================

function getUidInfo(data){

    let pos = 0;

    while(pos < data.length){

        const [tag,p1] =
        readVarint(data,pos);

        pos = p1;

        const field =
        Number(tag >> 3n);

        const wire =
        Number(tag & 7n);

        if(wire === 0){

            const [
                value,
                p2,
                raw
            ] =
            readVarint(data,pos);

            pos = p2;

            if(field === 7){

                return {

                    uid:
                    value.toString(),

                    raw
                };
            }
        }

        else if(wire === 1){

            pos += 8;
        }

        else if(wire === 2){

            const [len,p2] =
            readVarint(data,pos);

            pos =
            p2 + Number(len);
        }

        else if(wire === 5){

            pos += 4;
        }

        else{

            break;
        }
    }

    return null;
}

// ======================================================
// PATCH USERLEVEL
// ======================================================

function patchByMarker(data,p){

    const marker =
    hexToBytes(p.marker);

    const search =
    hexToBytes(p.search);

    const replace =
    hexToBytes(p.replace);

    let pos = 0;

    while(true){

        const found =
        findPattern(
            data,
            search,
            pos
        );

        if(found === -1)
            break;

        const markerPos =
        found +
        search.length +
        94;

        let ok = true;

        for(
            let i=0;
            i<marker.length;
            i++
        ){

            if(
                data[markerPos+i]
                !== marker[i]
            ){

                ok = false;
                break;
            }
        }

        if(ok){

            for(
                let i=0;
                i<replace.length;
                i++
            ){

                data[found+i] =
                replace[i];
            }

            addLog(
                `PATCHED ${p.name}`
            );

            break;
        }

        pos = found + 1;
    }
}

// ======================================================
// ZIP LOAD
// ======================================================

zipInput.addEventListener(
"change",
async ()=>{

    log.innerHTML = "";

    uidContainer.innerHTML = "";

    uidGroups = {};

    validSlots = {};

    patchBtn.disabled = true;

    const file =
    zipInput.files[0];

    if(!file)
        return;

    if(
        !file.name
        .toLowerCase()
        .endsWith(".zip")
    ){

        addLog(
            "ONLY ZIP FILE SUPPORTED",
            "fail"
        );

        return;
    }

    let zipBuffer;

    try{

        zipBuffer =
        await file.arrayBuffer();

    }catch(e){

        addLog(
            "FILE READ FAILED",
            "fail"
        );

        return;
    }

    try{

        parsedZip =
        await JSZip.loadAsync(
            zipBuffer
        );

    }catch(e){

        addLog(
            "INVALID OR CORRUPTED ZIP",
            "fail"
        );

        return;
    }

    addLog("ZIP LOADED");

    const slots = {};

    Object.keys(parsedZip.files)
    .forEach(name=>{

        let m =
        name.match(
            /^ProjectData_slot_(\d+)\.bytes$/i
        );

        if(m){

            if(!slots[m[1]])
                slots[m[1]] = {};

            slots[m[1]].pbytes = name;
        }

        m =
        name.match(
            /^ProjectData_slot_(\d+)\.meta$/i
        );

        if(m){

            if(!slots[m[1]])
                slots[m[1]] = {};

            slots[m[1]].meta = name;
        }

        m =
        name.match(
            /^UserLevelData_(\d+)\.bytes$/i
        );

        if(m){

            if(!slots[m[1]])
                slots[m[1]] = {};

            slots[m[1]].ul = name;
        }
    });

    for(const slot in slots){

        const s = slots[slot];

        if(
            !s.ul ||
            !s.meta ||
            !s.pbytes
        ){

            addLog(
                `SKIP SLOT ${slot} MISSING FILES`,
                "fail"
            );

            continue;
        }

        let buffer;

        try{

            buffer =
            await parsedZip
            .file(s.pbytes)
            .async("arraybuffer");

        }catch(e){

            addLog(
                `READ FAIL SLOT ${slot}`,
                "fail"
            );

            continue;
        }

        const info =
        getUidInfo(
            new Uint8Array(buffer)
        );

        if(!info){

            addLog(
                `UID READ FAIL SLOT ${slot}`,
                "fail"
            );

            continue;
        }

        const uid =
        info.uid;

        if(!uidGroups[uid])
            uidGroups[uid] = [];

        uidGroups[uid]
        .push(slot);

        validSlots[slot] = s;

        addLog(
            `VALID SLOT ${slot}`
        );
    }

    if(
        Object.keys(validSlots).length
        === 0
    ){

        addLog(
            "NO VALID SLOT FOUND",
            "fail"
        );

        return;
    }

    Object.keys(uidGroups)
    .forEach(uid=>{

        const div =
        document.createElement("div");

        div.className =
        "uid-group";

        div.innerHTML = `

        <label>
        Slots:
        ${uidGroups[uid].join(",")}
        </label>

        <input
        type="text"
        value="${uid}"
        data-old="${uid}">
        `;

        uidContainer
        .appendChild(div);
    });

    patchBtn.disabled = false;

    addLog("ZIP READY");
});

// ======================================================
// MAIN PATCH
// ======================================================

patchBtn.onclick =
async ()=>{

    log.innerHTML = "";

    addLog("START PATCH");

    const outZip =
    new JSZip();

    const inputs =
    uidContainer.querySelectorAll("input");

    const uidMap = {};

    inputs.forEach(i=>{

        uidMap[
            i.dataset.old
        ] = i.value.trim();
    });

    for(const slot in validSlots){

        const s =
        validSlots[slot];

        addLog(
            `PROCESS SLOT ${slot}`
        );

        // ===============================================
        // USERLEVEL
        // ===============================================

        const oldUlBuffer =
        await parsedZip
        .file(s.ul)
        .async("arraybuffer");

        let ulData =
        new Uint8Array(
            oldUlBuffer
        );

        const oldUlMd5 =
        md5Bytes(
            oldUlBuffer
        );

        markerPatches.forEach(p=>{

            patchByMarker(
                ulData,
                p
            );
        });

        const newUlMd5 =
        md5Bytes(
            ulData.buffer
        );

        // ===============================================
        // PROJECTDATA
        // ===============================================

        const oldPBuffer =
        await parsedZip
        .file(s.pbytes)
        .async("arraybuffer");

        let pData =
        new Uint8Array(
            oldPBuffer
        );

        const oldPSize =
        pData.length;

        const oldPMd5 =
        md5Bytes(
            oldPBuffer
        );

        const uidInfo =
        getUidInfo(pData);

        if(uidInfo){

            const oldUid =
            uidInfo.uid;

            const newUid =
            uidMap[oldUid];

            if(
                newUid &&
                newUid !== oldUid
            ){

                const newVarint =
                encodeVarint(newUid);

                pData =
                replaceBytes(

                    pData,

                    uidInfo.raw,

                    newVarint
                );

                addLog(
                    `UID ${oldUid} → ${newUid}`
                );
            }
        }

        const newPSize =
        pData.length;

        const newPMd5 =
        md5Bytes(
            pData.buffer
        );

        // ===============================================
        // META
        // ===============================================

        const metaBuffer =
        await parsedZip
        .file(s.meta)
        .async("arraybuffer");

        let metaData =
        new Uint8Array(
            metaBuffer
        );

        // USERLEVEL MD5
        metaData =
        replaceBytes(

            metaData,

            oldUlMd5,

            newUlMd5
        );

        // UID + SIZE + MD5
        if(uidInfo){

            const oldUid =
            uidInfo.uid;

            const newUid =
            uidMap[oldUid];

            if(
                newUid &&
                newUid !== oldUid
            ){

                metaData =
                replaceBytes(

                    metaData,

                    encodeVarint(oldUid),

                    encodeVarint(newUid)
                );

                metaData =
                replaceBytes(

                    metaData,

                    encodeVarint(oldPSize),

                    encodeVarint(newPSize)
                );

                metaData =
                replaceBytes(

                    metaData,

                    oldPMd5,

                    newPMd5
                );

                addLog(
                    "META UPDATED"
                );
            }
        }

        outZip.file(
            s.ul,
            ulData
        );

        outZip.file(
            s.pbytes,
            pData
        );

        outZip.file(
            s.meta,
            metaData
        );
    }

    addLog("BUILD ZIP");

    const finalZip =
    await outZip.generateAsync({

        type:"blob"
    });

    const timestamp =
    Date.now();

    const a =
    document.createElement("a");

    a.href =
    URL.createObjectURL(
        finalZip
    );

    a.download =
    `patched_${timestamp}.zip`;

    a.click();

    addLog("DONE");
};