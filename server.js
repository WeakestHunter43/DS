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

function addLog(
    text="",
    cls="info"
){

    console.log(text);

    log.innerHTML +=
    `<div class="${cls}">${text}</div>`;

    log.scrollTop =
    log.scrollHeight;
}

function line(){

    addLog(
        "--------------------------------",
        "line"
    );
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
// PATCH RULES
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
// HEX STRING
// ======================================================

function bytesToHex(bytes){

    return Array
    .from(bytes)
    .map(x=>

        x
        .toString(16)
        .padStart(2,"0")

    )
    .join(" ");
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
// FIND FIELD
// ======================================================

function findField(
    data,
    targetField
){

    let pos = 0;

    while(pos < data.length){

        const [tag,p1] =
        readVarint(data,pos);

        pos = p1;

        const field =
        Number(tag >> 3n);

        const wire =
        Number(tag & 7n);

        // VARINT
        if(wire === 0){

            const valueStart = pos;

            const [
                value,
                p2,
                raw
            ] =
            readVarint(data,pos);

            pos = p2;

            if(field === targetField){

                return {

                    field,
                    wire,
                    value,
                    start:valueStart,
                    end:p2,
                    raw
                };
            }
        }

        // LENGTH
        else if(wire === 2){

            const [len,p2] =
            readVarint(data,pos);

            const dataStart = p2;

            const dataEnd =
            p2 + Number(len);

            const bytes =
            data.slice(
                dataStart,
                dataEnd
            );

            if(field === targetField){

                return {

                    field,
                    wire,
                    start:dataStart,
                    end:dataEnd,
                    raw:bytes,
                    len:Number(len)
                };
            }

            pos = dataEnd;
        }

        // 64BIT
        else if(wire === 1){

            pos += 8;
        }

        // 32BIT
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
// REPLACE RANGE
// ======================================================

function replaceRange(
    data,
    start,
    end,
    newBytes
){

    return new Uint8Array([

        ...data.slice(0,start),

        ...newBytes,

        ...data.slice(end)
    ]);
}

// ======================================================
// UID INFO
// ======================================================

function getUidInfo(data){

    return findField(data,7);
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

        if(found === -1){

            addLog(
                `× ${p.name}`,
                "fail"
            );

            return;
        }

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
                `✓ ${p.name} @${found}`,
                "patch"
            );

            return;
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

    addLog(
        `FILE: ${file.name}`,
        "title"
    );

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

    try{

        parsedZip =
        await JSZip.loadAsync(
            await file.arrayBuffer()
        );

    }catch(e){

        addLog(
            "INVALID ZIP",
            "fail"
        );

        return;
    }

    const slots = {};

    Object.keys(parsedZip.files)
    .forEach(name=>{

        const clean =
        name.split("/").pop();

        let m =
        clean.match(
            /^ProjectData_slot_(\d+)\.bytes$/i
        );

        if(m){

            if(!slots[m[1]])
                slots[m[1]] = {};

            slots[m[1]].pbytes = name;
        }

        m =
        clean.match(
            /^ProjectData_slot_(\d+)\.meta$/i
        );

        if(m){

            if(!slots[m[1]])
                slots[m[1]] = {};

            slots[m[1]].meta = name;
        }

        m =
        clean.match(
            /^UserLevelData_(\d+)\.bytes$/i
        );

        if(m){

            if(!slots[m[1]])
                slots[m[1]] = {};

            slots[m[1]].ul = name;
        }
    });

    addLog(
        `SLOTS: ${Object.keys(slots).length}`,
        "info"
    );

    line();

    for(const slot in slots){

        const s = slots[slot];

        const missing = [];

        if(!s.ul)
            missing.push(
                `UserLevelData_${slot}.bytes`
            );

        if(!s.meta)
            missing.push(
                `ProjectData_slot_${slot}.meta`
            );

        if(!s.pbytes)
            missing.push(
                `ProjectData_slot_${slot}.bytes`
            );

        if(missing.length){

            addLog(
                `SKIP SLOT ${slot}`,
                "fail"
            );

            missing.forEach(f=>{

                addLog(
                    `Missing: ${f}`,
                    "fail"
                );
            });

            line();

            continue;
        }

        const buffer =
        await parsedZip
        .file(s.pbytes)
        .async("arraybuffer");

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
        info.value.toString();

        if(!uidGroups[uid])
            uidGroups[uid] = [];

        uidGroups[uid]
        .push(slot);

        validSlots[slot] = s;

        addLog(
            `SLOT:${slot}, UID=${uid}`,
            "slot"
        );
    }

    if(
        Object.keys(validSlots).length
        === 0
    ){

        line();

        addLog(
            "NO VALID SLOT FOUND",
            "fail"
        );

        return;
    }

    line();

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

    addLog(
        "ZIP READY",
        "success"
    );
});

// ======================================================
// MAIN PATCH
// ======================================================

patchBtn.onclick =
async ()=>{

    log.innerHTML = "";

    const outZip =
    new JSZip();

    const finalUidGroups = {};

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

        let patchSuccess = 0;

        let patchFail = 0;

        line();

        addLog(
            `SLOT:${slot}`,
            "title"
        );

        line();

        // ==================================================
        // USERLEVEL
        // ==================================================

        const oldUlBuffer =
        await parsedZip
        .file(s.ul)
        .async("arraybuffer");

        let ulData =
        new Uint8Array(
            oldUlBuffer
        );

        const finalUlMd5 =
        md5Bytes(
            ulData.buffer
        );

        // ==================================================
        // PROJECTDATA
        // ==================================================

        const oldPBuffer =
        await parsedZip
        .file(s.pbytes)
        .async("arraybuffer");

        let pData =
        new Uint8Array(
            oldPBuffer
        );

        const finalPSize =
        pData.length;

        const finalPMd5 =
        md5Bytes(
            pData.buffer
        );

        const uidInfo =
        getUidInfo(pData);

        let oldUid = "";

        let newUid = "";

        if(uidInfo){

            oldUid =
            uidInfo.value.toString();

            newUid =
            uidMap[oldUid] || oldUid;

            addLog(
                `UID`,
                "info"
            );

            addLog(
                oldUid,
                "info"
            );

            addLog(
                `UID Status`,
                "info"
            );

            if(newUid !== oldUid){

                addLog(
                    `Updated`,
                    "warn"
                );

                addLog(
                    `${oldUid}`,
                    "warn"
                );

                addLog(
                    `→`,
                    "warn"
                );

                addLog(
                    `${newUid}`,
                    "warn"
                );

                pData =
                replaceRange(

                    pData,

                    uidInfo.start,

                    uidInfo.end,

                    encodeVarint(newUid)
                );
            }

            else{

                addLog(
                    `Unchanged`,
                    "success"
                );
            }
        }

        line();

        // ==================================================
        // META
        // ==================================================

        const metaBuffer =
        await parsedZip
        .file(s.meta)
        .async("arraybuffer");

        let metaData =
        new Uint8Array(
            metaBuffer
        );

        const ulMd5Field =
        findField(
            metaData,
            19
        );

        let cancelSlot = false;

        let metaUlMd5 = "";

        if(
            ulMd5Field &&
            ulMd5Field.wire === 2
        ){

            metaUlMd5 =
            bytesToHex(
                ulMd5Field.raw
            );

            const realUlMd5 =
            bytesToHex(
                finalUlMd5
            );

            addLog(
                `UserLevel MD5`,
                "title"
            );

            line();

            addLog(
                `Meta UserLevel MD5`,
                "info"
            );

            addLog(
                metaUlMd5,
                "info"
            );

            addLog(
                `File UserLevel MD5`,
                "info"
            );

            addLog(
                realUlMd5,
                "info"
            );

            addLog(
                `Status`,
                "info"
            );

            if(
                metaUlMd5 === realUlMd5
            ){

                addLog(
                    `✓`,
                    "success"
                );
            }

            else{

                addLog(
                    `×`,
                    "fail"
                );

                addLog(
                    `SLOT CANCELLED`,
                    "fail"
                );

                cancelSlot = true;
            }
        }

        if(cancelSlot){

            line();

            continue;
        }

        line();

        // ==================================================
        // SIZE
        // ==================================================

        const sizeField =
        findField(
            metaData,
            15
        );

        let metaSize = 0;

        addLog(
            `ProjectData Size`,
            "title"
        );

        line();

        if(sizeField){

            metaSize =
            Number(sizeField.value);

            addLog(
                `Meta Size`,
                "info"
            );

            addLog(
                `${metaSize}`,
                "info"
            );

            addLog(
                `File Size`,
                "info"
            );

            addLog(
                `${finalPSize}`,
                "info"
            );

            addLog(
                `Status`,
                "info"
            );

            if(metaSize === finalPSize){

                addLog(
                    `✓`,
                    "success"
                );
            }

            else{

                addLog(
                    `×`,
                    "warn"
                );
            }
        }

        line();

        // ==================================================
        // PROJECTDATA MD5
        // ==================================================

        const pMd5Field =
        findField(
            metaData,
            20
        );

        let oldMetaPMd5 = "";

        addLog(
            `ProjectData MD5`,
            "title"
        );

        line();

        if(
            pMd5Field &&
            pMd5Field.wire === 2
        ){

            oldMetaPMd5 =
            bytesToHex(
                pMd5Field.raw
            );

            const realMd5Hex =
            bytesToHex(
                finalPMd5
            );

            addLog(
                `Meta ProjectData MD5`,
                "info"
            );

            addLog(
                oldMetaPMd5,
                "info"
            );

            addLog(
                `File ProjectData MD5`,
                "info"
            );

            addLog(
                realMd5Hex,
                "info"
            );

            addLog(
                `Status`,
                "info"
            );

            if(
                oldMetaPMd5 === realMd5Hex
            ){

                addLog(
                    `✓`,
                    "success"
                );
            }

            else{

                addLog(
                    `×`,
                    "warn"
                );
            }
        }

        line();

        // ==================================================
        // PATCHING
        // ==================================================

        addLog(
            `PATCHING`,
            "title"
        );

        line();

        markerPatches.forEach(p=>{

            const before =
            ulData.slice();

            patchByMarker(
                ulData,
                p
            );

            let changed = false;

            for(
                let i=0;
                i<ulData.length;
                i++
            ){

                if(before[i] !== ulData[i]){

                    changed = true;
                    break;
                }
            }

            if(changed)
                patchSuccess++;
            else
                patchFail++;
        });

        addLog(
            `Patched: ${patchSuccess}`,
            "success"
        );

        addLog(
            `Failed: ${patchFail}`,
            "fail"
        );

        line();

        // ==================================================
        // NEW VALUES
        // ==================================================

        const newUlMd5 =
        md5Bytes(
            ulData.buffer
        );

        const newPSize =
        pData.length;

        const newPMd5 =
        md5Bytes(
            pData.buffer
        );

        // ==================================================
        // UPDATE META
        // ==================================================

        addLog(
            `Metadata Update`,
            "update"
        );

        line();

        addLog(
            `UserLevel MD5`,
            "update"
        );

        addLog(
            metaUlMd5,
            "update"
        );

        addLog(
            `→`,
            "update"
        );

        addLog(
            bytesToHex(newUlMd5),
            "update"
        );

        addLog(
            `ProjectData MD5`,
            "update"
        );

        addLog(
            oldMetaPMd5,
            "update"
        );

        addLog(
            `→`,
            "update"
        );

        addLog(
            bytesToHex(newPMd5),
            "update"
        );

        addLog(
            `Size`,
            "update"
        );

        addLog(
            `${metaSize}`,
            "update"
        );

        addLog(
            `→`,
            "update"
        );

        addLog(
            `${newPSize}`,
            "update"
        );

        // ==================================================
        // APPLY META
        // ==================================================

        if(sizeField){

            metaData =
            replaceRange(

                metaData,

                sizeField.start,

                sizeField.end,

                encodeVarint(newPSize)
            );
        }

        if(
            pMd5Field &&
            pMd5Field.wire === 2
        ){

            metaData =
            replaceRange(

                metaData,

                pMd5Field.start,

                pMd5Field.end,

                newPMd5
            );
        }

        if(
            ulMd5Field &&
            ulMd5Field.wire === 2
        ){

            metaData =
            replaceRange(

                metaData,

                ulMd5Field.start,

                ulMd5Field.end,

                newUlMd5
            );
        }

        // ==================================================
        // META UID
        // ==================================================

        const metaUidField =
        findField(
            metaData,
            49
        );

        if(
            metaUidField &&
            newUid !== oldUid
        ){

            line();

            addLog(
                `Meta UID Update`,
                "update"
            );

            line();

            addLog(
                oldUid,
                "update"
            );

            addLog(
                `→`,
                "update"
            );

            addLog(
                newUid,
                "update"
            );

            metaData =
            replaceRange(

                metaData,

                metaUidField.start,

                metaUidField.end,

                encodeVarint(newUid)
            );
        }

        // ==================================================
        // STORE UID GROUP
        // ==================================================

        const finalUid =
        newUid || oldUid;

        if(!finalUidGroups[finalUid]){

            finalUidGroups[finalUid] = [];
        }

        finalUidGroups[finalUid]
        .push({

            ulData,
            pData,
            metaData,
            files:s
        });

        line();

        addLog(
            `SLOT ${slot} SAVED`,
            "success"
        );
    }

    // ==================================================
    // BUILD ZIP
    // ==================================================

    const uidKeys =
    Object.keys(finalUidGroups);

    const singleUid =
    uidKeys.length === 1;

    uidKeys.forEach(uid=>{

        finalUidGroups[uid]
        .forEach(entry=>{

            const base =

            singleUid
            ? ""
            : `${uid}/`;

            outZip.file(
                base +
                entry.files.ul
                .split("/")
                .pop(),
                entry.ulData
            );

            outZip.file(
                base +
                entry.files.pbytes
                .split("/")
                .pop(),
                entry.pData
            );

            outZip.file(
                base +
                entry.files.meta
                .split("/")
                .pop(),
                entry.metaData
            );
        });
    });

    line();

    addLog(
        `BUILD ZIP`,
        "title"
    );

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

    line();

    addLog(
        `DONE`,
        "success"
    );

    addLog(
        `OUTPUT: patched_${timestamp}.zip`,
        "success"
    );
};