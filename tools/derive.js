function parsePE(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    if (dv.getUint16(0, true) !== 0x5A4D) throw new Error("not an MZ image");
    const lfanew = dv.getUint32(0x3C, true);
    if (dv.getUint32(lfanew, true) !== 0x00004550) throw new Error("no PE signature");
    const numSec = dv.getUint16(lfanew + 6, true);
    const optSize = dv.getUint16(lfanew + 20, true);
    const opt = lfanew + 24;
    if (dv.getUint16(opt, true) !== 0x10B) throw new Error("32-bit PE image required");
    const timestamp = dv.getUint32(lfanew + 8, true);
    const imageBase = dv.getUint32(opt + 28, true);
    const sizeOfImage = dv.getUint32(opt + 56, true);
    const secs = [];
    for (let i = 0; i < numSec; i++) {
        const s = opt + optSize + i * 40;
        let name = "";
        for (let k = 0; k < 8 && u8[s + k]; k++) name += String.fromCharCode(u8[s + k]);
        const chars = dv.getUint32(s + 36, true);
        secs.push({ name, va: imageBase + dv.getUint32(s + 12, true),
                    vsize: dv.getUint32(s + 8, true), raw: dv.getUint32(s + 20, true),
                    rawsize: dv.getUint32(s + 16, true),
                    exec: (chars & 0x20000000) !== 0, writable: (chars & 0x80000000) !== 0 });
    }
    return { u8, dv, imageBase, sizeOfImage, timestamp, secs };
}

function va2off(p, va) {
    for (const s of p.secs) {
        const span = Math.max(s.vsize, s.rawsize);
        if (va >= s.va && va < s.va + span) return s.raw + (va - s.va);
    }
    return -1;
}

function readString(p, va) {
    const o = va2off(p, va);
    if (o < 0) return null;
    let s = "";
    for (let i = 0; i < 256 && o + i < p.u8.length; i++) {
        const c = p.u8[o + i];
        if (c === 0) break;
        if (c < 0x20 || c > 0x7E) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 4 ? s : null;
}

function rot13(s) {
    return s.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
    });
}

function functionStarts(p, funcs) {
    const out = [];
    for (const f of funcs) {
        const o = va2off(p, f);
        if (o >= 0 && o + 3 <= p.u8.length &&
            p.u8[o] === 0x55 && p.u8[o + 1] === 0x8B && p.u8[o + 2] === 0xEC) out.push(f);
    }
    return out.sort((a, b) => a - b);
}

function containingFunction(starts, va) {
    let lo = 0, hi = starts.length - 1, best = null;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (starts[mid] <= va) { best = starts[mid]; lo = mid + 1; } else hi = mid - 1;
    }
    return best;
}

function findCoreTables(p, dataRefs, starts) {
    const found = [];
    const seen = new Set();

    const addRun = (va) => {
        if (seen.has(va)) return;
        const records = [];
        let cur = va;
        for (;;) {
            const o = va2off(p, cur);
            if (o < 0 || o + 12 > p.u8.length) break;
            const name = p.dv.getUint32(o, true);
            const data = p.dv.getUint32(o + 4, true);
            const size = p.dv.getUint32(o + 8, true);
            const end = p.imageBase + p.sizeOfImage;
            if (!size || size > 0x400000 || name < p.imageBase || name >= end ||
                data < p.imageBase || data + size > end) break;
            const no = va2off(p, name);
            if (no < 0) break;
            let k = 0;
            while (k < 128 && no + k < p.u8.length && p.u8[no + k] >= 0x20 && p.u8[no + k] <= 0x7E) k++;
            if (!k || k === 128) break;
            records.push({ va: cur, name, data, size });
            cur += 12;
        }
        if (records.length < 3) return;
        seen.add(va);
        found.push({ va, records });
    };
    const end = p.imageBase + p.sizeOfImage;
    const record = (va) => {
        const o = va2off(p, va);
        if (o < 0 || o + 12 > p.u8.length) return null;
        const name = p.dv.getUint32(o, true);
        const data = p.dv.getUint32(o + 4, true);
        const size = p.dv.getUint32(o + 8, true);
        if (!size || size > 0x400000) return null;
        if (data < p.imageBase || data + size > end) return null;
        if (name < p.imageBase || name >= end) return null;
        const s = readString(p, name);
        return s ? { va, raw: s, name: rot13(s), data, size } : null;
    };
    for (const s of p.secs) {
        if (s.exec) continue;
        const span = Math.max(s.vsize, s.rawsize);
        let va = s.va;
        while (va + 36 <= s.va + span) {
            if (!record(va) || !record(va + 12) || !record(va + 24) || !record(va + 36)) { va += 4; continue; }
            const records = [];
            let cur = va;
            for (;;) {
                const r = record(cur);
                if (!r || records.length >= 4096) break;
                records.push(r);
                cur += 12;
            }
            if (records.length >= 3) addRun(va, records);
            va = cur;
        }
    }
    for (const target of dataRefs.keys()) {
        addRun(target);
        addRun(target - 4);
        addRun(target - 8);
    }

    for (const t of found) {
        t.refs = [];
        const end = t.va + t.records.length * 12;
        for (let a = t.va; a < end; a += 4) {
            const sites = dataRefs.get(a);
            if (!sites) continue;
            for (const site of sites) t.refs.push(site);
        }
        t.refs = Array.from(new Set(t.refs)).sort((a, b) => a - b);
        const owners = new Set();
        for (const site of t.refs) {
            const fn = containingFunction(starts, site);
            if (fn !== null) owners.add(fn);
        }
        t.owners = Array.from(owners).sort((a, b) => a - b);
    }

    found.sort((a, b) => a.va - b.va);
    return found;
}

function findStrings(p) {
    const out = [];
    for (const s of p.secs) {
        if (s.exec) continue;
        const end = Math.min(s.raw + s.rawsize, p.u8.length);
        let o = s.raw;
        while (o < end) {
            if (p.u8[o] >= 0x20 && p.u8[o] < 0x7F) {
                let j = o;
                while (j < end && p.u8[j] >= 0x20 && p.u8[j] < 0x7F) j++;
                const len = j - o;
                if (len >= 6 && j < end && p.u8[j] === 0) {
                    let t = "";
                    for (let k = o; k < j; k++) t += String.fromCharCode(p.u8[k]);
                    out.push({ va: s.va + (o - s.raw), text: t });
                }
                o = j;
            } else o++;
        }
    }
    return out;
}

function findMagic(p) {
    const needle = [0x52, 0x53, 0x42, 0x31];
    const hits = [];
    for (const sec of p.secs) {
        if (sec.exec) continue;
        const end = Math.min(sec.raw + sec.rawsize, p.u8.length);
        for (let o = sec.raw; o + 4 <= end; o++) {
            if (p.u8[o] === needle[0] && p.u8[o + 1] === needle[1] &&
                p.u8[o + 2] === needle[2] && p.u8[o + 3] === needle[3])
                hits.push(sec.va + (o - sec.raw));
        }
    }
    return hits;
}

function traceArgument(r, fn, target) {
    return traceFromList(r.range(fn, 0x180), target);
}

const SCRAMBLE_CONSTANTS = [
    ["encoderA", 0x29451AFB, "encoder"],
    ["encoderB", 0x72394BC8, "encoder"],
    ["encoderC", 0x46582A8B, "encoder"],
    ["decoderA", 0x001C6B438, "decoder"],
    ["decoderB", 0x001451AFB, "decoder"],
    ["decoderC", 0x001A7D575, "decoder"]
];

function findScramble(p) {
    const want = new Map(SCRAMBLE_CONSTANTS.map(([name, v, kind]) => [v >>> 0, { name, kind }]));
    const first = new Map();
    for (const [v, meta] of want) {
        const b = v & 0xFF;
        if (!first.has(b)) first.set(b, []);
        first.get(b).push([v, meta]);
    }

    const hits = {};
    for (const s of p.secs) {
        if (!s.exec) continue;
        const end = Math.min(s.raw + s.rawsize, p.u8.length);
        for (let o = s.raw; o + 4 <= end; o++) {
            if (!first.has(p.u8[o])) continue;
            const v = (p.u8[o] | (p.u8[o + 1] << 8) | (p.u8[o + 2] << 16) | (p.u8[o + 3] << 24)) >>> 0;
            const meta = want.get(v);
            if (!meta) continue;
            if (!hits[meta.name]) hits[meta.name] = [];
            if (hits[meta.name].length < 16) hits[meta.name].push(s.va + (o - s.raw));
        }
    }
    return hits;
}

function findNumKey(r, roots, depth = 4) {
    const seen = new Set();
    let queue = roots.filter((v) => v !== undefined);
    for (let level = 0; level <= depth && queue.length; ++level) {
        const next = [];
        for (const fn of queue) {
            if (seen.has(fn)) continue;
            seen.add(fn);
            for (const [at, i] of r.range(fn, 0x1200)) {
                if (i.mnemonic === "xorpd") {
                    const m = /xmm\d+,\s*(?:xmmword ptr\s*)?\[?\s*(0x[0-9a-f]+)/i.exec(i.op);
                    if (m) {
                        const va = parseInt(m[1], 16);
                        const sec = r.p.secs.find((s) => !s.exec &&
                            va >= s.va && va < s.va + Math.max(s.vsize, s.rawsize));
                        if (sec) return { va, at };
                    }
                }
                if (i.mnemonic === "call") {
                    const t = parseInt(i.op.trim().replace("0x", ""), 16);
                    if (!isNaN(t) && t >= r.p.imageBase) next.push(t);
                }
            }
        }
        queue = next;
    }
    return null;
}

const SLICE_DISP = "(0x[0-9a-f]+|[0-9]+)";

function sliceNumber(text) {
    return text.indexOf("0x") === 0 ? parseInt(text.slice(2), 16) : parseInt(text, 10);
}

function traceRegister(list, callIdx, startReg, trace) {
    const volatileReg = { eax: 1, ecx: 1, edx: 1 };
    const writes = { mov: 1, lea: 1, add: 1, sub: 1, xor: 1, and: 1, or: 1, inc: 1, dec: 1, shl: 1, pop: 1 };
    const reLeaImm = new RegExp("^\\[(\\w+) \\+ " + SLICE_DISP + "\\]$");
    const reLeaReg = /^\[(\w+)\]$/;
    const reArg = new RegExp("^dword ptr \\[ebp \\+ " + SLICE_DISP + "\\]$");
    const reSlot = new RegExp("^dword ptr \\[ebp - " + SLICE_DISP + "\\]$");
    const reStore = new RegExp("^dword ptr \\[ebp - " + SLICE_DISP + "\\]$");

    let cur = startReg, add = 0, param = null;
    const step = (at, text) => trace.push("0x" + at.toString(16) + " " + text);

    for (let k = callIdx - 1; k >= 0 && callIdx - k <= 40; k--) {
        const [at, i] = list[k];
        if (i.mnemonic === "call" && volatileReg[cur])
            return { offset: null, param: null, failed: "0x" + at.toString(16) + " call clobbers " + cur };

        const parts = i.op.split(",");
        const dest = (parts[0] || "").trim();
        if (!writes[i.mnemonic] || dest !== cur) continue;
        const src = (parts[1] || "").trim();

        if (i.mnemonic === "lea") {
            const m = reLeaImm.exec(src);
            if (m) { step(at, "lea " + i.op); add += sliceNumber(m[2]); cur = m[1]; continue; }
            const r2 = reLeaReg.exec(src);
            if (r2) { step(at, "lea " + i.op); cur = r2[1]; continue; }
            return { offset: null, param: null, failed: "unhandled lea: " + i.op };
        }
        if (i.mnemonic === "mov") {
            const reg = /^(\w+)$/.exec(src);
            if (reg) { step(at, "mov " + i.op); cur = reg[1]; continue; }
            const a = reArg.exec(src);
            if (a) { step(at, "mov " + i.op); param = sliceNumber(a[1]); break; }
            const sl = reSlot.exec(src);
            if (sl) {
                const slot = sliceNumber(sl[1]);
                let found = null;
                for (let j = k - 1; j >= 0 && k - j < 80; j--) {
                    const prev = list[j][1];
                    if (prev.mnemonic !== "mov") continue;
                    const pd = (prev.op.split(",")[0] || "").trim();
                    const sm = reStore.exec(pd);
                    if (!sm || sliceNumber(sm[1]) !== slot) continue;
                    found = (prev.op.split(",")[1] || "").trim();
                    break;
                }
                if (found && /^\w+$/.test(found)) { step(at, "mov " + i.op + "  (spilled from " + found + ")"); cur = found; continue; }
                return { offset: null, param: null, failed: "unhandled spill: " + i.op };
            }
            return { offset: null, param: null, failed: "unhandled mov: " + i.op };
        }
        if (i.mnemonic === "add" || i.mnemonic === "sub") {
            if (/^0x[0-9a-f]+$/i.test(src) || /^[0-9]+$/.test(src)) {
                step(at, i.mnemonic + " " + i.op);
                add += (i.mnemonic === "add" ? 1 : -1) * sliceNumber(src);
                continue;
            }
            return { offset: null, param: null, failed: "unhandled " + i.mnemonic + ": " + i.op };
        }
        return { offset: null, param: null, failed: "stopped at " + i.mnemonic + " " + i.op };
    }

    if (param === null) return { offset: null, param: null, failed: "base never reached a stack argument" };
    trace.push("base = [ebp+0x" + param.toString(16).toUpperCase() + "], addend = 0x" + add.toString(16).toUpperCase());
    if (param !== 0xC) return { offset: null, param: param, failed: "base is not the 2nd parameter (ebp+0xC)" };
    return { offset: add, param: param };
}

function traceFromList(list, target) {
    const trace = [];
    let callIdx = -1;
    for (let k = 0; k < list.length; k++) {
        const i = list[k][1];
        if (i.mnemonic !== "call") continue;
        if (parseInt(i.op.trim().replace("0x", ""), 16) === target) { callIdx = k; break; }
    }
    if (callIdx < 0) { trace.push("no call to 0x" + target.toString(16)); return { offset: null, param: null, trace }; }

    const reArgOperand = new RegExp("^(?:dword ptr )?\\[ebp \\+ " + SLICE_DISP + "\\]$");
    const pushes = [];
    for (let k = callIdx - 1; k >= 0 && callIdx - k <= 24; k--) {
        const i = list[k][1];
        if (i.mnemonic === "push") pushes.push({ at: list[k][0], op: i.op.trim() });
    }

    const attempts = [];
    if (pushes.length >= 2) {
        const second = pushes[1];
        const bare = /^(\w+)$/.exec(second.op);
        if (bare) attempts.push({ label: "stack (" + second.op + ")", reg: bare[1], at: second.at });
        else {
            const direct = reArgOperand.exec(second.op);
            if (direct && sliceNumber(direct[1]) === 0xC)
                return { offset: 0, param: 0xC, trace: ["0x" + second.at.toString(16) + " push " + second.op + "   (2nd argument, direct)"] };
        }
    }
    attempts.push({ label: "fastcall (edx)", reg: "edx", at: null });

    const failures = [];
    for (const a of attempts) {
        const local = [];
        if (a.at !== null) local.push("0x" + a.at.toString(16) + " push " + a.reg + "   (2nd argument, stack-passed)");
        const r = traceRegister(list, callIdx, a.reg, local);
        if (r.offset !== null) return { offset: r.offset, param: r.param, trace: local, via: a.label };
        failures.push(a.label + ": " + r.failed);
    }
    return { offset: null, param: null, trace: failures };
}

function p_section(p, va) {
    for (const s of p.secs) {
        const span = Math.max(s.vsize, s.rawsize);
        if (va >= s.va && va < s.va + span) return s;
    }
    return null;
}

function refsInData(p, va) {
    const out = [];
    const n = [va & 0xff, (va >>> 8) & 0xff, (va >>> 16) & 0xff, (va >>> 24) & 0xff];
    for (const sec of p.secs) {
        if (sec.exec) continue;
        const end = Math.min(sec.raw + sec.rawsize, p.u8.length);
        for (let o = sec.raw; o + 4 <= end; o += 4) {
            if (p.u8[o] === n[0] && p.u8[o+1] === n[1] && p.u8[o+2] === n[2] && p.u8[o+3] === n[3])
                out.push(sec.va + (o - sec.raw));
        }
    }
    return out;
}

function derive(r) {
    const out = { client: {}, server: {}, notes: [] };
    const hex = (v) => "0x" + v.toString(16).toUpperCase().padStart(8, "0");
    const u8 = r.p.u8;

    const starts = r.starts;
    const startOf = (va) => containingFunction(starts, va);

    const scrambleHits = findScramble(r.p);
    const hasEncoder = SCRAMBLE_CONSTANTS.some(([n, , k]) => k === "encoder" && scrambleHits[n]);
    const hasDecoder = SCRAMBLE_CONSTANTS.some(([n, , k]) => k === "decoder" && scrambleHits[n]);
    const beforeCallScramble = !hasEncoder && !hasDecoder;
    out.scramble = { hits: scrambleHits, hasEncoder, hasDecoder, beforeCallScramble };
    {
        const tally = (kind) => SCRAMBLE_CONSTANTS.filter(([n, , k]) => k === kind)
            .map(([n]) => n + " x" + (scrambleHits[n] || []).length).join(" ");
        out.notes.push("call scramble: encoder " + (hasEncoder ? "present (" + tally("encoder") + ")" : "absent") +
                       "; decoder " + (hasDecoder ? "present (" + tally("decoder") + ")" : "absent"));
        out.notes.push(beforeCallScramble
            ? "variant: secure opcode mapping only -> #define BEFORE_CALL_SCRAMBLE"
            : "variant: CALL operand scramble present -> leave BEFORE_CALL_SCRAMBLE undefined");
    }

    const callees = (fn, size) => {
        const m = new Map();
        for (const [at, i] of r.range(fn, size)) {
            if (i.mnemonic !== "call") continue;
            const t = parseInt(i.op.trim().replace("0x", ""), 16);
            if (!isNaN(t) && t >= r.p.imageBase) m.set(t, (m.get(t) || 0) + 1);
        }
        return m;
    };

    const assignShape = (fn) => {
        let stored = false, capacity = false, argPtr = false, thisPtr = false, argSize = false;
        for (const [, i] of r.range(fn, 0x80)) {
            if (i.mnemonic !== "mov") continue;
            if (i.op === "ebx, dword ptr [ebp + 8]") argPtr = true;
            if (i.op === "esi, ecx") thisPtr = true;
        }
        if (!argPtr || !thisPtr) return false;
        for (const [, i] of r.range(fn, 0x200)) {
            if (i.mnemonic !== "mov" || i.op.indexOf("dword ptr [") < 0) continue;
            if (i.op === "edi, dword ptr [ebp + 0xc]") argSize = true;
            if (/dword ptr \[[^\]]*\+ 0x10\],/.test(i.op)) stored = true;
            if (/\+ 0x14\]/.test(i.op)) capacity = true;
        }
        return stored && capacity && argSize;
    };

    const pickAssign = (fn, size) => {
        const list = r.range(fn, size);
        const calls = new Map();
        for (const [at, i] of list) {
            if (i.mnemonic !== "call") continue;
            const t = parseInt(i.op.trim().replace("0x", ""), 16);
            if (isNaN(t)) continue;
            if (!calls.has(t)) calls.set(t, []);
            calls.get(t).push(at);
        }
        const scored = [];
        for (const [c, sites] of calls) {
            if (!assignShape(c)) continue;
            scored.push([c, sites.length]);
        }
        if (!scored.length) return [undefined, []];
        scored.sort((a, b) => (b[1] - a[1]) || (a[0] - b[0]));
        return [scored[0][0], scored.map((c) => hex(c[0]) + " (x" + c[1] + ")")];
    };

    if (r.tables && r.tables.length) {
        out.client.gCoreScripts = r.tables[0].va;
        out.client.tables = [];
        for (const t of r.tables) {
            out.client.tables.push({ va: t.va, count: t.records.length,
                                     owners: t.owners, refs: t.refs.length });
            out.notes.push("core table " + hex(t.va) + " (" + t.records.length + " records)" +
                           "  consumed by " + (t.owners.length ? t.owners.map(hex).join(", ") : "nothing") +
                           "  via " + t.refs.length + " operand(s)");
        }
        if (r.tables.length > 1)
            out.notes.push("multiple tables: allowlist must cover all of them");
    }

    const magic = findMagic(r.p);
    out.notes.push("RSB1 constants: " + (magic.length ? magic.map(hex).join(", ") : "none"));

    for (const m of magic) {
        const sites = Array.from(r.dataRefs.get(m) || []).sort((a, b) => a - b);
        if (sites.length !== 1) continue;
        const owner = startOf(sites[0] + 1);
        if (owner === null) continue;
        const callers = Array.from(new Set(Array.from(r.codeRefs.get(owner) || []).map((x) => startOf(x + 1)).filter((x) => x !== null)));

        const hotCaller = callers.length === 1 && (r.codeRefs.get(callers[0]) || new Set()).size >= 5;
        if (hotCaller && out.client.deserializer === undefined && out.client.gCoreScripts !== undefined) {
            out.client.deserializer = owner;
            if (callers.length === 1) out.client.LuaVM__load = callers[0];
            const [assign, cands] = pickAssign(owner, 0x400);
            if (assign !== undefined) out.client.stringAssign = assign;
            out.client.stringAssignAlternatives = cands;
            out.notes.push("client: serialized by " + hex(owner) + ", loaded by " + hex(callers[0]));
            out.notes.push("client: assign candidates " + cands.join(", "));
        }
        if (!hotCaller && out.server.writer === undefined) {
            out.server.writer = owner;
            out.server.LuaSerializer__write = owner;
            const [assign, cands] = pickAssign(owner, 0x400);
            if (assign !== undefined) out.server.stringAssign = assign;
            out.server.stringAssignAlternatives = cands;
            out.notes.push("server: serializer " + hex(owner));
            out.notes.push("server: assign candidates " + cands.join(", "));

            const numKey = findNumKey(r, [owner]);
            if (numKey) {
                out.server.numKey = numKey.va;
                out.server.numKeySite = numKey.at;
                out.notes.push("number key: global @ " + hex(numKey.va) +
                               " (xorpd at " + hex(numKey.at) + ")");
            }
        }
    }

    if (out.client.LuaVM__load !== undefined && out.client.deserializer !== undefined) {
        const traced = traceArgument(r, out.client.LuaVM__load, out.client.deserializer);
        out.client.bytecodeOffsetTrace = traced.trace;

        if (traced.offset !== null) out.client.bytecodeOffset = traced.offset;
        else {
            const list = r.range(out.client.LuaVM__load, 0x80);
            let callAt = -1;
            for (const [at, i] of list) {
                if (i.mnemonic === "call" && parseInt(i.op.trim().replace("0x", ""), 16) === out.client.deserializer)
                    { callAt = at; break; }
            }
            for (const [at, i] of list) {
                if (callAt >= 0 && at >= callAt) break;
                const m = /^edx, (?:dword ptr )?\[\w+ \+ (0x[0-9a-f]+)\]$/.exec(i.op);
                if (i.mnemonic === "lea" && m) out.client.bytecodeOffset = parseInt(m[1], 16);
            }
            if (out.client.bytecodeOffset !== undefined)
                out.notes.push("client: offset fell back to a plain lea scan (slice unresolved)");
        }

        const off = out.client.bytecodeOffset;
        if (off !== undefined) {
            const sane = off > 0 && off < 0x40 && (off % 4) === 0;
            out.notes.push("client: bytecode offset = 0x" + off.toString(16).toUpperCase() +
                           (sane ? " (small, 4-aligned)" : "  ** implausible value **"));
            for (const t of traced.trace) out.notes.push("    slice: " + t);
        } else {
            out.notes.push("client: bytecode offset NOT derived - refusing to guess");
        }

        for (const [at, i] of r.range(out.client.deserializer, 0x40)) {
            const m = /^eax, (?:dword ptr )?\[edx \+ (0x[0-9a-f]+)\]$/.exec(i.op);
            if (i.mnemonic === "mov" && m && out.client.sizeOffset === undefined)
                out.client.sizeOffset = parseInt(m[1], 16);
        }
        if (out.client.sizeOffset !== undefined)
            out.notes.push("std::string layout: size @ +0x" + out.client.sizeOffset.toString(16).toUpperCase() +
                           " (helpers use +0x10/+0x14)");

        const numKey = findNumKey(r, [out.client.deserializer]);
        if (numKey) {
            out.client.numKey = numKey.va;
            out.client.numKeySite = numKey.at;
            out.notes.push("number key: global @ " + hex(numKey.va) +
                           " (xorpd at " + hex(numKey.at) + ")");
        }
    }

    for (const st of r.strings) {
        if (st.text !== ".?AVProtectedString@RBX@@") continue;
        const descriptor = st.va - 8;
        out.notes.push("rtti: name " + st.text + " @ " + hex(st.va));
        out.notes.push("rtti: TypeDescriptor @ " + hex(descriptor) +
                       "  vftable " + (p_section(r.p, descriptor) ? hex(r.p.dv.getUint32(va2off(r.p, descriptor), true)) : "?"));
        const cols = refsInData(r.p, descriptor);
        if (!cols.length) {
            out.notes.push("rtti: no complete object locator -> class is not polymorphic (or RTTI stripped);");
            out.notes.push("rtti: no member offsets exist in RTTI regardless - use the code-derived offset");
        } else {
            out.notes.push("rtti: complete object locator @ " + cols.map(hex).join(", "));
            const vtables = refsInData(r.p, cols[0]).map((v) => v + 4);
            out.notes.push("rtti: vtable(s) @ " + vtables.slice(0, 4).map(hex).join(", "));
            out.client.vtable = vtables[0];
        }
    }

    return out;
}


async function analyze(u8, boot) {
    const p = parsePE(u8);
    const cs = await boot();
    const decoder = new cs.Capstone(cs.ARCH_X86, cs.MODE_32);
    const end = p.imageBase + p.sizeOfImage;

    const dataRefs = new Map();
    const codeRefs = new Map();
    const funcs = new Set();
    let count = 0;

    const note = (map, target, from) => {
        if (!map.has(target)) map.set(target, new Set());
        map.get(target).add(from);
    };

    const sectionAt = (va) => p.secs.find((s) => s.exec && va >= s.va && va < s.va + Math.max(s.vsize, s.rawsize));

    const range = (from, size) => {
        const list = block(from, size);
        const out = [];
        for (const i of list) {
            const at = Number(i.address);
            if (at < from || at >= from + size) break;
            out.push([at, { mnemonic: i.mnemonic, op: i.op_str, size: Number(i.size) }]);
        }
        return out;
    };

    const block = (from, maxBytes) => {
        const s = sectionAt(from);
        if (!s) return [];
        const o = s.raw + (from - s.va);
        const stop = Math.min(s.raw + s.rawsize, p.u8.length);
        if (o < 0 || o >= stop) return [];
        const n = Math.min(maxBytes, stop - o);
        if (n <= 0) return [];
        try { return decoder.disasm(p.u8.subarray(o, o + n), from); } catch (e) { return []; }
    };

    const absorb = (list) => {
        for (const i of list) {
            const at = Number(i.address);
            const size = Number(i.size);
            if (!size || at < p.imageBase || at >= end) continue;
            count++;
            const isBranch = i.mnemonic === "call" || i.mnemonic === "jmp";
            const bare = /^0x([0-9a-f]+)$/.exec(i.op_str.trim());
            if (isBranch && bare) {
                const t = parseInt(bare[1], 16);
                if (t >= p.imageBase && t < end) { note(codeRefs, t, at); funcs.add(t); }
                continue;
            }
            const re = /0x([0-9a-f]+)/gi;
            let m;
            while ((m = re.exec(i.op_str)) !== null) {
                const t = parseInt(m[1], 16);
                if (t >= p.imageBase && t < end) note(dataRefs, t, at);
            }
            if (isBranch && i.op_str.indexOf("[") === -1) {
                const v = parseInt(i.op_str.trim().replace("0x", ""), 16);
                if (v >= p.imageBase && v < end) { note(codeRefs, v, at); funcs.add(v); }
            }
        }
    };

    const scan = (s) => {
        const stop = Math.min(s.raw + s.rawsize, p.u8.length);
        let o = s.raw;
        while (o < stop) {
            const n = Math.min(48 * 1024, stop - o);
            const base = s.va + (o - s.raw);
            let list;
            try { list = decoder.disasm(p.u8.subarray(o, o + n), base); } catch (e) { o += 1; continue; }
            if (!list || !list.length) { o += 1; continue; }
            absorb(list);
            const last = list[list.length - 1];
            const used = Number(last.address) + Number(last.size) - base;
            o += used > 0 ? used : 1;
        }
    };

    for (const s of p.secs) {
        if (!s.exec) continue;
        scan(s);
    }


    const starts = functionStarts(p, funcs);
    const tables = findCoreTables(p, dataRefs, starts);
    const result = { p, tables, table: tables[0] || null, starts, strings: findStrings(p), dataRefs, codeRefs,
                     funcs: new Set(funcs), count, range };
    result.derived = derive(result);
    result.close = () => decoder.close();
    return result;
}

if (typeof module !== "undefined") module.exports = { analyze, parsePE, va2off, readString, rot13, traceFromList };
