"""Convert real AI agent logs into the lab's events.jsonl schema.

Supported inputs
  claude-code  Claude Code session transcripts (~/.claude/projects/<project>/<session>.jsonl)
  openai       OpenAI-style chat logs: {"messages": [...], "tools": [...]} per session.
               Also covers Ollama /api/chat logs and most agent frameworks / gateways
               that log in this shape. Accepts a .json object, a .json list, or .jsonl.

Real logs don't carry the lab's labels (read/write, trust, sensitivity, egress),
so the Enricher infers them from tool names, arguments, file paths and content.
Those inferences are heuristics; tune the patterns below for your environment.
"""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

# ------------------------------------------------------------------ heuristics
READ_TOOLS = {"read", "glob", "grep", "ls", "webfetch", "websearch", "notebookread", "toolsearch",
              "taskget", "tasklist", "read_file", "list_files", "read_email", "read_inbox", "fetch_url",
              "search", "get_weather", "get_forecast"}
LOCAL_WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "todowrite", "taskcreate", "taskupdate"}
UNTRUSTED_RESULT_TOOLS = {"webfetch", "websearch", "fetch_url", "read_email", "read_inbox", "search"}
WRITE_VERB = re.compile(r"(send|post|create|update|delete|remove|write|publish|upload|push|comment|"
                        r"reply|forward|share|submit|notify|message|invite|transfer|pay)", re.I)
EGRESS_VERB = re.compile(r"(send|post|email|mail|http|webhook|upload|publish|forward|share|notify|message)", re.I)

SECRET_PATH = re.compile(
    r"(^|[/\\])(\.env(\.[\w-]+)?|id_rsa|id_ed25519|id_ecdsa|\.netrc|\.npmrc|\.pypirc|\.git-credentials|"
    r"credentials(\.json)?|secrets?\.(ya?ml|json|txt)|kubeconfig)$|\.(pem|key|p12|pfx)$|[/\\]\.(aws|ssh|gnupg)[/\\]",
    re.I)
SECRET_CONTENT = [re.compile(p) for p in [
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4000}?-----END [A-Z ]*PRIVATE KEY-----",
    r"\bsk-[A-Za-z0-9_-]{20,}",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"(?im)^[ \t]*[\w.-]*(password|passwd|secret|api[_-]?key|access[_-]?key|token)[\w.-]*[ \t]*[:=][ \t]*\S{8,}$",
]]

NET_CMD = re.compile(r"\b(curl|wget|nc|ncat|netcat|scp|rsync|ssh|sftp|ftp|telnet|Invoke-WebRequest|iwr)\b|"
                     r"\bgit\s+push\b|https?://", re.I)
URL_RE = re.compile(r"https?://[^\s'\"<>|)]+", re.I)
HOST_ARG = re.compile(r"\b(?:[\w.-]+@)?([a-z0-9-]+(?:\.[a-z0-9-]+)+):", re.I)  # scp/rsync user@host:
NC_ARG = re.compile(r"\b(?:nc|ncat|netcat|telnet)\s+(?:-\S+\s+)*([\w.-]+)\s+\d+", re.I)
SSH_ARG = re.compile(r"\b(?:ssh|sftp)\s+(?:-\S+\s+(?:\S+\s+)?)*(?:[\w.-]+@)?([\w.-]+\.[a-z]{2,})", re.I)

MAX_CONTENT = 4000
REMINDER = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)


def domain_of(dest):
    s = (dest or "").strip().lower()
    if "://" in s:
        return urlparse(s).hostname or ""
    if "@" in s:
        return s.rsplit("@", 1)[1]
    return s


class Enricher:
    def __init__(self, internal_domains=(), internal_mcp=()):
        self.internal = tuple(d.lower().lstrip(".") for d in internal_domains)
        self.internal_mcp = set(internal_mcp)

    # -- classification
    def is_internal(self, domain):
        if domain in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or domain.endswith(".local"):
            return True
        if domain.startswith("mcp:"):
            return domain[4:] in self.internal_mcp
        return any(domain == d or domain.endswith("." + d) for d in self.internal)

    def server_of(self, name):
        if name.startswith("mcp__"):
            parts = name.split("__")
            return parts[1] if len(parts) > 2 else "mcp"
        return "builtin"

    def kind_of(self, name, args):
        base = name.split("__")[-1].lower()
        if base == "bash" or name.lower() == "bash":
            cmd = str(args.get("command", ""))
            return "write" if NET_CMD.search(cmd) or re.search(r"(\brm\b|\bmv\b|>\s*\S|\bgit\s+(commit|push)\b)", cmd) else "read"
        if base in LOCAL_WRITE_TOOLS:
            return "write"
        if base in READ_TOOLS:
            return "read"
        return "write" if WRITE_VERB.search(base) else "read"

    def trust_of(self, name, args):
        base = name.split("__")[-1].lower()
        if name.startswith("mcp__") or base in UNTRUSTED_RESULT_TOOLS:
            return "untrusted"
        if base == "bash" and NET_CMD.search(str(args.get("command", ""))):
            return "untrusted"
        return "internal"

    def source_of(self, name, args):
        return str(args.get("file_path") or args.get("path") or args.get("url") or args.get("query")
                   or args.get("command") or args.get("pattern") or name)[:300]

    def secret_material(self, name, args, content):
        """Return the sensitive part of a tool result ('' if none)."""
        path = str(args.get("file_path") or args.get("path") or "")
        cmd = str(args.get("command", ""))
        if (path and SECRET_PATH.search(path)) or any(SECRET_PATH.search(tok) for tok in cmd.split()):
            return content
        found = [m.group(0) for rx in SECRET_CONTENT for m in rx.finditer(content or "")]
        return "\n".join(found)

    def egress_of(self, name, args):
        """Outbound destinations implied by a tool call: [(dest, payload)]."""
        base = name.split("__")[-1].lower()
        out = []
        if base == "webfetch" or base == "fetch_url":
            out.append((str(args.get("url", "")), str(args.get("url", ""))))
        elif base == "websearch":
            out.append(("websearch", str(args.get("query", ""))))
        elif base == "bash":
            cmd = str(args.get("command", ""))
            if NET_CMD.search(cmd):
                dests = URL_RE.findall(cmd) + [m.group(1) for rx in (HOST_ARG, NC_ARG, SSH_ARG)
                                                for m in rx.finditer(cmd)]
                if not dests and re.search(r"\bgit\s+push\b", cmd):
                    dests = ["git-remote"]
                for d in dict.fromkeys(dests):
                    out.append((d, cmd))
        elif name.startswith("mcp__"):
            out.append((f"mcp:{self.server_of(name)}", json.dumps(args)))
        elif EGRESS_VERB.search(base):
            dest = args.get("to") or args.get("url") or args.get("recipient") or args.get("email") \
                or args.get("channel") or name
            out.append((str(dest), json.dumps(args)))
        res = []
        for dest, payload in out:
            dom = dest if dest.startswith("mcp:") or dest in ("websearch", "git-remote") else domain_of(dest)
            if not self.is_internal(dom):
                res.append({"dest": dest, "dest_domain": dom, "payload": payload})
        return res


# ------------------------------------------------------------------ writer
class Writer:
    """Emits events in the lab schema. One lab session per user prompt by default."""

    def __init__(self, out, enricher, split_turns=True):
        self.out, self.e, self.split = out, enricher, split_turns
        self.sessions = 0
        self.session = None

    def start(self, sid, model="unknown", ts=None):
        self.session, self.seq = sid, 0
        self.sessions += 1
        self._log("session_start", ts, agent="imported", model=model)

    def end(self, ts=None):
        if self.session:
            self._log("session_end", ts, steps=self.seq)
            self.session = None

    def _log(self, event, ts, **f):
        self.seq += 1
        rec = {"ts": ts or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
               "session": self.session, "seq": self.seq, "event": event, **f}
        self.out.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def tool_registered(self, name, description, parameters, ts=None):
        spec = {"name": name, "description": description or "", "parameters": parameters or {}}
        h = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:16]
        self._log("tool_registered", ts, server=self.e.server_of(name), tool=name,
                  kind=self.e.kind_of(name, {}), third_party=name.startswith("mcp__"),
                  description=description or "", schema_hash=h)

    def prompt(self, text, ts=None):
        self._log("user_prompt", ts, text=text[:4000])

    def llm(self, text, calls, ts=None):
        self._log("llm_response", ts, text=(text or "")[:2000], tool_calls=calls)

    def tool_call(self, name, args, ts=None):
        self._log("tool_call", ts, tool=name, server=self.e.server_of(name), kind=self.e.kind_of(name, args),
                  third_party=name.startswith("mcp__"), args=args)
        for eg in self.e.egress_of(name, args):
            self._log("egress", ts, tool=name, server=self.e.server_of(name), dest=eg["dest"],
                      dest_domain=eg["dest_domain"], internal=False, bytes=len(eg["payload"]),
                      payload_preview=eg["payload"][:1000])

    def tool_result(self, name, args, content, is_error=False, ts=None):
        secret = self.e.secret_material(name, args, content)
        rec = dict(tool=name, server=self.e.server_of(name), trust=self.e.trust_of(name, args),
                   sensitivity="secret" if secret else "none", source=self.e.source_of(name, args),
                   size=len(content), content=content[:MAX_CONTENT], is_error=bool(is_error))
        if secret:
            rec["secret_material"] = secret[:MAX_CONTENT]
        self._log("tool_result", ts, **rec)


# ------------------------------------------------------------------ adapters
def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") == "text" or "text" in b:
                    parts.append(str(b.get("text", "")))
                elif b.get("type") == "image":
                    parts.append("[image]")
            else:
                parts.append(str(b))
        return "\n".join(parts)
    return "" if content is None else json.dumps(content)


def import_claude_code(path, w):
    """Claude Code transcript: one JSON record per line. Tool calls are 'tool_use'
    blocks in assistant messages; results are 'tool_result' blocks in user messages."""
    name = os.path.splitext(os.path.basename(path))[0][:8]
    pending, turn, started = {}, 0, False
    model = "unknown"
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") not in ("user", "assistant") or d.get("isSidechain"):
                continue
            ts, msg = d.get("timestamp"), d.get("message") or {}
            content = msg.get("content")
            blocks = content if isinstance(content, list) else [{"type": "text", "text": content or ""}]
            if d["type"] == "assistant":
                model = msg.get("model") or model
                calls = [b for b in blocks if b.get("type") == "tool_use"]
                text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")
                if not started:
                    w.start(f"cc:{name}#t{turn}", model, ts)
                    started = True
                if text or calls:
                    w.llm(text, [c.get("name") for c in calls], ts)
                for c in calls:
                    args = c.get("input") or {}
                    pending[c.get("id")] = (c.get("name", "?"), args)
                    w.tool_call(c.get("name", "?"), args, ts)
                continue
            # user record: either tool results or a new prompt
            results = [b for b in blocks if b.get("type") == "tool_result"]
            for r in results:
                tname, args = pending.pop(r.get("tool_use_id"), ("?", {}))
                if not started:
                    w.start(f"cc:{name}#t{turn}", model, ts)
                    started = True
                w.tool_result(tname, args, _text_of(r.get("content")), r.get("is_error"), ts)
            prompt = REMINDER.sub("", "\n".join(b.get("text", "") for b in blocks
                                                if b.get("type") == "text")).strip()
            if prompt and not results:
                if w.split and started:
                    w.end(ts)
                    turn += 1
                    started = False
                if not started:
                    w.start(f"cc:{name}#t{turn}", model, ts)
                    started = True
                w.prompt(prompt, ts)
    w.end()


def _openai_sessions(path):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    try:
        data = json.loads(raw)
        items = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        items = [json.loads(l) for l in raw.splitlines() if l.strip()]
    for i, item in enumerate(items):
        if isinstance(item, dict) and "messages" in item:
            yield item.get("id") or f"{i}", item
        elif isinstance(item, dict) and "request" in item:  # gateway logs: {"request": {...}, "response": {...}}
            req = dict(item["request"])
            msg = (item.get("response") or {}).get("choices", [{}])[0].get("message") or \
                  (item.get("response") or {}).get("message")
            if msg:
                req["messages"] = list(req.get("messages", [])) + [msg]
            yield item.get("id") or f"{i}", req


def import_openai(path, w):
    base = os.path.splitext(os.path.basename(path))[0][:12]
    for sid, s in _openai_sessions(path):
        w.start(f"oa:{base}:{sid}", s.get("model", "unknown"))
        for t in s.get("tools") or []:
            fn = t.get("function", t)
            w.tool_registered(fn.get("name", "?"), fn.get("description"), fn.get("parameters"))
        ids, last_call = {}, None
        turn = 0
        for m in s.get("messages", []):
            role = m.get("role")
            if role == "user":
                text = _text_of(m.get("content")).strip()
                if w.split and turn > 0:
                    w.end()
                    w.start(f"oa:{base}:{sid}#t{turn}", s.get("model", "unknown"))
                turn += 1
                w.prompt(text)
            elif role == "assistant":
                calls = []
                for c in m.get("tool_calls") or []:
                    fn = c.get("function", {})
                    args = fn.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {"_raw": args}
                    calls.append((c.get("id"), fn.get("name", "?"), args))
                w.llm(_text_of(m.get("content")), [c[1] for c in calls])
                for cid, name, args in calls:
                    ids[cid] = (name, args)
                    last_call = (name, args)
                    w.tool_call(name, args)
            elif role == "tool":
                name, args = ids.get(m.get("tool_call_id")) or (
                    (m.get("tool_name") or m.get("name"), {}) if (m.get("tool_name") or m.get("name"))
                    else (last_call or ("?", {})))
                w.tool_result(name, args, _text_of(m.get("content")))
        w.end()


def detect_format(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        head = f.read(20000)
    if '"sessionId"' in head and ('"tool_use"' in head or '"parentUuid"' in head):
        return "claude-code"
    return "openai"


IMPORTERS = {"claude-code": import_claude_code, "openai": import_openai}
