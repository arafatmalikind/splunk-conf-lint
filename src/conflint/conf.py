"""Parser for Splunk .conf files that keeps line numbers and duplicates."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Setting:
    key: str
    value: str
    line: int
    file: str = ""


@dataclass
class Stanza:
    name: str
    line: int
    file: str
    settings: Dict[str, Setting] = field(default_factory=dict)
    duplicates: List[Setting] = field(default_factory=list)

    def get(self, key, default=None):
        s = self.settings.get(key)
        return s.value if s else default

    def line_of(self, key):
        s = self.settings.get(key)
        return s.line if s else self.line

    def file_of(self, key):
        s = self.settings.get(key)
        return s.file if s and s.file else self.file

    def prefixed(self, prefix):
        return {k: v for k, v in self.settings.items() if k.startswith(prefix)}


@dataclass
class ConfFile:
    path: str
    name: str                    # props, transforms, ...
    layer: str                   # default | local
    stanzas: List[Stanza]
    duplicate_stanzas: List[Stanza] = field(default_factory=list)

    def get(self, name):
        for s in self.stanzas:
            if s.name == name:
                return s
        return None


def parse(path, rel=None):
    rel = rel or path
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read().splitlines()
    parts = rel.replace("\\", "/").split("/")
    layer = "local" if "local" in parts[:-1] else "default"
    name = parts[-1].rsplit(".", 1)[0]
    stanzas, dups, seen = [], [], {}
    cur = Stanza("default", 0, rel)
    stanzas.append(cur)
    i = 0
    while i < len(raw):
        lineno = i + 1
        line = raw[i]
        while line.endswith("\\") and i + 1 < len(raw):
            i += 1
            line = line[:-1] + "\n" + raw[i]
        i += 1
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            nm = s[1:-1].strip()
            if nm in seen:
                cur = seen[nm]
                dups.append(Stanza(nm, lineno, rel))
            else:
                cur = Stanza(nm, lineno, rel)
                seen[nm] = cur
                stanzas.append(cur)
            continue
        if "=" in s:
            k, _, v = s.partition("=")
            k, v = k.strip(), v.strip()
            st = Setting(k, v, lineno, rel)
            if k in cur.settings:
                cur.duplicates.append(cur.settings[k])
            cur.settings[k] = st
    if not stanzas[0].settings:
        stanzas.pop(0)
    return ConfFile(rel, name, layer, stanzas, dups)


def merge(files):
    """Merge default and local layers of one conf type the way Splunk does: local wins per setting."""
    files = sorted(files, key=lambda c: c.layer != "default")
    if not files:
        return None
    merged = ConfFile(files[0].path, files[0].name, "merged", [])
    index = {}
    for cf in files:
        for st in cf.stanzas:
            if st.name not in index:
                m = Stanza(st.name, st.line, st.file)
                index[st.name] = m
                merged.stanzas.append(m)
            index[st.name].settings.update(st.settings)
    return merged
