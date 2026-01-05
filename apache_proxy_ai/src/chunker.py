import os
import re
from typing import List, Dict

VHOST_START = re.compile(r'<VirtualHost\s+([^>]+)>', re.I)
VHOST_END = re.compile(r'</VirtualHost>', re.I)
DIR_START = re.compile(r'<Directory\s+([^>]+)>', re.I)
DIR_END = re.compile(r'</Directory>', re.I)

def load_files(base_path: str) -> Dict[str, str]:
    configs = {}
    for root, _, files in os.walk(base_path):
        for f in files:
            if f.endswith(('.conf', '.htaccess')):
                full = os.path.join(root, f)
                with open(full, 'r', encoding='utf-8', errors='ignore') as fh:
                    configs[full] = fh.read()
    return configs

def chunk_config(text: str, source: str) -> List[Dict]:
    chunks = []
    lines = text.splitlines()
    buffer = []
    scope = "GLOBAL"
    scope_id = "GLOBAL"
    parent = None

    for line in lines:
        if VHOST_START.search(line):
            if buffer:
                chunks.append(_chunk(scope, scope_id, parent, buffer, source))
                buffer = []
            scope = "VIRTUAL_HOST"
            scope_id = VHOST_START.search(line).group(1)
            parent = "GLOBAL"
            continue

        if DIR_START.search(line):
            if buffer:
                chunks.append(_chunk(scope, scope_id, parent, buffer, source))
                buffer = []
            scope = "DIRECTORY"
            scope_id = DIR_START.search(line).group(1)
            parent = "GLOBAL"
            continue

        if VHOST_END.search(line) or DIR_END.search(line):
            chunks.append(_chunk(scope, scope_id, parent, buffer, source))
            buffer = []
            scope = "GLOBAL"
            scope_id = "GLOBAL"
            parent = None
            continue

        buffer.append(line)

    if buffer:
        chunks.append(_chunk(scope, scope_id, parent, buffer, source))

    return chunks

def _chunk(scope, scope_id, parent, lines, source):
    return {
        "scope_type": scope,
        "scope_id": scope_id,
        "parent_scope": parent,
        "source": source,
        "directives": [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    }

def build_chunks(config_root: str) -> List[Dict]:
    all_chunks = []
    files = load_files(config_root)
    for path, text in files.items():
        all_chunks.extend(chunk_config(text, path))
    return all_chunks
