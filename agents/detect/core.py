"""Shared JSON state and the finding contract used by all detection agents."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import uuid


def now():
    return datetime.now(timezone.utc).isoformat()


def redact(value):
    if isinstance(value, dict):
        return {key: '[REDACTED]' if re.search(r'api[_-]?key|authorization|access[_-]?token|password', key, re.I) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return re.sub(r'(?:gsk_|gh[pousr]_)[A-Za-z0-9_-]{20,}|Bearer\s+\S+', '[REDACTED]', value)
    return value


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(redact(value), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    os.replace(temporary, path)


def finding(category, title, *, tool, severity='UNKNOWN', confidence='medium', status='potential',
            package_id=None, location=None, advisory_id=None, evidence=None, remediation=None, **extra):
    identity = json.dumps([category, package_id, advisory_id, location, title], sort_keys=True)
    return {'id': 'finding:' + hashlib.sha256(identity.encode()).hexdigest()[:20],
            'category': category, 'title': title, 'severity': severity.upper(), 'confidence': confidence,
            'status': status, 'tools': [tool], 'package_id': package_id, 'location': location,
            'advisory_id': advisory_id, 'evidence': evidence or [], 'remediation': remediation or [],
            'reachability': {'status': 'unknown', 'reason': 'Function-level reachability has not been established.'}, **extra}


@dataclass
class AgentResult:
    agent: str
    findings: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    tools: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    llm_review: dict | None = None


class WorkflowState:
    def __init__(self, target, output, config):
        self.output = Path(output)
        self.lock = threading.RLock()
        self.data = {'schema': 'guardian-detection-1', 'run_id': str(uuid.uuid4()), 'started_at': now(),
                     'target': str(Path(target).resolve()), 'configuration': config, 'status': 'running',
                     'agents': {}, 'events': [], 'findings': [], 'coverage': {}, 'followups': [], 'llm': {}}

    def event(self, sender, recipient, message, **details):
        with self.lock:
            self.data['events'].append({'at': now(), 'from': sender, 'to': recipient,
                                        'message': message, 'details': redact(details)})
            self.checkpoint()

    def start(self, agent):
        with self.lock:
            self.data['agents'][agent] = {'status': 'running', 'started_at': now()}
            self.event('MasterOrchestrator', agent, 'Execute assigned analysis')

    def finish(self, result):
        with self.lock:
            self.data['agents'][result.agent].update({'status': 'complete', 'finished_at': now(), **asdict(result)})
            self.data['findings'].extend(result.findings)
            self.data['coverage'].update(result.coverage)
            self.event(result.agent, 'MasterOrchestrator', 'Analysis results available', finding_count=len(result.findings))

    def fail(self, agent, error):
        with self.lock:
            self.data['agents'][agent] = {'status': 'failed', 'error': redact(str(error)), 'finished_at': now()}
            self.data['coverage'][agent] = {'status': 'failed', 'reason': redact(str(error))}
            self.event(agent, 'MasterOrchestrator', 'Analysis failed; coverage remains incomplete')

    def checkpoint(self):
        with self.lock:
            write_json(self.output / 'workflow-state.json', self.data)
