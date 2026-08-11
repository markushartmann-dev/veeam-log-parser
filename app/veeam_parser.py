"""
Veeam Backup & Replication 12.x log parser.

Supported log types (auto-detected by filename prefix):
  Job.*.log    — Job Manager / BackupCopy log, may span multiple daily sessions
  Task.*.log   — Per-VM task log within a job / copy session
  Agent.*.log  — VeeamAgent transport process log
"""
import re
import uuid
from datetime import datetime
from typing import Optional

# ── Line formats ──────────────────────────────────────────────────────────────
# Manager / Task:
#   [DD.MM.YYYY HH:MM:SS.mmm]    <thread> [task]    Level (N)    message
MGR_RE = re.compile(
    r'^\[(\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\.\d{3})\]'
    r'\s+<\s*(\d+)\s*>'
    r'(?:\s+\[(\w+)\])?'
    r'\s+(Info|Warning|Error|Failed|Success)'
    r'\s+\(\d+\)'
    r'\s+(.*)'
)

# VeeamAgent:
#   [DD.MM.YYYY HH:MM:SS.mmm] < thread> category      | message
AGENT_RE = re.compile(
    r'^\[(\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\.\d{3})\]'
    r'\s+<\s*(\d+)\s*>'
    r'(?:\s+(\w+))?\s+\|\s+(.*)'
)

TS_FMT = '%d.%m.%Y %H:%M:%S.%f'

# ── Key data patterns ─────────────────────────────────────────────────────────
JOB_NAME_RE = re.compile(r'Job Name:\s*\[([^\]]+)\]')

# Job session completion:
#   Job session 'ID' has been completed, status: 'Success',
#   '11,6 TB' of '11,6 TB' bytes, '14' storages in '14' tasks,
#   '14' successful, '0' failed, details: ...
JOB_SESSION_RE = re.compile(
    r"Job session '([^']+)' has been completed, status: '(\w+)', "
    r"'([^']+)' of '([^']+)' bytes, "
    r"'(\d+)' storages in '(\d+)' tasks, '(\d+)' successful, '(\d+)' failed"
)

# Task (per-VM) session completion:
#   Task session [ID] has been completed, status: Success,
#   1073741824000 of 1073741824000 bytes
TASK_SESSION_RE = re.compile(
    r"Task session \[([^\]]+)\] has been completed, status: (\w+), "
    r"([\d,]+) of ([\d,]+) bytes"
)

# Backup stats line:
#   BackupSize '176392044544', dataSize '417610907177',
#   dedupRatio '92', compressRatio '45'
STATS_RE = re.compile(
    r"BackupSize '(\d+)', dataSize '(\d+)', "
    r"dedupRatio '(\d+)', compressRatio '(\d+)'"
)

# Backed up size line:
#   Backed up size: 164,3 GB, total backed up size: 106,8 TB
BACKED_UP_RE = re.compile(
    r'Backed up size:\s*([\d,.]+)\s*(KB|MB|GB|TB)', re.I
)
TOTAL_BACKED_RE = re.compile(
    r'total backed up size:\s*([\d,.]+)\s*(KB|MB|GB|TB)', re.I
)

# Load / Busy line:
#   Load: Source 99% > Proxy 19% > Network 1% > Target 0%
LOAD_RE = re.compile(
    r'(?:Load|Busy):\s*Source (\d+)%\s*>\s*Proxy (\d+)%\s*>'
    r'\s*Network (\d+)%\s*>\s*Target (\d+)%'
)

BOTTLENECK_RE = re.compile(r'Primary bottleneck:\s*(\S+)')

# Proxy / transport-mode patterns (Job Manager logs only)
# Request: "... ViDisk_|ViProxyRepositoryPairResourceRequest ... srv name=X : ... vddk modes=Y : ... ]:N"
PROXY_REQ_RE = re.compile(
    r'ViDisk_\|ViProxyRepositoryPairResourceRequest'
    r'.*?srv name=([^:]+)'
    r'.*?vddk modes=([^:]+)'
    r'.*\]:(\d+)\s*$'
)
# Response that follows: "- - - - Response: Count: N"
PROXY_RESP_COUNT_RE = re.compile(r'- - - - Response: Count: (\d+)')

# Per-VM tracking: VM name in Job Manager log lines (task_id correlation)
VM_NAME_RE = re.compile(
    r"(?:Processing object|Object name)[:\s]+['\"]([^'\"]+)['\"]"
    r"|(?:VM|Task) name[:\s]+\[([^\]]+)\]"
    r"|Processing\s+['\"]([^'\"]+)['\"]",
    re.I
)
# Transport mode in Task logs (fallback pattern)
TASK_TRANSPORT_RE = re.compile(
    r'(?:transport(?:\s+mode)?|mode is)[:\s]+'
    r'(HotAdd|DirectSAN|NBDSsl|NBD\s*ssl|NBD|SAN|NAS)',
    re.I
)

TO_GB = {'KB': 1 / 1024 / 1024, 'MB': 1 / 1024, 'GB': 1.0, 'TB': 1024.0}


def _normalize_mode(m: str) -> str:
    m = m.strip().lower()
    if 'hotadd' in m:
        return 'HotAdd'
    if m == 'san' or 'directsan' in m or 'fibre' in m or 'iscsi' in m:
        return 'DirectSAN'
    if 'nbdssl' in m or 'nbd_ssl' in m:
        return 'NBD/SSL'
    if 'nbd' in m:
        return 'NBD'
    if 'nas' in m:
        return 'NFS Direct'
    return m.upper()


def _de_float(s: str) -> float:
    """Parse German-formatted number (dot=thousands, comma=decimal)."""
    return float(s.replace('.', '').replace(',', '.'))


def _size_gb(val: str, unit: str) -> float:
    return _de_float(val) * TO_GB[unit.upper()]


def _bytes_gb(b: int) -> float:
    return b / (1024 ** 3)


def _parse_ts(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, TS_FMT)
    except ValueError:
        return None


def _detect_type(filename: str) -> str:
    n = filename.lower()
    if n.startswith('job.'):
        return 'job'
    if n.startswith('task.'):
        return 'task'
    if n.startswith('agent.'):
        return 'agent'
    return 'unknown'


def _split_size(s: str):
    """'11,6 TB' -> ('11,6', 'TB')"""
    m = re.match(r'([\d,.]+)\s*(KB|MB|GB|TB)', s.strip(), re.I)
    return (m.group(1), m.group(2)) if m else (None, None)


# ── Session accumulator ───────────────────────────────────────────────────────
class _S:
    __slots__ = (
        'job_name', 'session_id', 'start_ts', 'end_ts', 'status',
        'entries', 'errors', 'warnings',
        'successful_tasks', 'failed_tasks', 'total_tasks',
        'backup_bytes', 'data_bytes', 'dedup_ratio', 'compress_ratio',
        'transferred_bytes', 'backed_up_gb', 'total_repo_gb',
        'bottleneck', 'load', 'proxy_stats', 'vm_proxy_stats',
    )

    def __init__(self):
        self.job_name = None
        self.session_id = None
        self.start_ts = None
        self.end_ts = None
        self.status = 'Unknown'
        self.entries = []
        self.errors = []
        self.warnings = []
        self.successful_tasks = None
        self.failed_tasks = None
        self.total_tasks = None
        self.backup_bytes = None
        self.data_bytes = None
        self.dedup_ratio = None
        self.compress_ratio = None
        self.transferred_bytes = None
        self.backed_up_gb = None
        self.total_repo_gb = None
        self.bottleneck = None
        self.load = None
        self.proxy_stats = {}    # {(proxy_name, mode): task_count}
        self.vm_proxy_stats = [] # [{vm, proxy, mode, count}]


def _add_vm_proxy(sess: _S, vm: str, proxy: str, mode: str) -> None:
    """Increment per-VM transport-mode counter, inserting a new entry if needed."""
    for e in sess.vm_proxy_stats:
        if e['vm'] == vm and e['proxy'] == proxy and e['mode'] == mode:
            e['count'] += 1
            return
    sess.vm_proxy_stats.append({'vm': vm, 'proxy': proxy, 'mode': mode, 'count': 1})


def _vm_name_from_task_file(filename: str) -> str:
    """Extract VM name from Task log filename: Task.VMNAME.SESSIONID.log"""
    if not filename.lower().startswith('task.'):
        return ''
    inner = filename[5:]          # strip 'task.' prefix
    parts = inner.split('.')
    # ['VMNAME', 'SESSIONID', 'log'] → join all but last 2
    if len(parts) > 2:
        return '.'.join(parts[:-2])
    return parts[0] if parts else ''


def _build_vm_proxy(s: _S, log_type: str, filename: str) -> list:
    """Return vm_proxy_stats, optionally deriving it for task logs from proxy_stats."""
    if s.vm_proxy_stats:
        return sorted(s.vm_proxy_stats, key=lambda e: (e['vm'], e['proxy'], e['mode']))
    # For task logs: derive from proxy_stats using VM name embedded in filename
    if log_type == 'task' and s.proxy_stats:
        vm = _vm_name_from_task_file(filename)
        if vm:
            return [
                {'vm': vm, 'proxy': proxy, 'mode': mode, 'count': count}
                for (proxy, mode), count in sorted(s.proxy_stats.items(), key=lambda x: -x[1])
            ]
    return []


def _finalize(filename: str, log_type: str, s: _S, total_lines: int) -> dict:
    status = s.status
    if status == 'Unknown':
        if s.errors:
            status = 'Failed'
        elif s.warnings:
            status = 'Warning'
        elif s.entries:
            status = 'Success'

    duration_sec = None
    if s.start_ts and s.end_ts:
        t1, t2 = _parse_ts(s.start_ts), _parse_ts(s.end_ts)
        if t1 and t2:
            duration_sec = max(0, int((t2 - t1).total_seconds()))

    return {
        'id': str(uuid.uuid4()),
        'filename': filename,
        'log_type': log_type,
        'job_name': s.job_name,
        'session_id': s.session_id,
        'start_time': s.start_ts,
        'end_time': s.end_ts,
        'duration_sec': duration_sec,
        'status': status,
        'total_lines': total_lines,
        'entry_count': len(s.entries),
        'error_count': len(s.errors),
        'warning_count': len(s.warnings),
        'entries': s.entries,
        'errors': s.errors,
        'warnings': s.warnings,
        'vms': [],
        'successful_tasks': s.successful_tasks,
        'failed_tasks': s.failed_tasks,
        'total_tasks': s.total_tasks,
        'backup_size_gb': round(_bytes_gb(s.backup_bytes), 2) if s.backup_bytes else None,
        'data_size_gb': round(_bytes_gb(s.data_bytes), 2) if s.data_bytes else None,
        'transferred_gb': round(_bytes_gb(s.transferred_bytes), 2) if s.transferred_bytes else None,
        'backed_up_gb': round(s.backed_up_gb, 2) if s.backed_up_gb else None,
        'total_repo_gb': round(s.total_repo_gb, 2) if s.total_repo_gb else None,
        'dedup_ratio': s.dedup_ratio,
        'compress_ratio': s.compress_ratio,
        'bottleneck': s.bottleneck,
        'load': s.load,
        'rate_mbps': None,
        'proxy_stats': [
            {'proxy': proxy, 'mode': mode, 'tasks': count}
            for (proxy, mode), count in sorted(s.proxy_stats.items(), key=lambda x: -x[1])
        ],
        'vm_proxy_stats': _build_vm_proxy(s, log_type, filename),
    }


def _accumulate(sess: _S, line_no: int, ts_str: str, thread: str,
                task_id: Optional[str], level: str, message: str, raw: str):
    """Add one parsed log line to a session accumulator."""
    if sess.start_ts is None:
        sess.start_ts = ts_str
    sess.end_ts = ts_str

    entry = {
        'line_number': line_no,
        'timestamp': ts_str,
        'thread': thread.strip(),
        'task_id': task_id,
        'level': level,
        'message': message,
        'raw': raw,
    }
    sess.entries.append(entry)

    if level in ('Error', 'Failed'):
        sess.errors.append(entry)
    elif level == 'Warning':
        sess.warnings.append(entry)

    if sess.job_name is None:
        jn = JOB_NAME_RE.search(message)
        if jn:
            sess.job_name = jn.group(1)

    sc = JOB_SESSION_RE.search(message)
    if sc:
        sess.session_id = sc.group(1)
        sess.status = sc.group(2)
        v, u = _split_size(sc.group(3))
        if v and u:
            try:
                sess.transferred_bytes = int(_size_gb(v, u) * (1024 ** 3))
            except Exception:
                pass
        try:
            sess.total_tasks = int(sc.group(6))
            sess.successful_tasks = int(sc.group(7))
            sess.failed_tasks = int(sc.group(8))
        except Exception:
            pass

    tc = TASK_SESSION_RE.search(message)
    if tc:
        sess.session_id = tc.group(1)
        sess.status = tc.group(2)
        try:
            sess.transferred_bytes = int(tc.group(4).replace(',', ''))
        except Exception:
            pass

    bs = STATS_RE.search(message)
    if bs:
        try:
            sess.backup_bytes = int(bs.group(1))
            sess.data_bytes = int(bs.group(2))
            sess.dedup_ratio = int(bs.group(3))
            sess.compress_ratio = int(bs.group(4))
        except Exception:
            pass

    bup = BACKED_UP_RE.search(message)
    if bup:
        try:
            sess.backed_up_gb = _size_gb(bup.group(1), bup.group(2))
        except Exception:
            pass

    tot = TOTAL_BACKED_RE.search(message)
    if tot:
        try:
            sess.total_repo_gb = _size_gb(tot.group(1), tot.group(2))
        except Exception:
            pass

    ld = LOAD_RE.search(message)
    if ld:
        sess.load = {
            'source': int(ld.group(1)),
            'proxy': int(ld.group(2)),
            'network': int(ld.group(3)),
            'target': int(ld.group(4)),
        }

    bn = BOTTLENECK_RE.search(message)
    if bn:
        sess.bottleneck = bn.group(1)


# ── Public entry point ────────────────────────────────────────────────────────
def parse_log(filename: str, content: str) -> list:
    log_type = _detect_type(filename)
    lines = content.splitlines()

    if log_type == 'agent':
        return _parse_agent(filename, lines)
    return _parse_manager(filename, lines, log_type)


# ── Manager / Task parser ─────────────────────────────────────────────────────
def _parse_manager(filename: str, lines: list, log_type: str) -> list:
    results = []
    sess = _S()
    need_start_marker = (log_type == 'job')
    started = not need_start_marker
    # For job logs: accumulate pre-STARTBACKUPJOB lines as a potential preceding session
    pre_sess = _S() if need_start_marker else None
    last_proxy = None    # (proxy_name, mode) set by request line, consumed by response
    task_vm_map = {}     # {task_id: vm_name} for job log per-VM correlation
    # For task logs extract VM name once from filename
    vm_name_for_task = _vm_name_from_task_file(filename) if log_type == 'task' else ''

    for i, raw in enumerate(lines, 1):
        m = MGR_RE.match(raw.rstrip())
        if not m:
            continue

        ts_str, thread, task_id, level, message = m.groups()
        message = message.strip()

        # ── Session boundary ──────────────────────────────────────────────
        if message == 'STARTBACKUPJOB':
            if started and sess.entries:
                # Finalize the session that just ended
                results.append(_finalize(filename, log_type, sess, len(lines)))
            elif not started and pre_sess is not None and pre_sess.entries:
                # Only emit pre-session if it has an explicit completion line
                # (status != 'Unknown' means JOB_SESSION_RE or TASK_SESSION_RE matched).
                # This distinguishes a real prior session from mere startup noise.
                if pre_sess.status != 'Unknown':
                    results.append(_finalize(filename, log_type, pre_sess, len(lines)))
            sess = _S()
            pre_sess = None  # only one pre-session per file
            started = True
            last_proxy = None
            continue

        if not started:
            # Collect into pre-session accumulator
            if pre_sess is not None:
                _accumulate(pre_sess, i, ts_str, thread, task_id, level, message, raw.rstrip())
            continue

        # ── Accumulate entry ──────────────────────────────────────────────
        _accumulate(sess, i, ts_str, thread, task_id, level, message, raw.rstrip())

        # ── VM-name tracking (job logs, task_id correlation) ─────────────
        if log_type == 'job' and task_id:
            vm_m = VM_NAME_RE.search(message)
            if vm_m:
                vm = next((g for g in vm_m.groups() if g), '').strip()
                if vm:
                    task_vm_map[task_id.strip()] = vm

        # ── Transport mode (task logs, text-based fallback) ───────────────
        if log_type == 'task' and vm_name_for_task:
            tm = TASK_TRANSPORT_RE.search(message)
            if tm and sess.proxy_stats:
                mode = _normalize_mode(tm.group(1))
                proxy = next(iter(sess.proxy_stats))[0]
                _add_vm_proxy(sess, vm_name_for_task, proxy, mode)

        # ── Proxy / transport-mode tracking ──────────────────────────────
        if 'ViDisk_|ViProxyRepositoryPairResourceRequest' in message:
            pm = PROXY_REQ_RE.search(message)
            if pm:
                proxy_name = pm.group(1).strip()
                mode = _normalize_mode(pm.group(2))
                last_proxy = (proxy_name, mode)
                # Per-VM: job log via task_id, task log via filename
                if task_id and task_id.strip() in task_vm_map:
                    _add_vm_proxy(sess, task_vm_map[task_id.strip()], proxy_name, mode)
                elif vm_name_for_task:
                    _add_vm_proxy(sess, vm_name_for_task, proxy_name, mode)
        elif last_proxy is not None:
            if '- - - - Response: Count:' in message:
                cm = PROXY_RESP_COUNT_RE.search(message)
                if cm:
                    sess.proxy_stats[last_proxy] = (
                        sess.proxy_stats.get(last_proxy, 0) + int(cm.group(1))
                    )
            last_proxy = None  # clear after any line following the request

    if started and sess.entries:
        results.append(_finalize(filename, log_type, sess, len(lines)))

    # Add run index to job_name when multiple sessions in one file
    if len(results) > 1:
        total = len(results)
        for idx, r in enumerate(results, 1):
            if r['job_name']:
                r['job_name'] = f"{r['job_name']} (Run {idx}/{total})"

    return results


# ── Agent parser ──────────────────────────────────────────────────────────────
def _parse_agent(filename: str, lines: list) -> list:
    sess = _S()
    sess.job_name = filename

    for i, raw in enumerate(lines, 1):
        m = AGENT_RE.match(raw.rstrip())
        if not m:
            continue
        ts_str, thread, category, message = m.groups()
        if sess.start_ts is None:
            sess.start_ts = ts_str
        sess.end_ts = ts_str
        sess.entries.append({
            'line_number': i,
            'timestamp': ts_str,
            'thread': thread.strip(),
            'task_id': category,
            'level': 'Info',
            'message': (message or '').strip(),
            'raw': raw.rstrip(),
        })

    result = _finalize(filename, 'agent', sess, len(lines))
    result['status'] = 'Info'
    return [result]
