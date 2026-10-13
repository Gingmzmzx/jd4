from asyncio import get_event_loop, shield, sleep, wait_for, TimeoutError
from itertools import chain
from os import access, cpu_count, geteuid, getpid, kill, makedirs, path, rmdir, W_OK
from signal import SIGKILL
from socket import socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET, SO_PEERCRED
from subprocess import call
from sys import __stdin__
from tempfile import mkdtemp

from jd4.log import logger
from jd4.util import read_text_file, write_text_file

CGROUP2_ROOT = '/sys/fs/cgroup/jd4'
CGROUP2_DAEMON_ROOT = path.join(CGROUP2_ROOT, 'daemon')
CGROUP2_SUBTREE_CONTROL = '/sys/fs/cgroup/cgroup.subtree_control'
SUBTREE_CONTROL = '+cpu +memory +pids'
CPUACCT_CGROUP_ROOT = '/sys/fs/cgroup/cpuacct/jd4'
MEMORY_CGROUP_ROOT = '/sys/fs/cgroup/memory/jd4'
PIDS_CGROUP_ROOT = '/sys/fs/cgroup/pids/jd4'
WAIT_JITTER_NS = 5000000

def use_cgroup2():
    return path.exists('/sys/fs/cgroup/cgroup.controllers')

def try_init_cgroup():
    if use_cgroup2():
        _try_init_cgroup2()
    else:
        _try_init_cgroup1()

def _try_init_cgroup2():
    euid = geteuid()
    if (path.isdir(CGROUP2_ROOT) and access(CGROUP2_ROOT, W_OK) and
            path.isdir(CGROUP2_DAEMON_ROOT) and access(CGROUP2_DAEMON_ROOT, W_OK)):
        return
    if euid == 0:
        logger.info('Initializing cgroup: %s', CGROUP2_ROOT)
        try:
            write_text_file(CGROUP2_SUBTREE_CONTROL, SUBTREE_CONTROL)
        except OSError as e:
            logger.warning('Failed to enable controllers in %s: %s',
                           CGROUP2_SUBTREE_CONTROL, e)
        makedirs(CGROUP2_ROOT, exist_ok=True)
        write_text_file(path.join(CGROUP2_ROOT, 'cgroup.subtree_control'),
                        SUBTREE_CONTROL)
        makedirs(CGROUP2_DAEMON_ROOT, exist_ok=True)
    elif __stdin__.isatty():
        logger.info('Initializing cgroup: %s', CGROUP2_ROOT)
        call(['sudo', 'sh', '-c',
              'echo "{0}" > "{1}" && mkdir -p "{2}" "{3}" && '
              'echo "{0}" > "{2}/cgroup.subtree_control" && chown -R "{4}" "{2}"'.format(
                  SUBTREE_CONTROL, CGROUP2_SUBTREE_CONTROL, CGROUP2_ROOT,
                  CGROUP2_DAEMON_ROOT, euid)])
    else:
        logger.error('Cgroup not initialized')
        return
    # Keep the daemon out of CGROUP2_ROOT, otherwise controllers could not be
    # enabled for the cgroups created underneath it.
    try:
        write_text_file(path.join(CGROUP2_DAEMON_ROOT, 'cgroup.procs'),
                        str(getpid()))
    except OSError as e:
        logger.warning('Failed to move judge daemon into %s: %s',
                       CGROUP2_DAEMON_ROOT, e)

def _try_init_cgroup1():
    euid = geteuid()
    cgroups_to_init = list()
    if not (path.isdir(CPUACCT_CGROUP_ROOT) and access(CPUACCT_CGROUP_ROOT, W_OK)):
        cgroups_to_init.append(CPUACCT_CGROUP_ROOT)
    if not (path.isdir(MEMORY_CGROUP_ROOT) and access(MEMORY_CGROUP_ROOT, W_OK)):
        cgroups_to_init.append(MEMORY_CGROUP_ROOT)
    if not (path.isdir(PIDS_CGROUP_ROOT) and access(PIDS_CGROUP_ROOT, W_OK)):
        cgroups_to_init.append(PIDS_CGROUP_ROOT)
    if cgroups_to_init:
        if euid == 0:
            logger.info('Initializing cgroup: %s', ', '.join(cgroups_to_init))
            for cgroup_to_init in cgroups_to_init:
                makedirs(cgroup_to_init, exist_ok=True)
        elif __stdin__.isatty():
            logger.info('Initializing cgroup: %s', ', '.join(cgroups_to_init))
            call(['sudo', 'sh', '-c', 'mkdir -p "{1}" && chown -R "{0}" "{1}"'.format(
                euid, '" "'.join(cgroups_to_init))])
        else:
            logger.error('Cgroup not initialized')

class CGroup:
    def __init__(self):
        self.cgroup2 = use_cgroup2()
        if self.cgroup2:
            self.cgroup2_dir = mkdtemp(prefix='', dir=CGROUP2_ROOT)
        else:
            self.cpuacct_cgroup_dir = mkdtemp(prefix='', dir=CPUACCT_CGROUP_ROOT)
            self.memory_cgroup_dir = mkdtemp(prefix='', dir=MEMORY_CGROUP_ROOT)
            self.pids_cgroup_dir = mkdtemp(prefix='', dir=PIDS_CGROUP_ROOT)

    def close(self):
        if self.cgroup2:
            rmdir(self.cgroup2_dir)
        else:
            rmdir(self.cpuacct_cgroup_dir)
            rmdir(self.memory_cgroup_dir)
            rmdir(self.pids_cgroup_dir)

    async def accept(self, sock):
        loop = get_event_loop()
        accept_sock, _ = await loop.sock_accept(sock)
        try:
            pid = accept_sock.getsockopt(SOL_SOCKET, SO_PEERCRED)
            if self.cgroup2:
                write_text_file(path.join(self.cgroup2_dir, 'cgroup.procs'),
                                str(pid))
            else:
                write_text_file(path.join(self.cpuacct_cgroup_dir, 'tasks'), str(pid))
                write_text_file(path.join(self.memory_cgroup_dir, 'tasks'), str(pid))
                write_text_file(path.join(self.pids_cgroup_dir, 'tasks'), str(pid))
        finally:
            # Always release the peer, which stays blocked in enter_cgroup()
            # until this socket is closed.
            accept_sock.close()

    @property
    def procs(self):
        if self.cgroup2:
            return set(map(int, read_text_file(
                path.join(self.cgroup2_dir, 'cgroup.procs')).splitlines()))
        return set(chain(
            map(int, read_text_file(path.join(self.cpuacct_cgroup_dir, 'cgroup.procs')).splitlines()),
            map(int, read_text_file(path.join(self.memory_cgroup_dir, 'cgroup.procs')).splitlines()),
            map(int, read_text_file(path.join(self.pids_cgroup_dir, 'cgroup.procs')).splitlines())))

    def kill(self):
        procs = self.procs
        if procs:
            for pid in procs:
                try:
                    kill(pid, SIGKILL)
                except ProcessLookupError:
                    pass
            return True
        else:
            return False

    @property
    def cpu_usage_ns(self):
        if self.cgroup2:
            # The first line of cpu.stat is 'usage_usec <microseconds>'.
            return int(read_text_file(
                path.join(self.cgroup2_dir, 'cpu.stat')).split()[1]) * 1000
        return int(read_text_file(path.join(self.cpuacct_cgroup_dir, 'cpuacct.usage')))

    @property
    def memory_limit_bytes(self):
        if self.cgroup2:
            return int(read_text_file(path.join(self.cgroup2_dir, 'memory.max')))
        return int(read_text_file(path.join(self.memory_cgroup_dir, 'memory.limit_in_bytes')))

    @memory_limit_bytes.setter
    def memory_limit_bytes(self, value):
        if self.cgroup2:
            write_text_file(path.join(self.cgroup2_dir, 'memory.max'), str(value))
        else:
            write_text_file(path.join(self.memory_cgroup_dir, 'memory.limit_in_bytes'), str(value))

    @property
    def memory_usage_bytes(self):
        if self.cgroup2:
            return int(read_text_file(path.join(self.cgroup2_dir, 'memory.peak')))
        return int(read_text_file(path.join(self.memory_cgroup_dir, 'memory.max_usage_in_bytes')))

    @property
    def pids_max(self):
        if self.cgroup2:
            return int(read_text_file(path.join(self.cgroup2_dir, 'pids.max')))
        return int(read_text_file(path.join(self.pids_cgroup_dir, 'pids.max')))

    @pids_max.setter
    def pids_max(self, value):
        if self.cgroup2:
            write_text_file(path.join(self.cgroup2_dir, 'pids.max'), str(value))
        else:
            write_text_file(path.join(self.pids_cgroup_dir, 'pids.max'), str(value))

def enter_cgroup(socket_path):
    with socket(AF_UNIX, SOCK_STREAM) as sock:
        sock.connect(socket_path)
        sock.recv(1)

def _get_idle():
    return float(read_text_file('/proc/uptime').split()[1])

async def wait_cgroup(sock, execute_task, cpu_limit_ns, idle_limit_ns,
                      memory_limit_bytes, process_limit):
    cgroup = CGroup()
    try:
        cgroup.memory_limit_bytes = memory_limit_bytes
        cgroup.pids_max = process_limit
        # accept() must not block forever: a peer which never shows up would
        # never be killed, and the caller would wait for it indefinitely.
        await wait_for(cgroup.accept(sock),
                       (min(cpu_limit_ns, idle_limit_ns) + WAIT_JITTER_NS) / 1e9)
        start_idle = _get_idle()

        while True:
            cpu_usage_ns = cgroup.cpu_usage_ns
            cpu_remain_ns = cpu_limit_ns - cpu_usage_ns
            if cpu_remain_ns <= 0:
                return cpu_usage_ns, cgroup.memory_usage_bytes
            idle_usage_ns = int((_get_idle() - start_idle) / cpu_count() * 1e9)
            idle_remain_ns = idle_limit_ns - idle_usage_ns
            if idle_remain_ns <= 0:
                return idle_usage_ns, cgroup.memory_usage_bytes
            try:
                await wait_for(shield(execute_task),
                               (min(cpu_remain_ns, idle_remain_ns) + WAIT_JITTER_NS) / 1e9)
                return cgroup.cpu_usage_ns, cgroup.memory_usage_bytes
            except TimeoutError:
                pass
    except BaseException:
        # Otherwise the task process may stay blocked in enter_cgroup() forever,
        # waiting for a connection that is never accepted, and the caller of this
        # coroutine hangs waiting for that process.
        sock.close()
        raise
    finally:
        while cgroup.kill():
            await sleep(.001)
        cgroup.close()
