#!/usr/bin/env python3

import argparse
import contextlib
import errno
import glob
import gzip
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request

try:
    import pwd
except ImportError:  # not available on Windows
    pwd = None

SCRIPT_VERSION = "0.2.0"
TRACKER_DATE = "2026-11-20"

VULN = "VULNERABLE"
SAFE = "not vulnerable"
MANUAL = "manual check"

ENTRIES = {
    "Ruby2Shell": "CVE-2026-132825",
    "NGINX2Shell": "CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, "
                   "CVE-2026-121810, CVE-2026-113425",
    "Java2Shell": "CVE-2026-114938",
    "4EverAble2Shell": "CVE-2026-90436 (first stage)",
    "Able2Shell": "CVE-2026-125878 to CVE-2026-125883, CVE-2026-91000",
    "Node2Shell": "CVE-2026-111497",
    "PHP2Shell": "CVE-2026-109618, CVE-2026-109619",
    "Plex2Shell": "CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656",
    "Comment2Shell": "CVE-2026-93485",
    "KindaRails2Shell": "CVE-2026-66066",
    "WP2Shell": "CVE-2026-63030, CVE-2026-60137",
}

# Where to look for WordPress installs and Rails apps (Gemfile.lock).
SEARCH_ROOTS = ["/var/www", "/srv", "/usr/share/nginx", "/usr/share/wordpress",
                "/opt", "/home", "/app"]
SEARCH_DEPTH = 5
PRUNE_DIRS = {"node_modules", "wp-content", "vendor", "cache", "tmp", "log",
              "logs", "proc", "sys"}

FINDINGS = []
FAILED_CHECKS = []
NOTES = []  # limits of this particular scan, shown in the summary and in JSON
COLOR = False
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
NOBODY = (65534, 65534)


# ---------------------------------------------------------------- output

def paint(text, code):
    return "\033[{}m{}\033[0m".format(code, text) if COLOR else text


def red(text):
    return paint(text, "1;31")


def green(text):
    return paint(text, "1;32")


def yellow(text):
    return paint(text, "1;33")


def bold(text):
    return paint(text, "1")


def dim(text):
    return paint(text, "2")


def verdict_tag(verdict):
    return {VULN: red(VULN), SAFE: green(SAFE), MANUAL: yellow(MANUAL)}[verdict]


def section(num, total, title, entries):
    print()
    print(bold("[{}/{}] {}".format(num, total, title)) + dim("  (" + ", ".join(entries) + ")"))


def info(text):
    print("    " + dim(text))


_CONTAINER_SEEN = {}
_REPEATS = {}  # container label -> findings in the current check that repeat an earlier one


def record(entry, component, version, location, verdict, detail="", root=None, pids=None,
           extra=None):
    container = root.label if root is not None and not root.host else ""
    finding = {"entry": entry, "component": component, "version": version,
               "location": "{}:{}".format(container, location) if container else location,
               "path": location, "container": container, "also_in": [],
               "verdict": verdict, "detail": detail, "pids": sorted(set(pids or []))}
    if extra:
        finding.update(extra)
    if container:
        # Replicas of one image give identical findings: keep one, list the others.
        key = (entry, component, version, location, verdict, detail)
        first = _CONTAINER_SEEN.get(key)
        if first is not None:
            first["also_in"].append(container)
            first["pids"] = sorted(set(first["pids"] + finding["pids"]))
            _REPEATS[container] = _REPEATS.get(container, 0) + 1
            return
        _CONTAINER_SEEN[key] = finding
    FINDINGS.append(finding)
    label = "{} {}".format(component, version) if version else component
    running = "  " + dim("(running)") if finding["pids"] else ""
    print("    - {} at {} -> {}  {}{}".format(label, finding["location"], verdict_tag(verdict),
                                           dim("[" + entry + "]"), running))
    if verdict == SAFE and detail:
        # Vulnerable and manual items get their detail in the summary. Without
        # this, a note on a safe item would never be shown.
        for line in textwrap.wrap(detail, 72):
            print("      " + dim(line))


# ---------------------------------------------------------------- helpers

def drop_to(path):
    if not IS_ROOT:
        return None
    real = os.path.realpath(path)
    try:
        for target in (path, real, os.path.dirname(os.path.abspath(path)),
                       os.path.dirname(real)):
            meta = os.lstat(target)
            if meta.st_uid != 0:
                return meta.st_uid, meta.st_gid
            if not stat.S_ISLNK(meta.st_mode) and meta.st_mode & 0o022:
                return NOBODY
    except OSError:
        return NOBODY
    return None


def switch_user(uid, gid):
    def switch():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    return switch


def run(cmd, timeout=15):
    env = dict(os.environ, LC_ALL="C", LANG="C")
    extra = {}
    drop = drop_to(shutil.which(cmd[0]) or cmd[0])
    if drop:
        extra["preexec_fn"] = switch_user(*drop)
        try:
            user = pwd.getpwuid(drop[0])
            env.update(HOME=user.pw_dir, USER=user.pw_name, LOGNAME=user.pw_name)
        except (KeyError, AttributeError):
            env.update(HOME="/", USER="nobody", LOGNAME="nobody")
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, cwd="/",
                              env=env, **extra)
    except (OSError, subprocess.SubprocessError, ValueError):
        return 1, ""
    return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")


def output(cmd, timeout=15):
    return run(cmd, timeout)[1]


def vtuple(text, parts=None):
    match = re.search(r"\d+(?:\.\d+)*", text or "")
    if not match:
        return None
    nums = tuple(int(x) for x in match.group(0).split("."))
    return nums[:parts] if parts else nums


def vcmp(a, b):
    width = max(len(a), len(b))
    a = tuple(a) + (0,) * (width - len(a))
    b = tuple(b) + (0,) * (width - len(b))
    return (a > b) - (a < b)


def lt(a, b):
    return vcmp(a, b) < 0


def in_range(v, low, high):
    return vcmp(v, low) >= 0 and vcmp(v, high) < 0


def vstr(v):
    return ".".join(str(x) for x in v)


_HOMES = None


def home_dirs():
    global _HOMES
    if _HOMES is None:
        homes = [os.path.expanduser("~")]
        if IS_ROOT:
            try:
                homes.extend(user.pw_dir for user in pwd.getpwall())
            except (AttributeError, KeyError, OSError):
                pass
            homes.extend(sorted(glob.glob("/home/*")))
        _HOMES, seen = [], set()
        for home in homes:
            real = os.path.realpath(home) if home else ""
            if real in ("", "/") or real in seen or not os.path.isdir(real):
                continue
            seen.add(real)
            _HOMES.append(home)
    return _HOMES


def expand_home(pattern):
    if not pattern.startswith("~/"):
        return [pattern]
    return [os.path.join(home, pattern[2:]) for home in home_dirs()]


BIN_DIRS = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]

# Process names of the runtimes this script tracks.
RUNTIME_KINDS = [
    ("ruby", re.compile(r"^ruby[\d.]*$")),
    ("nginx", re.compile(r"^(nginx|openresty)$")),
    ("java", re.compile(r"^java$")),
    ("node", re.compile(r"^(node|nodejs)$")),
    ("bun", re.compile(r"^bun$")),
    ("dotnet", re.compile(r"^dotnet$")),
    ("php", re.compile(r"^(ls)?php(-fpm|-cgi)?[\d.]*$")),
    ("python", re.compile(r"^python[\d.]*$")),
]


def runtime_kind(path):
    name = os.path.basename(path)
    for kind, pattern in RUNTIME_KINDS:
        if pattern.match(name):
            return kind
    return None


def root_glob(root, pattern):
    if root.host:
        return sorted(glob.glob(pattern))
    cut = len(root.prefix)
    return sorted(path[cut:] for path in glob.glob(root.prefix + pattern))


def home_patterns(root, pattern):
    if root.host:
        return expand_home(pattern)
    if pattern.startswith("~/"):
        return ["/root/" + pattern[2:], "/home/*/" + pattern[2:]]
    return [pattern]


def find_runtime(root, kind, names, patterns=(), name_re=None):
    if root.host:
        candidates = [shutil.which(name) for name in names]
    else:
        candidates = [folder + "/" + name for folder in BIN_DIRS for name in names]
    for pattern in patterns:
        for expanded in home_patterns(root, pattern):
            candidates.extend(root_glob(root, expanded))
    candidates.extend(proc["exe"] for proc in root.procs
                      if not proc["deleted"] and runtime_kind(proc["exe"]) == kind)
    found, seen = [], set()
    for path in candidates:
        if not path or (name_re and not re.match(name_re, os.path.basename(path))):
            continue
        real = resolve_in(root.prefix, path)
        if not real or real in seen or not os.path.isfile(real) or not os.access(real, os.X_OK):
            continue
        seen.add(real)
        found.append((path, real, root.exe_pids(real)))
    return found


def owning_package(path):
    real = os.path.realpath(path)
    if shutil.which("dpkg-query"):
        code, out = run(["dpkg-query", "-S", real])
        if code == 0 and ": " in out:
            pkg = out.splitlines()[0].split(": ")[0].split(",")[0].strip()
            ver = output(["dpkg-query", "-W", "-f=${Version}", pkg]).strip()
            return "dpkg", pkg, "{} {}".format(pkg, ver).strip()
    if shutil.which("rpm"):
        code, out = run(["rpm", "-qf", real])
        if code == 0 and out.strip():
            pkg = out.strip().splitlines()[0]
            return "rpm", pkg, pkg
    if shutil.which("apk"):
        code, out = run(["apk", "info", "--who-owns", real])
        match = re.search(r"is owned by (\S+)", out)
        if code == 0 and match:
            return "apk", match.group(1), match.group(1)
    return None


def package_changelog(manager, pkg):
    if manager == "dpkg":
        for filename in ("changelog.Debian.gz", "changelog.gz"):
            path = os.path.join("/usr/share/doc", pkg.split(":")[0], filename)
            try:
                with gzip.open(path, "rb") as handle:
                    return handle.read(5000000).decode("utf-8", "replace")
            except (OSError, EOFError):
                continue
    elif manager == "rpm":
        return output(["rpm", "-q", "--changelog", pkg], 30)
    return ""


def distro_check(verdict, detail, path, cves, root=None):
    if verdict != VULN:
        return verdict, detail
    if root is not None and not root.host:
        # No package database or changelog is consulted inside a container.
        if path.startswith(OS_DIRS):
            detail = (detail + " It sits where the image's OS packages install, and package "
                      "changelogs aren't checked inside a container, so a backported fix "
                      "would not show here.").strip()
        return verdict, detail
    owner = owning_package(path)
    if not owner:
        return verdict, detail
    manager, pkg, label = owner
    wanted = re.findall(r"CVE-\d+-\d+", cves)
    changelog = package_changelog(manager, pkg)
    listed = [cve for cve in wanted if re.search(re.escape(cve) + r"(?!\d)", changelog)]
    missing = [cve for cve in wanted if cve not in listed]
    if wanted and not missing:
        return SAFE, ("The upstream version is in the affected range, but the OS package {} "
                      "names {} as fixed in its changelog (distro backport)."
                      .format(label, ", ".join(wanted)))
    if listed:
        return MANUAL, ("{} The OS package {} names a fix for {} in its changelog but not for "
                        "{}. Check your distro's advisory."
                        .format(detail, label, ", ".join(listed), ", ".join(missing)).strip())
    if changelog:
        return VULN, ("{} Installed from the OS package {}, whose changelog doesn't mention "
                      "{}, so it looks unpatched. Confirm against your distro's advisory."
                      .format(detail, label, ", ".join(wanted)).strip())
    return VULN, ("{} Installed from the OS package {}. Distros often backport fixes without "
                  "changing the upstream version, and this package's changelog couldn't be "
                  "read, so confirm against your distro's advisory for {}."
                  .format(detail, label, cves).strip())


class LoopbackRedirects(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = urllib.parse.urlsplit(newurl).hostname
        if host not in ("127.0.0.1", "localhost", "::1"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url, timeout=4):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ctx),
                                         LoopbackRedirects())
    request = urllib.request.Request(url, headers={"User-Agent": "something2shell-check"})
    try:
        with opener.open(request, timeout=timeout) as resp:
            return resp.read(2000000).decode("utf-8", "replace")
    except Exception:
        return None


_APPS = {}


def file_in(root, path):
    real = resolve_in(root.prefix, path)
    return real if real and os.path.isfile(real) else None


def find_apps(root):
    if root.prefix in _APPS:
        return _APPS[root.prefix]
    wordpress, lockfiles, venvs, seen = [], [], [], set()
    cut = len(root.prefix)
    for search_root in SEARCH_ROOTS:
        top = resolve_in(root.prefix, search_root)
        if not top or not os.path.isdir(top):
            continue
        base = top.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(top):
            real = os.path.realpath(dirpath) if root.host else dirpath
            if real in seen:
                dirnames[:] = []
                continue
            seen.add(real)
            inner = dirpath[cut:] or "/"
            for name in list(dirnames):
                # Any directory holding pyvenv.cfg is a virtualenv, hidden ones included.
                if file_in(root, os.path.join(inner, name, "pyvenv.cfg")):
                    venvs.append(os.path.join(inner, name))
                    dirnames.remove(name)
            if file_in(root, os.path.join(inner, "wp-includes", "version.php")):
                wordpress.append(inner)
                dirnames[:] = []
                continue
            if "Gemfile.lock" in filenames:
                lockfiles.append(os.path.join(inner, "Gemfile.lock"))
                dirnames[:] = []
                continue
            depth = dirpath.count(os.sep) - base
            if depth >= SEARCH_DEPTH:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames
                               if d not in PRUNE_DIRS and not d.startswith(".")]
    _APPS[root.prefix] = (wordpress, lockfiles, venvs)
    return _APPS[root.prefix]


def read_text(path, limit=5000000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


# ---------------------------------------------------------------- processes, containers, reading without running

OS_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/lib", "/bin/", "/sbin/", "/lib")
TRACKED_LIBS = ("libbrotlidec", "libphp", "mod_php", "libjvm", "libruby")


class Root(object):
    def __init__(self, prefix, label, procs):
        self.prefix, self.label, self.procs = prefix, label, procs
        self._exes = self._libs = None

    @property
    def host(self):
        return not self.prefix

    def exe_pids(self, real):
        if self._exes is None:
            self._exes = {}
            for proc in self.procs:
                target = None if proc["deleted"] else resolve_in(self.prefix, proc["exe"])
                if target:
                    self._exes.setdefault(target, []).append(proc["pid"])
        return self._exes.get(real, [])

    def lib_pids(self, real):
        if self._libs is None:
            self._libs = {}
            for proc in self.procs:
                for lib, gone in proc["libs"]:
                    target = None if gone else resolve_in(self.prefix, lib)
                    if target:
                        self._libs.setdefault(target, []).append(proc["pid"])
        return self._libs.get(real, [])


def resolve_in(prefix, path):
    if not prefix:
        real = os.path.realpath(path)
        return real if os.path.exists(real) else None
    todo = [part for part in path.split("/") if part and part != "."]
    done, hops = [], 0
    while todo:
        part = todo.pop(0)
        if part == "..":
            if done:
                done.pop()
            continue
        current = prefix + "/" + "/".join(done + [part])
        try:
            meta = os.lstat(current)
            if stat.S_ISLNK(meta.st_mode):
                hops += 1
                if hops > 40:
                    return None
                target = os.readlink(current)
                if target.startswith("/"):
                    done = []
                todo = [p for p in target.split("/") if p and p != "."] + todo
                continue
        except OSError:
            return None
        done.append(part)
    return prefix + "/" + "/".join(done)


def scan_processes():
    procs, denied = [], 0
    try:
        names = os.listdir("/proc")
    except OSError:
        return procs
    for name in names:
        if not name.isdigit() or int(name) == os.getpid():
            continue
        base = "/proc/" + name
        try:
            exe = os.readlink(base + "/exe")
            meta = os.stat(base + "/root")
            rootlink = os.readlink(base + "/root")
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                denied += 1
            continue  # otherwise a kernel thread, or the process has just exited
        # A chroot in our own mount namespace reports host paths: cut its directory off.
        cut = rootlink + "/" if rootlink != "/" else ""

        def inside(path):
            return path[len(cut) - 1:] if cut and path.startswith(cut) else path

        proc = {"pid": int(name), "exe": exe, "deleted": exe.endswith(" (deleted)"),
                "root_id": (meta.st_dev, meta.st_ino), "libs": [], "argv": [], "venv": ""}
        if proc["deleted"]:
            proc["exe"] = exe[:-len(" (deleted)")]
        proc["exe"] = inside(proc["exe"])
        try:
            with open(base + "/maps", "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if not any(lib in line for lib in TRACKED_LIBS):
                        continue
                    fields = line.rstrip("\n").split(None, 5)
                    if len(fields) < 6 or not fields[5].startswith("/"):
                        continue
                    gone = fields[5].endswith(" (deleted)")
                    path = inside(fields[5][:-len(" (deleted)")] if gone else fields[5])
                    if (path, gone) not in proc["libs"]:
                        proc["libs"].append((path, gone))
            with open(base + "/cmdline", "rb") as handle:
                proc["argv"] = [arg.decode("utf-8", "replace")
                                for arg in handle.read(8192).split(b"\0") if arg]
            if runtime_kind(proc["exe"]) == "python":
                with open(base + "/environ", "rb") as handle:
                    match = re.search(rb"(?:^|\0)VIRTUAL_ENV=([^\0]+)", handle.read(200000))
                    if match:
                        proc["venv"] = match.group(1).decode("utf-8", "replace")
        except OSError:
            pass
        procs.append(proc)
    if denied:
        NOTES.append("{} running process(es) could not be inspected{}.".format(
            denied, "" if IS_ROOT else " because they belong to other users; run as root to "
                                       "include them and their containers"))
    return procs


def container_label(pid, prefix):
    ids = re.findall(r"[0-9a-f]{64}", read_text("/proc/{}/cgroup".format(pid), 20000))
    hostname = resolve_in(prefix, "/etc/hostname")
    name = re.match(r"[\w.-]{1,64}", read_text(hostname, 200).strip() if hostname else "")
    name = name.group(0) if name else ""
    if ids and name and not ids[-1].startswith(name):
        return "container {} ({})".format(name, ids[-1][:12])
    if ids:
        return "container {}".format(ids[-1][:12])
    return "isolated root {}(pid {})".format(name + " " if name else "", pid)


_ROOTS = None


def roots():
    global _ROOTS
    if _ROOTS is not None:
        return _ROOTS
    try:
        procs = scan_processes()
        meta = os.stat("/")
        host_id = (meta.st_dev, meta.st_ino)
    except Exception as exc:  # the scan still works without the process view
        NOTES.append("Running processes could not be read ({}).".format(exc))
        procs, host_id = [], None
    groups = {}
    for proc in procs:
        groups.setdefault(proc["root_id"], []).append(proc)
    _ROOTS = [Root("", "", groups.pop(host_id, []))]
    for root_id in sorted(groups, key=lambda key: min(proc["pid"] for proc in groups[key])):
        members = sorted(groups[root_id], key=lambda proc: proc["pid"])
        prefix = "/proc/{}/root".format(members[0]["pid"])
        _ROOTS.append(Root(prefix, container_label(members[0]["pid"], prefix), members))
    return _ROOTS


def only(items):
    return items[0] if len(items) == 1 else ""


def cant_read(root):
    if root.host:
        return "Couldn't read the version."
    return ("Couldn't read the version from the file. Files in containers are never run, "
            "so check this one by hand.")


_SCANS = {}


def scan_file(path, pattern, limit=400 * 1024 * 1024):
    try:
        meta = os.stat(path)
    except OSError:
        return []
    if not stat.S_ISREG(meta.st_mode):
        return []
    key = (os.path.basename(path), meta.st_size, meta.st_mtime, pattern.pattern)
    if key in _SCANS:
        return _SCANS[key]
    found, tail, read, size = set(), b"", 0, 8 * 1024 * 1024
    try:
        with open(path, "rb") as handle:
            while read < limit:
                chunk = handle.read(size)
                read += len(chunk)
                data = tail + chunk
                # A match touching the end of a chunk may be cut short: leave it for the next round.
                edge = len(data) - 128 if len(chunk) == size else len(data)
                found.update(match.group(1) for match in pattern.finditer(data)
                             if match.end() <= edge)
                if len(chunk) < size:
                    break
                tail = data[-512:]
    except OSError:
        pass
    _SCANS[key] = sorted(item.decode("ascii", "replace") for item in found)
    return _SCANS[key]


# Version strings that these programs carry inside their own files.
MARK_NGINX = re.compile(rb"((?:nginx|openresty)/\d+\.\d+\.\d+(?:\.\d+)?)(?![\d.])")
MARK_NGINX_PLUS = re.compile(rb"\((nginx-plus-[\w-]+)\)")
MARK_NGINX_CONF = re.compile(rb"--conf-path=([^\s\0']+)")
MARK_NGINX_PREFIX = re.compile(rb"--prefix=([^\s\0']+)")
MARK_PHP = re.compile(rb"X-Powered-By: PHP/(\d+\.\d+\.\d+)")
MARK_NODE = re.compile(rb"node-v(\d+\.\d+\.\d+)-headers")
MARK_BUN = re.compile(rb"Bun/(\d+\.\d+\.\d+)(?![\d.])")
MARK_RUBY = re.compile(rb"ruby (\d+\.\d+\.\d+)(?:p\d+)? \(\d{4}-\d\d-\d\d")
MARK_RUBY_LIB = re.compile(rb"(libruby[\w.-]*\.so\.[\d.]*\d)")
MARK_SHARED_BROTLI = re.compile(rb"(libbrotlidec\.so)")


def static_nginx_text(real):
    marks = scan_file(real, MARK_NGINX)
    pick = only([mark for mark in marks if mark.startswith("openresty/")] or marks)
    if not pick:
        return ""
    plus = only(scan_file(real, MARK_NGINX_PLUS))
    return "nginx version: {}{}".format(pick, " ({})".format(plus) if plus else "")


def static_ruby_version(root, real):
    version = only(scan_file(real, MARK_RUBY))
    if version:
        return version
    inner = real[len(root.prefix):]
    folders = [os.path.join(os.path.dirname(os.path.dirname(inner)), "lib"), "/usr/local/lib",
               "/usr/lib", "/usr/lib64", "/usr/lib/*-linux-gnu"]
    versions = set()
    for libname in scan_file(real, MARK_RUBY_LIB):
        for folder in folders:
            for candidate in root_glob(root, folder + "/" + libname + "*"):
                lib = file_in(root, candidate)
                if lib:
                    versions.update(scan_file(lib, MARK_RUBY))
    return only(sorted(versions))


def java_home(root, real):
    folder = os.path.dirname(real)
    for _ in range(6):
        if folder == "/" or len(folder) <= len(root.prefix):
            break
        release = os.path.join(folder, "release")
        if os.path.isfile(release) and not os.path.islink(release):
            match = re.search(r'^JAVA_VERSION="([^"]+)"', read_text(release, 20000), re.M)
            if match:
                return folder, match.group(1)
        folder = os.path.dirname(folder)
    return "", ""


# ---------------------------------------------------------------- version rules

def eval_ruby(v):
    fixes = {(3, 3): (3, 3, 14), (3, 4): (3, 4, 13), (4, 0): (4, 0, 10)}
    if lt(v, (2, 4, 0)):
        return SAFE, "Older than 2.4.0, which predates the bug."
    branch = v[:2]
    if branch in fixes:
        if lt(v, fixes[branch]):
            return VULN, "Fixed in Ruby {}.".format(vstr(fixes[branch]))
        return SAFE, ""
    if vcmp(branch, (4, 0)) > 0:
        return SAFE, ""
    return VULN, "End-of-life branch with no fix. Move to Ruby 3.3.14, 3.4.13 or 4.0.10."


def eval_nginx(v):
    fixes = {(1, 30): (1, 30, 7), (1, 31): (1, 31, 9)}
    if lt(v, (0, 5, 33)):
        return SAFE, "Older than 0.5.33, outside the affected range."
    branch = v[:2]
    if branch in fixes:
        if lt(v, fixes[branch]):
            return VULN, ("Fixed in nginx {}. Turning off HTTP/2 covers only "
                          "CVE-2026-123007 and CVE-2026-123633.".format(vstr(fixes[branch])))
        return SAFE, ""
    if vcmp(branch, (1, 31)) > 0:
        return SAFE, ""
    detail = ("Branch has no fix. Move to nginx 1.30.7 (stable) or 1.31.9 (mainline). "
              "Some of the five CVEs only apply with certain configurations "
              "(HTTP/2, HTTP/3, resolver, mail proxy).")
    if lt(v, (1, 9, 5)):
        detail += " CVE-2026-123007 itself needs 1.9.5 or later."
    return VULN, detail


def cpu_has_avx512_vbmi():
    if platform.machine().lower() not in ("x86_64", "amd64"):
        return False
    text = read_text("/proc/cpuinfo", 200000)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("flags"):
            return "avx512vbmi" in line.split()
    return None


def eval_java(v, raw):
    major = v[1] if v[0] == 1 and len(v) > 1 else v[0]
    fixes = {17: (17, 0, 21, 1), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}
    if major < 17:
        if major == 8 and "perf" in raw.lower():
            update = re.search(r"(?:_|8u)(\d+)", raw)
            if not update:
                return MANUAL, ("Oracle Java SE 8 Enterprise Performance Pack builds are "
                                "affected. Check Oracle's November 2026 Critical Patch Update.")
            if int(update.group(1)) < 513:
                return VULN, ("Oracle Java SE 8 Enterprise Performance Pack build, which "
                              "carries the affected decoder. Fixed in 8u513-perf.")
            return SAFE, ""
        return SAFE, "Java {} is not affected.".format(major)
    if major == 17 and lt(v, (17, 0, 6)):
        return SAFE, "Older than 17.0.6, which predates the affected code."
    if major in fixes:
        if lt(v, fixes[major]):
            return VULN, ("Fixed in {} (Oracle/OpenJDK numbering; other vendors use their "
                          "own build numbers, so check your vendor's advisory). Interim "
                          "mitigation: -XX:-UseBASE64Intrinsics.".format(vstr(fixes[major])))
        return SAFE, ""
    if major > 27:
        return SAFE, ""
    return VULN, ("Java {} is an end-of-life release with the same vulnerable code and no "
                  "fix. Move to 21.0.13.1, 25.0.5.1 or 27.0.1.1. Interim mitigation: "
                  "-XX:-UseBASE64Intrinsics.".format(major))


def node_has_brotli(v):
    return not (lt(v, (10, 16, 0)) or in_range(v, (11, 0, 0), (11, 7, 0)))


def eval_node(v):
    fixes = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
    if not node_has_brotli(v):
        return SAFE, "Predates Node's Brotli decoder (added in 10.16.0 and 11.7.0)."
    if v[0] in fixes:
        if lt(v, fixes[v[0]]):
            return VULN, "Fixed in Node.js {}.".format(vstr(fixes[v[0]]))
        return SAFE, ""
    if v[0] > 26:
        return SAFE, ""
    return VULN, "End-of-life release line with no fix. Move to Node.js 22.23.4, 24.22.1 or 26.12.1."


def eval_bun(v):
    if lt(v, (1, 0, 21)):
        return SAFE, "Older than 1.0.21, outside the affected range in Bun's advisory."
    if lt(v, (1, 4, 4)):
        return VULN, "Fixed in Bun 1.4.4, which bundles Brotli 1.2.1."
    return SAFE, ""


def brotli_affected(v):
    return (in_range(v, (1, 0, 3), (1, 0, 10)) or in_range(v, (1, 1, 0), (1, 1, 1))
            or in_range(v, (1, 2, 0), (1, 2, 1)))


def eval_dotnet(v):
    fixes = {8: (8, 0, 33), 9: (9, 0, 22), 10: (10, 0, 14)}
    if v[0] in fixes:
        if lt(v, fixes[v[0]]):
            return VULN, ("Fixed in .NET {}. Only exploitable where an app decompresses "
                          "Brotli data.".format(vstr(fixes[v[0]])))
        return SAFE, ""
    if v[0] > 10:
        return SAFE, ""
    if v[0] in (6, 7):
        return VULN, ("End-of-life .NET release with the same Brotli decoder and no fix. "
                      "Move to .NET 8.0.33, 9.0.22 or 10.0.14. Only exploitable where an "
                      "app decompresses Brotli data.")
    return MANUAL, "End-of-life .NET release that Microsoft's fix doesn't cover. Move to .NET 8, 9 or 10."


def eval_php(v):
    fixes = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
    latest = {(8, 2): (8, 2, 36), (8, 3): (8, 3, 37), (8, 4): (8, 4, 28), (8, 5): (8, 5, 13)}
    if lt(v, (5, 4, 0)):
        return MANUAL, "Older than 5.4, not covered by the advisories. Move to a supported release."
    branch = v[:2]
    if branch in fixes:
        if lt(v, fixes[branch]):
            return VULN, ("Fixed in PHP {}. Install {} (released 2026-11-19), which also "
                          "fixes related PHP bugs.".format(vstr(fixes[branch]), vstr(latest[branch])))
        if lt(v, latest[branch]):
            return SAFE, ("Consider PHP {} (2026-11-19), which also fixes CVE-2026-115560 "
                          "and CVE-2026-126714 (not tracked here).".format(vstr(latest[branch])))
        return SAFE, ""
    if vcmp(branch, (8, 5)) > 0:
        return SAFE, ""
    return VULN, ("End-of-life branch. Vulnerable unless your vendor applied PHP's official "
                  "backport; move to PHP 8.2.36 or later.")


def eval_plex(v):
    if lt(v, (1, 43, 3, 10861)):
        return VULN, "Fixed in Plex Media Server 1.43.3.10861."
    return SAFE, ""


WP_COMMENT2SHELL_FIXES = {
    (7, 1): (7, 1, 1), (7, 0): (7, 0, 5), (6, 9): (6, 9, 8), (6, 8): (6, 8, 9),
    (6, 7): (6, 7, 8), (6, 6): (6, 6, 8), (6, 5): (6, 5, 11), (6, 4): (6, 4, 11),
    (6, 3): (6, 3, 11), (6, 2): (6, 2, 12), (6, 1): (6, 1, 13), (6, 0): (6, 0, 15),
    (4, 7): (4, 7, 36),
}


def eval_comment2shell(v):
    branch = v[:2]
    if lt(branch, (4, 7)):
        return SAFE, ("Older than 4.7, outside the affected range. This branch gets no "
                      "security updates at all, so upgrading is still advised.")
    if vcmp(branch, (7, 1)) > 0:
        return SAFE, ""
    if branch in WP_COMMENT2SHELL_FIXES:
        fix = WP_COMMENT2SHELL_FIXES[branch]
        if lt(v, fix):
            return VULN, "Fixed in WordPress {} (released 2026-09-17).".format(vstr(fix))
        return SAFE, ""
    return MANUAL, ("Branch {} is affected. Update to the latest release on this branch; "
                    "WordPress backported the fix to every branch from 4.7.".format(vstr(branch)))


def eval_wp2shell(v):
    if in_range(v, (6, 9, 0), (6, 9, 5)) or in_range(v, (7, 0, 0), (7, 0, 2)):
        return VULN, "Full chain. Fixed in WordPress 6.9.5 / 7.0.2."
    if in_range(v, (6, 8, 0), (6, 8, 6)):
        return VULN, ("Only CVE-2026-60137 (SQL injection) applies on 6.8, not the full chain. "
                      "Fixed in WordPress 6.8.6.")
    return SAFE, ""


def eval_activestorage(v):
    fixes = {(8, 1): (8, 1, 3, 1), (8, 0): (8, 0, 5, 1), (7, 2): (7, 2, 3, 2)}
    exposure = (" Exposure also needs the vips variant processor (the default since "
                "Rails 7.0) and uploads from untrusted users. Update libvips to 8.13+ "
                "and rotate secrets if the app was exposed.")
    branch = v[:2]
    if branch in fixes:
        if lt(v, fixes[branch]):
            return VULN, "Fixed in Active Storage {}.".format(vstr(fixes[branch])) + exposure
        return SAFE, ""
    if vcmp(branch, (8, 1)) > 0:
        return SAFE, ""
    if branch in ((7, 0), (7, 1)):
        return VULN, "No fix on this branch. Move to Rails 7.2.3.2 or later." + exposure
    return MANUAL, ("Rails {}.x is affected only if Active Storage was set up to use "
                    "libvips, which isn't the default. Check "
                    "config.active_storage.variant_processor.".format(v[0]))


# ---------------------------------------------------------------- checks

def check_ruby():
    entry, cve = "Ruby2Shell", ENTRIES["Ruby2Shell"]
    patterns = ["/usr/bin/ruby*", "/usr/local/bin/ruby*", "/opt/*/embedded/bin/ruby",
                "~/.rbenv/versions/*/bin/ruby", "~/.rvm/rubies/*/bin/ruby",
                "/usr/local/rvm/rubies/*/bin/ruby", "/opt/rubies/*/bin/ruby"]
    count = 0
    for root in roots():
        for path, real, pids in find_runtime(root, "ruby", ["ruby"], patterns,
                                             name_re=r"^ruby[\d.]*$"):
            count += 1
            match = re.search(r"ruby (\d+\.\d+\.\d+)", output([path, "-v"]) if root.host else "")
            version = match.group(1) if match else static_ruby_version(root, real)
            if not version:
                record(entry, "Ruby", "", path, MANUAL, cant_read(root), root, pids)
                continue
            verdict, detail = distro_check(*eval_ruby(vtuple(version)), path, cve, root)
            record(entry, "Ruby", version, path, verdict, detail, root, pids)
    return count


# First affected nginx release for each CVE, as listed by nginx.org.
NGINX_FIRST_AFFECTED = {
    "CVE-2026-123007": (1, 9, 5), "CVE-2026-123633": (1, 19, 7),
    "CVE-2026-123634": (0, 6, 18), "CVE-2026-121810": (1, 25, 0),
    "CVE-2026-113425": (0, 5, 33),
}

# What has to be switched on in the configuration for each CVE to be reachable.
NGINX_NEEDS = {
    "CVE-2026-123007": ("http2",),
    "CVE-2026-123633": ("http2", "upstream"),
    "CVE-2026-121810": ("http3", "upstream"),
    "CVE-2026-123634": ("resolver_with_variable_proxy_pass",),
    "CVE-2026-113425": ("mail_auth_http",),
}
NGINX_FEATURE_TEXT = {
    "http2": "HTTP/2 is enabled",
    "http3": "HTTP/3 is enabled",
    "upstream": "requests are passed to an upstream",
    "resolver_with_variable_proxy_pass": "a resolver is set and a proxy_pass target uses a variable",
    "mail_auth_http": "the mail proxy uses auth_http",
}
NGINX_DEFAULT_CONFS = ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf",
                       "/usr/local/openresty/nginx/conf/nginx.conf", "/etc/openresty/nginx.conf"]


def strip_nginx_comments(text):
    out, quote, i = [], "", 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                out.append(text[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def nginx_conf_paths(root, real, version_text):
    paths = []
    for proc in root.procs:
        if not proc["deleted"] and resolve_in(root.prefix, proc["exe"]) == real:
            match = re.search(r"\s-c\s+(\S+)", " " + " ".join(proc["argv"]))
            if match:
                paths.append(match.group(1))
    conf = re.search(r"--conf-path=(\S+)", version_text)
    conf = conf.group(1) if conf else only(scan_file(real, MARK_NGINX_CONF))
    home = re.search(r"--prefix=(\S+)", version_text)
    home = home.group(1) if home else only(scan_file(real, MARK_NGINX_PREFIX))
    if conf:
        paths.append(conf if conf.startswith("/") else os.path.join(home or "/usr/local/nginx", conf))
    elif home:
        paths.append(os.path.join(home, "conf/nginx.conf"))
    if not paths:
        paths = [conf for conf in NGINX_DEFAULT_CONFS if file_in(root, conf)][:1]
    return sorted(set(path for path in paths if path.startswith("/")))


def nginx_config(root, conf_paths):
    files, chunks, state = [], [], {"complete": bool(conf_paths)}

    def load(path, base, depth):
        target = file_in(root, path)
        if not target or depth > 12:
            state["complete"] = False
            return
        if target in files:
            return
        files.append(target)
        try:
            with open(target, "r", encoding="utf-8", errors="replace") as handle:
                text = strip_nginx_comments(handle.read(4000000))
        except OSError:
            state["complete"] = False
            return
        chunks.append(text)
        for include in re.findall(r"(?<![\w$])include\s+([^;]+);", text):
            pattern = include.strip().strip("\"'")
            if not pattern.startswith("/"):
                pattern = base + "/" + pattern
            matches = root_glob(root, pattern)
            if not matches and not re.search(r"[*?\[]", pattern):
                state["complete"] = False  # a named file that isn't there or can't be listed
            for match in matches:
                load(match, base, depth + 1)

    for conf in conf_paths:
        load(conf, os.path.dirname(conf), 0)
    conf = "\n".join(chunks)

    def has(pattern):
        return bool(re.search(r"(?<![\w$])" + pattern, conf))

    features = {
        "http2": has(r"listen\s[^;]*\shttp2(?=[\s;])") or has(r"http2\s+on\s*;"),
        "http3": has(r"listen\s[^;]*\s(?:quic|http3)(?=[\s;])"),
        "upstream": has(r"(?:proxy|fastcgi|uwsgi|scgi|grpc|memcached)_pass\s"),
        "resolver_with_variable_proxy_pass": (has(r"resolver\s+[^;\s]")
                                              and has(r"proxy_pass\s+[^;]*\$")),
        "mail_auth_http": has(r"mail\s*\{") and has(r"auth_http\s+[^;\s]"),
    }
    cut = len(root.prefix)
    return {"main": conf_paths, "files": [path[cut:] for path in files],
            "complete": state["complete"], "features": features}


def nginx_exposure(root, real, version_text, verdict, detail, applicable):
    config = nginx_config(root, nginx_conf_paths(root, real, version_text))
    extra = {"config": config}
    if not config["complete"]:
        config["exposed"] = applicable
        why = ("part of it could not be read" if config["files"]
               else "no configuration file was found")
        return verdict, ("{} The nginx configuration could not be checked ({}), so every CVE "
                         "for this version is assumed reachable.".format(detail, why)), extra
    # The configuration was read, so the general remark about it is no longer needed.
    detail = detail.replace(" Some of the five CVEs only apply with certain configurations "
                            "(HTTP/2, HTTP/3, resolver, mail proxy).", "")
    config["exposed"] = [cve for cve in applicable
                         if all(config["features"][need] for need in NGINX_NEEDS[cve])]
    source = "{} ({} file(s) read)".format(", ".join(config["main"]), len(config["files"]))
    if config["exposed"]:
        reasons = sorted(set(NGINX_FEATURE_TEXT[need] for cve in config["exposed"]
                             for need in NGINX_NEEDS[cve]))
        hidden = [cve for cve in applicable if cve not in config["exposed"]]
        tail = " Not reachable with this configuration: {}.".format(", ".join(hidden)) if hidden else ""
        return verdict, ("{} Configuration {}: reachable through {}, because {}.{}".format(
            detail, source, ", ".join(config["exposed"]), " and ".join(reasons), tail)), extra
    return SAFE, ("Affected version, but the configuration {} switches on none of the features "
                  "these CVEs need: HTTP/2, HTTP/3 with an upstream, a resolver with a variable "
                  "proxy_pass target, or the mail proxy with auth_http. Update anyway, because "
                  "enabling HTTP/2 later would expose it.".format(source)), extra


def check_nginx():
    entry = "NGINX2Shell"
    patterns = ["/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx",
                "/usr/local/openresty/nginx/sbin/nginx", "/usr/local/openresty/bin/openresty",
                "/opt/*/sbin/nginx"]
    count = 0
    for root in roots():
        for path, real, pids in find_runtime(root, "nginx", ["nginx", "openresty"], patterns):
            count += 1
            # -V prints the version and the build options, which name the configuration file.
            text = output([path, "-V"]) if root.host else ""
            match = re.search(r"(nginx|openresty)/(\d+(?:\.\d+)+)", text)
            if not match:
                text = static_nginx_text(real)
                match = re.search(r"(nginx|openresty)/(\d+(?:\.\d+)+)", text)
            if not match:
                record(entry, "nginx", "", path, MANUAL, cant_read(root), root, pids)
                continue
            flavour, version = match.group(1), match.group(2)
            if "nginx-plus" in text.lower():
                record(entry, "NGINX Plus", version, path, MANUAL,
                       "NGINX Plus fixes: 37.3.0.1 / 37.0.8.1 (CVE-2026-123007) and "
                       "37.2.0.1 / 37.0.7.1 (CVE-2026-123633). Compare with your release.",
                       root, pids)
                continue
            core = vtuple(version, 3)
            verdict, detail = eval_nginx(core)
            applicable = [cve for cve in sorted(NGINX_FIRST_AFFECTED)
                          if not lt(core, NGINX_FIRST_AFFECTED[cve])]
            component = "nginx"
            if flavour == "openresty":
                # An OpenResty version is <nginx core>.<OpenResty patch level>, and its
                # security releases keep the core version, so the core can't prove a fix.
                component = "OpenResty"
                if verdict == VULN:
                    verdict = MANUAL
                    detail = ("Bundles nginx core {}, which is in the affected range. OpenResty "
                              "ships security fixes without changing the core version, so check "
                              "OpenResty's advisory for {}.".format(vstr(core), ENTRIES[entry]))
            else:
                verdict, detail = distro_check(verdict, detail, path, ", ".join(applicable), root)
            extra = None
            if verdict != SAFE and applicable:
                verdict, detail, extra = nginx_exposure(root, real, text, verdict, detail,
                                                        applicable)
            record(entry, component, version, path, verdict, detail, root, pids, extra)
    return count


def java_verdict(raw, vbmi):
    v = vtuple(re.split(r"[+\-_ ]", raw)[0]) or vtuple(raw)
    if not v:
        return None
    verdict, detail = eval_java(v, raw)
    if verdict == VULN and vbmi is False:
        verdict = SAFE
        detail = ("Affected version, but this CPU has no AVX-512 VBMI support, so the "
                  "vulnerable code path isn't used here. Update anyway in case the "
                  "workload moves to other hardware.")
    return verdict, detail


def check_java():
    entry, cve = "Java2Shell", ENTRIES["Java2Shell"]
    patterns = ["/usr/lib/jvm/*/bin/java", "/usr/lib/jvm/*/jre/bin/java",
                "/usr/java/*/bin/java", "/opt/java/*/bin/java",
                "/opt/*/jre/bin/java", "/opt/*/jdk*/bin/java"]
    if os.environ.get("JAVA_HOME"):
        patterns.insert(0, os.path.join(os.environ["JAVA_HOME"], "bin", "java"))
    count, vbmi, told = 0, None, False
    for root in roots():
        targets, homes = [], set()
        for path, real, pids in find_runtime(root, "java", ["java"], patterns):
            match = re.search(r'version "([^"]+)"',
                              output([path, "-version"]) if root.host else "")
            home, release = java_home(root, real)
            homes.add(home)
            targets.append(("Java", path, pids, match.group(1) if match else release))
        # A JVM embedded in another program shows up only as a loaded libjvm.so.
        for proc in root.procs:
            for lib, gone in proc["libs"]:
                real = None if gone or "libjvm" not in lib else file_in(root, lib)
                home, release = java_home(root, real) if real else ("", "")
                if home and home not in homes:
                    homes.add(home)
                    targets.append(("Java (embedded JVM)", lib, root.lib_pids(real), release))
        if targets and not told:
            vbmi, told = cpu_has_avx512_vbmi(), True
            if vbmi is False:
                info("CPU: no AVX-512 VBMI, so the vulnerable Java code path isn't used on this host.")
            elif vbmi is True:
                info("CPU: AVX-512 VBMI present, so the vulnerable Java code path can be used.")
        for component, path, pids, raw in targets:
            count += 1
            result = java_verdict(raw, vbmi) if raw else None
            if not result:
                record(entry, component, raw, path, MANUAL, cant_read(root), root, pids)
                continue
            verdict, detail = distro_check(result[0], result[1], path, cve, root)
            record(entry, component, raw, path, verdict, detail, root, pids)
    return count


def check_ncentral():
    url = "https://127.0.0.1/login"
    info("Looking for a local N-central web console at " + url)
    page = http_get(url)
    match = re.search(r"ncentralVersion[\"']?\s*[:=]\s*[\"']?(\d+(?:\.\d+)+)", page or "")
    if not match:
        if re.search(r"N-central", page or "", re.I):
            record("Able2Shell", "N-central", "", url, MANUAL,
                   "An N-central console answered, but its version couldn't be read from "
                   "the login page. Compare the build shown in the console with "
                   "2026.4.1.39 (2026.4 HF3).")
            return 1
        return 0
    version = match.group(1)
    v = vtuple(version)
    stale = (" A patched server may keep showing an old version number, so confirm "
             "against N-able's guidance.")
    if lt(v, (2026, 4, 1, 26)):
        record("Able2Shell", "N-central", version, url, VULN,
               "Fixed in N-central 2026.4 HF2 (2026.4.1.26). Install HF3 (2026.4.1.39), "
               "which builds on it." + stale)
    else:
        record("Able2Shell", "N-central", version, url, SAFE)
    if lt(v, (2026, 4, 1, 39)):
        record("4EverAble2Shell", "N-central", version, url, VULN,
               "Exploitable when the Legacy API is enabled. N-central 2026.4 HF3 "
               "(2026.4.1.39) removes the Legacy API permanently; until then, make sure "
               "it is turned off." + stale)
    else:
        record("4EverAble2Shell", "N-central", version, url, SAFE)
    return 1


PY_SITE_GLOBS = [
    "/usr/lib/python3*/site-packages", "/usr/lib/python3*/dist-packages",
    "/usr/lib/python3/dist-packages", "/usr/lib64/python3*/site-packages",
    "/usr/local/lib/python3*/site-packages", "/usr/local/lib/python3*/dist-packages",
    "/opt/conda/lib/python3*/site-packages", "/opt/conda/envs/*/lib/python3*/site-packages",
    "~/.local/lib/python3*/site-packages",
    # virtualenvs kept in per-user tool directories
    "~/.virtualenvs/*/lib/python3*/site-packages",
    "~/.local/share/virtualenvs/*/lib/python3*/site-packages",
    "~/.cache/pypoetry/virtualenvs/*/lib/python3*/site-packages",
    "~/.pyenv/versions/*/lib/python3*/site-packages",
    "~/.local/share/pipx/venvs/*/lib/python3*/site-packages",
    "~/.local/pipx/venvs/*/lib/python3*/site-packages",
    "~/miniconda3/lib/python3*/site-packages", "~/miniconda3/envs/*/lib/python3*/site-packages",
    "~/anaconda3/lib/python3*/site-packages", "~/anaconda3/envs/*/lib/python3*/site-packages",
]


def python_site_dirs(root):
    dirs = [path for path in sys.path if path and os.path.isdir(path)] if root.host else []
    for pattern in PY_SITE_GLOBS:
        for expanded in home_patterns(root, pattern):
            dirs.extend(root_glob(root, expanded))
    venvs = list(find_apps(root)[2])
    for proc in root.procs:
        if runtime_kind(proc["exe"]) != "python":
            continue
        venvs.append(proc["venv"])
        # "/srv/app/.venv/bin/python /srv/app/.venv/bin/gunicorn ..." names the virtualenv twice
        venvs.extend(os.path.dirname(os.path.dirname(arg)) for arg in proc["argv"][:2]
                     if arg.startswith("/") and os.path.basename(os.path.dirname(arg)) == "bin")
    for venv in venvs:
        if venv and file_in(root, venv + "/pyvenv.cfg"):
            dirs.extend(root_glob(root, venv + "/lib*/python3*/site-packages"))
    unique, seen = [], set()
    for folder in dirs:
        real = resolve_in(root.prefix, folder)
        if real and real not in seen and os.path.isdir(real):
            seen.add(real)
            unique.append((folder, real))
    return unique


BROTLI_LIB_GLOBS = ["/usr/lib/*/libbrotlidec.so.*", "/usr/lib64/libbrotlidec.so.*",
                    "/usr/lib/libbrotlidec.so.*", "/usr/local/lib/libbrotlidec.so.*",
                    "/usr/local/lib64/libbrotlidec.so.*", "/lib/*/libbrotlidec.so.*",
                    "/lib64/libbrotlidec.so.*", "/lib/libbrotlidec.so.*"]
_BROTLI = {}


def system_brotli(root):
    if root.prefix in _BROTLI:
        return _BROTLI[root.prefix]
    libs, seen = [], set()
    for pattern in BROTLI_LIB_GLOBS:
        for path in root_glob(root, pattern):
            real = resolve_in(root.prefix, path)
            match = re.search(r"\.so\.(\d+\.\d+\.\d+)$", real or "")
            if not match or real in seen or not os.path.isfile(real):
                continue
            seen.add(real)
            inner = real[len(root.prefix):]
            verdict, detail = SAFE, ""
            if brotli_affected(vtuple(match.group(1))):
                verdict, detail = distro_check(
                    VULN, "Fixed upstream in Brotli 1.0.10, 1.1.1 and 1.2.1. Install your "
                          "distro's updated Brotli package, then restart the programs that "
                          "use it.", inner, ENTRIES["Node2Shell"], root)
            libs.append({"path": inner, "version": match.group(1), "verdict": verdict,
                         "detail": detail, "pids": root.lib_pids(real)})
    _BROTLI[root.prefix] = libs
    return libs


def shared_brotli_verdict(libs):
    lead = ("This Node.js build uses the system Brotli library instead of its own copy, so "
            "the Node.js version doesn't decide this. ")
    if not libs:
        return MANUAL, lead + ("That library wasn't found in the usual places. Check that "
                               "your distro's Brotli package has the fix for "
                               "CVE-2026-111497, then restart Node.")
    for verdict, word in ((VULN, "vulnerable"), (MANUAL, "unconfirmed"), (SAFE, "not vulnerable")):
        for lib in libs:
            if lib["verdict"] == verdict:
                return verdict, lead + "System Brotli {} at {} is {}; see its own entry.".format(
                    lib["version"], lib["path"], word)
    return MANUAL, lead


def check_node2shell():
    entry, cve = "Node2Shell", ENTRIES["Node2Shell"]
    count = 0
    for root in roots():
        # System Brotli library
        libs = system_brotli(root)
        for lib in libs:
            count += 1
            record(entry, "System Brotli library", lib["version"], lib["path"], lib["verdict"],
                   lib["detail"], root, lib["pids"])

        # Node.js
        for path, real, pids in find_runtime(
                root, "node", ["node", "nodejs"],
                ["/usr/local/bin/node", "~/.nvm/versions/node/*/bin/node",
                 "~/.volta/tools/image/node/*/bin/node", "/opt/*/bin/node"]):
            count += 1
            v, shared = None, False
            if root.host:
                v = vtuple(output([path, "--version"]).strip().lstrip("v"))
                shared = bool(re.search(r"^true$", output(
                    [path, "-p", "process.config.variables.node_shared_brotli"]), re.M))
            if not v:
                v = vtuple(only(scan_file(real, MARK_NODE)))
                shared = bool(scan_file(real, MARK_SHARED_BROTLI))
            if shared and (not v or node_has_brotli(v)):
                # Distro builds (Debian, Ubuntu, Fedora, RHEL, Alpine) load the system
                # Brotli library, so the Node.js version says nothing either way.
                verdict, detail = shared_brotli_verdict(libs)
                record(entry, "Node.js", vstr(v) if v else "", path, verdict, detail, root, pids)
                continue
            if not v:
                record(entry, "Node.js", "", path, MANUAL, cant_read(root), root, pids)
                continue
            verdict, detail = distro_check(*eval_node(v), path, cve, root)
            record(entry, "Node.js", vstr(v), path, verdict, detail, root, pids)

        # Bun
        for path, real, pids in find_runtime(root, "bun", ["bun"], ["~/.bun/bin/bun"]):
            count += 1
            v = vtuple(output([path, "--version"])) if root.host else None
            v = v or vtuple(only(scan_file(real, MARK_BUN)))
            if not v:
                record(entry, "Bun", "", path, MANUAL, cant_read(root), root, pids)
                continue
            verdict, detail = eval_bun(v)
            record(entry, "Bun", vstr(v), path, verdict, detail, root, pids)

        # .NET runtimes
        for path, real, pids in find_runtime(
                root, "dotnet", ["dotnet"],
                ["/usr/share/dotnet/dotnet", "/usr/lib/dotnet/dotnet", "~/.dotnet/dotnet"]):
            lines = output([path, "--list-runtimes"]).splitlines() if root.host else []
            versions = [m.group(1) for m in (re.match(r"Microsoft\.NETCore\.App (\S+)",
                                                      line.strip()) for line in lines) if m]
            if not versions:  # read the runtime directories instead
                try:
                    versions = sorted(os.listdir(os.path.join(os.path.dirname(real), "shared",
                                                              "Microsoft.NETCore.App")))
                except OSError:
                    versions = []
            for name in versions:
                match = re.match(r"(\d+\.\d+\.\d+)(\S*)$", name)
                if not match:
                    continue
                count += 1
                if match.group(2):  # previews like 11.0.0-rc.2.26480.1
                    record(entry, ".NET runtime", name, path, MANUAL,
                           "Pre-release .NET runtime, which the fixed-version list doesn't "
                           "cover (.NET 11 is fixed from Release Candidate 3). Replace it "
                           "with a fixed release.", root, pids)
                    continue
                verdict, detail = distro_check(*eval_dotnet(vtuple(name)), path, cve, root)
                record(entry, ".NET runtime", name, path, verdict, detail, root, pids)

        # Python Brotli / brotlicffi packages
        pattern = re.compile(r"^(brotli|brotlicffi)-(\d[\w.]*?)\.(dist-info|egg-info)$", re.I)
        for site, real_site in python_site_dirs(root):
            try:
                names = os.listdir(real_site)
            except OSError:
                continue
            for name in names:
                match = pattern.match(name)
                if not match:
                    continue
                path = os.path.join(site, name)
                count += 1
                pkg, version = match.group(1).lower(), match.group(2)
                v = vtuple(version)
                if pkg == "brotli":
                    verdict, detail = (VULN, "Fixed in Brotli 1.2.1 (PyPI).") \
                        if brotli_affected(v) else (SAFE, "")
                    label = "Python Brotli"
                else:
                    verdict, detail = (VULN, "Fixed in brotlicffi 1.2.1.0.") \
                        if lt(v, (1, 2, 1, 0)) else (SAFE, "")
                    label = "Python brotlicffi"
                verdict, detail = distro_check(verdict, detail, path, cve, root)
                record(entry, label, version, path, verdict, detail, root)
    return count


PHP_MODULE_GLOBS = ["/usr/lib/apache2/modules/libphp*.so", "/usr/lib/apache2/modules/mod_php*.so",
                    "/usr/lib64/httpd/modules/libphp*.so", "/usr/lib/httpd/modules/libphp*.so",
                    "/etc/httpd/modules/libphp*.so", "/usr/local/apache2/modules/libphp*.so",
                    "/usr/libexec/apache2/libphp*.so"]


def check_php():
    entry, cve = "PHP2Shell", ENTRIES["PHP2Shell"]
    patterns = ["/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/local/bin/php*",
                "/usr/local/sbin/php-fpm*", "/opt/remi/*/root/usr/bin/php",
                "/opt/remi/*/root/usr/sbin/php-fpm", "/opt/plesk/php/*/bin/php",
                "/opt/cpanel/ea-php*/root/usr/bin/php",
                "/usr/local/lsws/lsphp*/bin/php", "/usr/local/lsws/lsphp*/bin/lsphp"]
    count = 0
    for root in roots():
        for path, real, pids in find_runtime(root, "php", ["php", "php-fpm", "php-cgi", "lsphp"],
                                             patterns, name_re=r"^(ls)?php(-fpm|-cgi)?[\d.]*$"):
            count += 1
            match = re.search(r"PHP (\d+\.\d+\.\d+)", output([path, "-v"]) if root.host else "")
            version = match.group(1) if match else only(scan_file(real, MARK_PHP))
            if not version:
                record(entry, "PHP", "", path, MANUAL, cant_read(root), root, pids)
                continue
            verdict, detail = distro_check(*eval_php(vtuple(version)), path, cve, root)
            record(entry, "PHP", version, path, verdict, detail, root, pids)

        # PHP built into the web server (mod_php). There may be no php binary at all,
        # so look for the module on disk and in what running processes have loaded.
        candidates = [path for pattern in PHP_MODULE_GLOBS for path in root_glob(root, pattern)]
        candidates += [lib for proc in root.procs for lib, gone in proc["libs"]
                       if not gone and re.search(r"/(libphp|mod_php)", lib)]
        seen = set()
        for path in candidates:
            real = file_in(root, path)
            if not real or real in seen:
                continue
            seen.add(real)
            count += 1
            pids = root.lib_pids(real)
            version = only(scan_file(real, MARK_PHP))
            if not version:
                record(entry, "PHP (web server module)", "", path, MANUAL,
                       "Couldn't read the PHP version from the module file.", root, pids)
                continue
            verdict, detail = distro_check(*eval_php(vtuple(version)), path, cve, root)
            record(entry, "PHP (web server module)", version, path, verdict, detail, root, pids)
    return count


def check_plex():
    entry = "Plex2Shell"
    version, location = None, None
    if shutil.which("dpkg-query"):
        # Require state "ii": a removed package with leftover config still has a version.
        code, out = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Version}",
                         "plexmediaserver"])
        parts = out.split()
        if code == 0 and len(parts) == 2 and parts[0] == "ii":
            version, location = parts[1], "package plexmediaserver (dpkg)"
    if not version and shutil.which("rpm"):
        code, out = run(["rpm", "-q", "--qf", "%{VERSION}", "plexmediaserver"])
        if code == 0 and out.strip() and "not installed" not in out:
            version, location = out.strip(), "package plexmediaserver (rpm)"
    if not version:
        url = "http://127.0.0.1:32400/identity"
        info("Looking for a running Plex Media Server at " + url)
        page = http_get(url)
        # Anchor on MediaContainer: the reply starts with <?xml version="1.0" ...?>.
        match = re.search(r'<MediaContainer\b[^>]*\bversion="([^"]+)"', page or "")
        if match:
            version, location = match.group(1), url
    if not version:
        return 0
    v = vtuple(version, 4)
    if not v:
        record(entry, "Plex Media Server", version, location, MANUAL, "Couldn't read the version.")
        return 1
    verdict, detail = eval_plex(v)
    record(entry, "Plex Media Server", version, location, verdict, detail)
    return 1


def check_wordpress():
    info("Searching for WordPress installs under: " + ", ".join(SEARCH_ROOTS))
    info("(this can take a moment on large file systems)")
    count = 0
    for root in roots():
        for install in find_apps(root)[0]:
            count += 1
            version_file = os.path.join(install, "wp-includes", "version.php")
            real = file_in(root, version_file)
            match = re.search(r"\$wp_version\s*=\s*'([^']+)'", read_text(real) if real else "")
            version = match.group(1) if match else ""
            v = vtuple(version)
            prerelease = re.search(r"alpha|beta|rc", version, re.I)
            for entry, rule in (("WP2Shell", eval_wp2shell), ("Comment2Shell", eval_comment2shell)):
                if not v:
                    record(entry, "WordPress", version, install, MANUAL,
                           "Couldn't read the version.", root)
                    continue
                verdict, detail = rule(v)
                if prerelease and verdict == SAFE:
                    verdict, detail = MANUAL, ("Pre-release build. The version number alone can't "
                                               "show whether it has the fix, so update to a "
                                               "stable release.")
                cves = ENTRIES[entry]
                if entry == "WP2Shell" and lt(v, (6, 9)):
                    cves = "CVE-2026-60137"  # the only one of the two that applies before 6.9
                verdict, detail = distro_check(verdict, detail, version_file, cves, root)
                record(entry, "WordPress", version, install, verdict, detail, root)
    return count


def check_rails():
    entry = "KindaRails2Shell"
    count = 0
    for root in roots():
        for lockfile in find_apps(root)[1]:
            real = file_in(root, lockfile)
            match = re.search(r"^ {4}activestorage \(([^)]+)\)\s*$",
                              read_text(real) if real else "", re.M)
            if not match:
                continue
            count += 1
            version = match.group(1)
            verdict, detail = eval_activestorage(vtuple(version))
            record(entry, "Active Storage", version, lockfile, verdict, detail, root)
    gem = shutil.which("gem")
    if gem:
        info("Checking installed gems (gem list activestorage)")
        match = re.search(r"^activestorage \(([^)]*)\)", output([gem, "list", "activestorage", "--exact"], 60), re.M)
        if match:
            for version in re.findall(r"\d+(?:\.\d+)+", match.group(1)):
                count += 1
                verdict, detail = eval_activestorage(vtuple(version))
                record(entry, "Active Storage gem", version, "installed gems (" + gem + ")",
                       verdict, detail)
    return count


STALE_LIBS = (("libbrotlidec", "Node2Shell"), ("libphp", "PHP2Shell"), ("mod_php", "PHP2Shell"),
              ("libjvm", "Java2Shell"), ("libruby", "Ruby2Shell"))
KIND_ENTRY = {"ruby": "Ruby2Shell", "nginx": "NGINX2Shell", "java": "Java2Shell",
              "node": "Node2Shell", "bun": "Node2Shell", "dotnet": "Node2Shell",
              "php": "PHP2Shell"}


def check_stale():
    count = 0
    for root in roots():
        stale = {}
        for proc in root.procs:
            kind = runtime_kind(proc["exe"])
            if proc["deleted"] and kind in KIND_ENTRY:
                stale.setdefault((KIND_ENTRY[kind], proc["exe"]), []).append(proc["pid"])
            for lib, gone in proc["libs"]:
                for name, entry in STALE_LIBS:
                    if gone and name in os.path.basename(lib):
                        stale.setdefault((entry, lib), []).append(proc["pid"])
                        break
        for (entry, path), pids in sorted(stale.items()):
            count += 1
            shown = ", ".join(str(pid) for pid in sorted(pids)[:8]) + (", ..." if len(pids) > 8 else "")
            record(entry, "Running process", "", path, MANUAL,
                   "{} running process(es) (pid {}) still use a copy of this file that has since "
                   "been replaced or removed on disk, usually an update without a restart. "
                   "Their version can't be read, so restart them and scan again."
                   .format(len(pids), shown), root, pids)
    return count


CHECKS = [
    ("Ruby interpreters", ["Ruby2Shell"], check_ruby),
    ("nginx / OpenResty", ["NGINX2Shell"], check_nginx),
    ("Java runtimes", ["Java2Shell"], check_java),
    ("N-able N-central console", ["4EverAble2Shell", "Able2Shell"], check_ncentral),
    ("Brotli users: system library, Node.js, Bun, .NET, Python packages", ["Node2Shell"],
     check_node2shell),
    ("PHP", ["PHP2Shell"], check_php),
    ("Plex Media Server", ["Plex2Shell"], check_plex),
    ("WordPress", ["Comment2Shell", "WP2Shell"], check_wordpress),
    ("Rails Active Storage", ["KindaRails2Shell"], check_rails),
    ("Processes still running replaced files", ["restart needed"], check_stale),
]


# ---------------------------------------------------------------- summary

def print_item(number, finding, colour):
    label = finding["component"] + (" " + finding["version"] if finding["version"] else "")
    head = "{} ({})".format(finding["entry"], ENTRIES[finding["entry"]])
    print()
    print("  {} {}".format(number, colour(head)))
    print("     {} at {}".format(label, finding["location"]))
    if finding["also_in"]:
        print("     also in: {}".format(", ".join(finding["also_in"])))
    if finding["pids"] and finding["component"] != "Running process":
        print("     in use by {} running process(es)".format(len(finding["pids"])))
    for line in textwrap.wrap(finding["detail"], 72):
        print("     " + line)


def summary():
    vulnerable = [f for f in FINDINGS if f["verdict"] == VULN]
    manual = [f for f in FINDINGS if f["verdict"] == MANUAL]
    print()
    print(bold("=" * 64))
    print(bold(" RESULT"))
    print(bold("=" * 64))
    if vulnerable:
        print(red("[!] VULNERABLE: {} item(s) found on this host".format(len(vulnerable))))
        for n, finding in enumerate(vulnerable, 1):
            print_item("{}.".format(n), finding, red)
    elif manual or FAILED_CHECKS:
        print(yellow("[?] No confirmed vulnerable item, but the result is incomplete (see below)."))
    else:
        print(green("[+] NOT VULNERABLE: no tracked *2Shell vulnerability was found on this host."))
    if manual:
        print()
        print(yellow("[?] Needs a manual check: {} item(s)".format(len(manual))))
        for finding in manual:
            print_item("-", finding, yellow)
    if FAILED_CHECKS:
        print()
        print(yellow("[!] {} check(s) failed and were skipped: {}".format(
            len(FAILED_CHECKS), ", ".join(FAILED_CHECKS))))
    for note in NOTES:
        print()
        for line in textwrap.wrap("Note: " + note, 76):
            print(yellow(line))
    print()
    for line in textwrap.wrap("Checked {} component(s). ".format(len(FINDINGS)) + LIMITS
                              + " Tracker data: {}.".format(TRACKER_DATE), 76):
        print(dim(line))


LIMITS = ("This is a version check. Containers are covered only while they run, and their "
          "files are read rather than run, so a few versions can't be determined there. It "
          "doesn't inspect stopped containers or images, self-contained .NET apps, or copies "
          "of Brotli compiled into other programs. For OS packages on this host it reads the "
          "package changelog to spot backported fixes, so it can't see a fix the changelog "
          "doesn't name.")
TOKENS = {VULN: "vulnerable", SAFE: "not_vulnerable", MANUAL: "manual_check"}


def cve_list(text):
    ids = []
    for first, last in re.findall(r"(CVE-\d+-\d+)(?:\s+to\s+(CVE-\d+-\d+))?", text):
        if last:
            stem, low = first.rsplit("-", 1)
            ids.extend("{}-{}".format(stem, n) for n in range(int(low), int(last.rsplit("-", 1)[1]) + 1))
        else:
            ids.append(first)
    return ids


def report(exit_code):
    findings = []
    for f in FINDINGS:
        item = {"entry": f["entry"], "cves": cve_list(ENTRIES[f["entry"]]),
                "component": f["component"], "version": f["version"],
                "verdict": TOKENS[f["verdict"]], "location": f["location"], "path": f["path"],
                "container": f["container"] or None, "also_in": f["also_in"],
                "running": bool(f["pids"]), "pids": f["pids"], "detail": f["detail"]}
        if "config" in f:
            item["config"] = f["config"]
        findings.append(item)
    counts = {token: sum(1 for f in FINDINGS if f["verdict"] == verdict)
              for verdict, token in TOKENS.items()}
    if counts["vulnerable"]:
        result = "vulnerable"
    else:
        result = "incomplete" if counts["manual_check"] or FAILED_CHECKS else "not_vulnerable"
    return {
        "tool": "something2shell detector", "version": SCRIPT_VERSION,
        "tracker_date": TRACKER_DATE,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {"hostname": socket.gethostname(), "platform": platform.platform(),
                 "scanned_as_root": IS_ROOT, "avx512_vbmi": cpu_has_avx512_vbmi()},
        "result": result, "exit_code": exit_code, "counts": counts,
        "failed_checks": FAILED_CHECKS,
        "containers": [root.label for root in roots() if not root.host],
        "notes": NOTES, "limits": LIMITS, "findings": findings,
    }


def scan():
    print(bold("something2shell detector {}".format(SCRIPT_VERSION))
          + dim("  (tracker data {})".format(TRACKER_DATE)))
    print("Scanning this host for {} tracked *2Shell vulnerabilities...".format(len(ENTRIES)))
    if not sys.platform.startswith("linux"):
        print(yellow("Note: this script is written for Linux; results elsewhere may be incomplete."))
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(yellow("Note: running as a regular user. Directories you can't read are skipped, "
                     "and other users' processes and containers are not inspected; run with "
                     "sudo for a complete scan."))
    others = [root.label for root in roots() if not root.host]
    if others:
        print("Also reading {} other root filesystem(s) with running processes: {}{}".format(
            len(others), ", ".join(others[:6]), ", ..." if len(others) > 6 else ""))

    for number, (title, entries, check) in enumerate(CHECKS, 1):
        section(number, len(CHECKS), title, entries)
        try:
            found = check()
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # keep going if one check breaks
            print(yellow("    ! this check failed: {}".format(exc)))
            FAILED_CHECKS.append(title)
            continue
        if not found:
            info("- nothing found")
        for label in sorted(_REPEATS):
            info("= {}: {} finding(s) identical to ones listed above".format(
                label, _REPEATS[label]))
        _REPEATS.clear()

    summary()
    if any(f["verdict"] == VULN for f in FINDINGS):
        return 1
    return 2 if FAILED_CHECKS else 0


def main():
    global COLOR
    parser = argparse.ArgumentParser(
        description="Check this host for the *2Shell vulnerabilities in the something2shell tracker.")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON instead of text")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version",
                        version="%(prog)s {} (tracker data {})".format(SCRIPT_VERSION, TRACKER_DATE))
    args = parser.parse_args()
    if args.json:
        with contextlib.redirect_stdout(io.StringIO()):
            code = scan()
        json.dump(report(code), sys.stdout, indent=2)
        print()
        return code
    COLOR = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    return scan()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
