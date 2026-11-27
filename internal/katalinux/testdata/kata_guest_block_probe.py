"""Unqualified lab probe only: no provider bootstrap or host management access."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

settings = sys.argv[1]
sys.argv = ["runnerd-kata-supervisor", "--block-storage", settings]
spec = importlib.util.spec_from_file_location("supervisor", "/usr/local/bin/runnerd-kata-supervisor")
# The installed entrypoint has no .py suffix.
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("supervisor", "/usr/local/bin/runnerd-kata-supervisor")
spec = importlib.util.spec_from_loader(loader.name, loader)
supervisor = importlib.util.module_from_spec(spec)
loader.exec_module(supervisor)
supervisor.prepare_guest_block_storage(10001, 10001)
for path in ["/dev/kvm", "/dev/loop-control", "/var/run/docker.sock", "/etc/neticora-runnerd"]:
    if os.path.lexists(path):
        raise RuntimeError("unexpected management/device path: " + path)
runtime = Path("/run/neticora-docker")
runtime.mkdir(mode=0o750)
os.chown(runtime, 0, 10001)
env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/runner/home", "DOCKER_HOST": "unix:///run/neticora-docker/docker.sock"}
log = open("/runner/_diag/lab-dockerd.log", "w+")
daemon = subprocess.Popen(["/usr/local/bin/dockerd", "--host=" + env["DOCKER_HOST"],
                          "--storage-driver=overlay2", "--data-root=/var/lib/docker",
                          "--exec-root=/run/neticora-docker/exec", "--pidfile=/run/neticora-docker/docker.pid",
                          "--group=root", "--live-restore=false"], env=env, stdout=log, stderr=subprocess.STDOUT)
try:
    for _ in range(80):
        if daemon.poll() is not None:
            raise RuntimeError("inner dockerd exited before readiness")
        status = subprocess.run(["docker", "info", "--format", "{{json .}}"], env=env, capture_output=True, text=True)
        if status.returncode == 0:
            info = json.loads(status.stdout)
            if info["Driver"] != "overlay2":
                raise RuntimeError("overlay2 required")
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("inner Docker readiness timed out")
    os.chown(runtime / "docker.sock", 0, 10001)
    os.chmod(runtime / "docker.sock", 0o660)
    print(json.dumps({"event": "guest-block-ready", "driver": info["Driver"],
                      "kernel": os.uname().release, "assigned": json.loads(settings),
                      "scope": "unqualified-lab"}), flush=True)
    # Allow the host to capture the exact live QEMU/backing-device witness.
    time.sleep(8)
    build = Path("/runner/_work/build")
    build.mkdir(mode=0o700)
    os.chown(build, 10001, 10001)
    for name, text in {"Dockerfile": "FROM scratch\nCOPY artifact /artifact\n", "artifact": "runnerd09-virtio-block-build\n"}.items():
        (build / name).write_text(text)
        os.chown(build / name, 10001, 10001)
    def identity():
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    subprocess.run(["docker", "build", "--network=none", "--tag", "runnerd09-block-probe:lab", str(build)],
                   env=env, preexec_fn=identity, check=True, timeout=100)
    subprocess.run(["docker", "image", "rm", "runnerd09-block-probe:lab"], env=env, preexec_fn=identity, check=True, timeout=20)
    print(json.dumps({"event": "native-docker-build-passed", "scope": "unqualified-lab"}), flush=True)
finally:
    daemon.terminate()
    try:
        daemon.wait(timeout=25)
    except subprocess.TimeoutExpired:
        daemon.kill()
        daemon.wait(timeout=5)
    log.flush()
    log.seek(0)
    print(log.read()[-16000:], flush=True)
    log.close()
