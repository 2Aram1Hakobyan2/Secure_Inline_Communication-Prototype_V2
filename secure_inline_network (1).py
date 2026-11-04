#!/usr/bin/env python3
"""Network3 homework - encrypting the data between two network devices.

PC1 -> Device1 -> Device2 -> PC2

Device1 encrypts the data, Device2 decrypts it, and PC2 gets the original
message. I used X25519 for exchanging keys and AES-GCM for encryption.
The test only sends data from PC1 to PC2 on port 5001.

This is just a small Linux test setup, not something to use on a real network.
It needs root access and does not handle things like large packets or replay attacks.

On Ubuntu/Debian, install the needed packages:
    sudo apt update
    sudo apt install -y iproute2 iptables python3-venv python3-dev \
        build-essential libnetfilter-queue-dev libnfnetlink-dev
    python3 -m pip install cryptography scapy NetfilterQueue

Run the basic tests:
    python3 secure_inline_network.py selftest

Run the network test (Linux, with root access):
    sudo python3 secure_inline_network.py demo

If you installed the Python packages in a virtual environment, run demo with
that Python instead, for example: sudo "$(which python)" secure_inline_network.py demo

Results go in network3_results/. If the test gets interrupted, clean up with:
    sudo python3 secure_inline_network.py cleanup
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time


PC1 = "n3_pc1"
DEVICE1 = "n3_device1"
DEVICE2 = "n3_device2"
PC2 = "n3_pc2"
NAMESPACES = (PC1, DEVICE1, DEVICE2, PC2)

SOURCE_IP = "10.0.1.2"
TARGET_IP = "10.0.2.2"
HANDSHAKE_IP = "10.0.12.2"
HANDSHAKE_PORT = 4400
APP_PORT = 5001
QUEUE_1 = 101
QUEUE_2 = 102
NONCE_SIZE = 12
TAG_SIZE = 16
INFO = b"Network3-Device1-Device2-AES256-GCM-v1"
DEMO_MESSAGE = b"Hello PC2, this is PC1!!!"  # 25 bytes


def crypto_imports():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:
        raise RuntimeError("Install cryptography: python3 -m pip install cryptography") from exc
    return InvalidTag, hashes, serialization, X25519PrivateKey, AESGCM, HKDF


def generate_exchange_keypair():
    _, _, serialization, X25519PrivateKey, _, _ = crypto_imports()
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def derive_session_key(private, remote_public_bytes: bytes) -> bytes:
    _, hashes, _, _, _, HKDF = crypto_imports()
    if len(remote_public_bytes) != 32:
        raise ValueError("X25519 public key must be exactly 32 bytes")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    shared_secret = private.exchange(X25519PublicKey.from_public_bytes(remote_public_bytes))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(
        shared_secret
    )


def fingerprint(key: bytes) -> str:
    # check if the keys match without showing the whole key
    return hashlib.sha256(key).hexdigest()[:16]


def encrypt_payload(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    _, _, _, _, AESGCM, _ = crypto_imports()
    nonce = os.urandom(NONCE_SIZE)
    # AESGCM adds the tag at the end of the encrypted data
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_payload(key: bytes, protected: bytes, aad: bytes = b"") -> bytes:
    _, _, _, _, AESGCM, _ = crypto_imports()
    if len(protected) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Protected payload is too short")
    nonce, ciphertext_and_tag = protected[:NONCE_SIZE], protected[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)


def associated_data(ip_packet) -> bytes:
    """Use the IPs, ports and sequence number when encrypting/decrypting.
    Some fields change while the packet travels, so I left those out.
    """
    tcp = ip_packet["TCP"]
    return (
        ipaddress.IPv4Address(ip_packet.src).packed
        + ipaddress.IPv4Address(ip_packet.dst).packed
        + struct.pack("!HHI", tcp.sport, tcp.dport, tcp.seq)
    )


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise ConnectionError("Handshake peer disconnected unexpectedly")
        data.extend(part)
    return bytes(data)


def server_handshake() -> bytes:
    private, public = generate_exchange_keypair()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HANDSHAKE_IP, HANDSHAKE_PORT))
        listener.listen(1)
        listener.settimeout(20)
        print("[Device2] Waiting for X25519 handshake ...", flush=True)
        with listener.accept()[0] as conn:
            conn.settimeout(10)
            remote_public = recv_exact(conn, 32)
            conn.sendall(public)
    return derive_session_key(private, remote_public)


def client_handshake() -> bytes:
    private, public = generate_exchange_keypair()
    end_time = time.monotonic() + 15
    while True:
        try:
            with socket.create_connection((HANDSHAKE_IP, HANDSHAKE_PORT), timeout=2) as conn:
                conn.sendall(public)
                remote_public = recv_exact(conn, 32)
            return derive_session_key(private, remote_public)
        except (ConnectionRefusedError, TimeoutError, OSError):
            if time.monotonic() >= end_time:
                raise TimeoutError("Could not connect to Device2 handshake listener")
            time.sleep(0.2)


def import_packet_dependencies():
    try:
        from netfilterqueue import NetfilterQueue
        from scapy.all import IP, TCP, Raw
    except ImportError as exc:
        raise RuntimeError(
            "Install packet dependencies: python3 -m pip install scapy NetfilterQueue"
        ) from exc
    return NetfilterQueue, IP, TCP, Raw


def make_packet_handler(key: bytes, encrypting: bool):
    _, IP, TCP, Raw = import_packet_dependencies()
    _, _, _, _, AESGCM, _ = crypto_imports()
    from cryptography.exceptions import InvalidTag

    device_name = "Device1" if encrypting else "Device2"
    aes = AESGCM(key)

    def handle(nf_packet):
        try:
            ip_packet = IP(nf_packet.get_payload())
            if not ip_packet.haslayer(TCP):
                nf_packet.accept()
                return

            tcp = ip_packet[TCP]
            if (
                ip_packet.src != SOURCE_IP
                or ip_packet.dst != TARGET_IP
                or tcp.dport != APP_PORT
            ):
                nf_packet.accept()
                return

            original = bytes(tcp.payload)
            if not original:  # SYN, ACK, FIN and packets without data are untouched.
                nf_packet.accept()
                return

            aad = associated_data(ip_packet)
            if encrypting:
                # skip big packets for now, they can cause problems with MTU
                if len(original) > 1200:
                    print("[Device1] Dropped oversized TCP payload", flush=True)
                    nf_packet.drop()
                    return
                nonce = os.urandom(NONCE_SIZE)
                modified = nonce + aes.encrypt(nonce, original, aad)
                operation = "encrypted"
            else:
                if len(original) < NONCE_SIZE + TAG_SIZE:
                    print("[Device2] Dropped invalid short protected packet", flush=True)
                    nf_packet.drop()
                    return
                nonce = original[:NONCE_SIZE]
                modified = aes.decrypt(nonce, original[NONCE_SIZE:], aad)
                operation = "decrypted"

            tcp.remove_payload()
            tcp.add_payload(Raw(load=modified))
            # packet size changed, so recalculate these values
            for field in ("len", "chksum"):
                if hasattr(ip_packet, field):
                    delattr(ip_packet, field)
            del tcp.chksum
            nf_packet.set_payload(bytes(ip_packet))
            nf_packet.accept()
            print(
                f"[{device_name}] {operation}: {len(original)} -> "
                f"{len(modified)} bytes",
                flush=True,
            )
        except (InvalidTag, ValueError) as exc:
            print(f"[{device_name}] Authentication/format failure: {exc}; dropped", flush=True)
            nf_packet.drop()
        except Exception as exc:
            # if something goes wrong, drop the packet
            print(f"[{device_name}] Packet handler error: {exc}; dropped", flush=True)
            nf_packet.drop()

    return handle


def mark_ready(ready_file: str):
    if ready_file:
        Path(ready_file).write_text("ready\n", encoding="utf-8")


def device_main(device: int, ready_file: str):
    NetfilterQueue, _, _, _ = import_packet_dependencies()
    key = client_handshake() if device == 1 else server_handshake()
    print(f"[Device{device}] X25519 + HKDF key SHA256 fingerprint: {fingerprint(key)}", flush=True)

    queue = NetfilterQueue()
    queue_id = QUEUE_1 if device == 1 else QUEUE_2
    queue.bind(queue_id, make_packet_handler(key, encrypting=(device == 1)))
    print(f"[Device{device}] Listening on NFQUEUE {queue_id}", flush=True)
    mark_ready(ready_file)
    try:
        queue.run()
    finally:
        queue.unbind()


def receiver_main(ready_file: str, output_file: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((TARGET_IP, APP_PORT))
        server.listen(1)
        server.settimeout(15)
        mark_ready(ready_file)
        with server.accept()[0] as conn:
            conn.settimeout(10)
            data = bytearray()
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
    Path(output_file).write_bytes(data)
    print(f"[PC2] Received plaintext: {data.decode('utf-8', errors='replace')}", flush=True)


def sender_main(message: bytes):
    with socket.create_connection((TARGET_IP, APP_PORT), timeout=10) as client:
        client.settimeout(10)
        client.sendall(message)
        client.shutdown(socket.SHUT_WR)
    print(f"[PC1] Sent {len(message)} plaintext bytes", flush=True)


def sniffer_main(ready_file: str, output_file: str):
    """Grab the packet before Device2 decrypts it.
    This lets us check what was actually sent between the devices.
    """
    _, IP, TCP, _ = import_packet_dependencies()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as s:
        s.bind(("vd2a", 0))
        s.settimeout(1.0)
        mark_ready(ready_file)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                frame = s.recv(65535)
            except socket.timeout:
                continue
            # skip anything that is not an IPv4 Ethernet packet
            if len(frame) < 14 or frame[12:14] != b"\x08\x00":
                continue
            try:
                ip = IP(frame[14:])
                if not ip.haslayer(TCP):
                    continue
                tcp = ip[TCP]
                if ip.src == SOURCE_IP and ip.dst == TARGET_IP and tcp.dport == APP_PORT:
                    data = bytes(tcp.payload)
                    if data:
                        Path(output_file).write_bytes(data)
                        print(f"[Capture] Device1--Device2 wire: {len(data)} bytes", flush=True)
                        return
            except Exception:
                continue
    raise TimeoutError("No matching encrypted TCP payload captured")


def run(*args: str, check: bool = True):
    return subprocess.run(list(args), check=check, text=True, capture_output=True)


def ns_exec(namespace: str, *args: str):
    return run("ip", "netns", "exec", namespace, *args)


def existing_namespaces() -> set[str]:
    result = run("ip", "netns", "list")
    return {line.split()[0] for line in result.stdout.splitlines() if line.split()}


def setup_topology():
    conflicts = set(NAMESPACES) & existing_namespaces()
    if conflicts:
        raise RuntimeError(
            f"Already existing namespaces: {sorted(conflicts)}. "
            "Run 'cleanup' only if these are your previous Network3 demo namespaces."
        )

    for name in NAMESPACES:
        run("ip", "netns", "add", name)

    links = (
        ("vpc1", PC1, "vd1a", DEVICE1),
        ("vd1b", DEVICE1, "vd2a", DEVICE2),
        ("vd2b", DEVICE2, "vpc2", PC2),
    )
    for left, left_ns, right, right_ns in links:
        run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
        run("ip", "link", "set", left, "netns", left_ns)
        run("ip", "link", "set", right, "netns", right_ns)

    addressing = (
        (PC1, "vpc1", "10.0.1.2/24"),
        (DEVICE1, "vd1a", "10.0.1.1/24"),
        (DEVICE1, "vd1b", "10.0.12.1/24"),
        (DEVICE2, "vd2a", "10.0.12.2/24"),
        (DEVICE2, "vd2b", "10.0.2.1/24"),
        (PC2, "vpc2", "10.0.2.2/24"),
    )
    for namespace in NAMESPACES:
        run("ip", "-n", namespace, "link", "set", "lo", "up")
    for namespace, interface, address in addressing:
        run("ip", "-n", namespace, "addr", "add", address, "dev", interface)
        run("ip", "-n", namespace, "link", "set", interface, "up")

    run("ip", "-n", PC1, "route", "add", "default", "via", "10.0.1.1")
    run("ip", "-n", PC2, "route", "add", "default", "via", "10.0.2.1")
    run("ip", "-n", DEVICE1, "route", "add", "10.0.2.0/24", "via", "10.0.12.2")
    run("ip", "-n", DEVICE2, "route", "add", "10.0.1.0/24", "via", "10.0.12.1")
    for namespace in (DEVICE1, DEVICE2):
        ns_exec(namespace, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

    print("[Setup] PC1 -> Device1 -> Device2 -> PC2 ready", flush=True)


def nfqueue_args(queue_number: int):
    return (
        "-t", "mangle", "-I", "FORWARD", "1", "-s", SOURCE_IP,
        "-d", TARGET_IP, "-p", "tcp", "--dport", str(APP_PORT),
        "-j", "NFQUEUE", "--queue-num", str(queue_number),
    )


def add_queue_rule(namespace: str, queue_number: int):
    ns_exec(namespace, "iptables", *nfqueue_args(queue_number))


def remove_queue_rule(namespace: str, queue_number: int):
    args = list(nfqueue_args(queue_number))
    args[2] = "-D"
    args.pop(4)  # -D does not need the rule position
    try:
        ns_exec(namespace, "iptables", *args)
    except subprocess.CalledProcessError:
        pass


def cleanup_topology():
    existing = existing_namespaces()
    for namespace, queue_number in ((DEVICE1, QUEUE_1), (DEVICE2, QUEUE_2)):
        if namespace in existing:
            remove_queue_rule(namespace, queue_number)
    for namespace in NAMESPACES:
        if namespace in existing:
            run("ip", "netns", "del", namespace, check=False)
    print("[Cleanup] Demo namespaces and NFQUEUE rules removed", flush=True)


def check_demo_requirements():
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("The full network demo requires Linux and root privileges")
    for name in ("ip", "iptables", "sysctl"):
        if not shutil.which(name):
            raise RuntimeError(f"Missing system tool: {name} (see installation instructions)")
    import_packet_dependencies()
    crypto_imports()


def wait_for_ready(ready: Path, proc: subprocess.Popen, label: str, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if ready.exists():
            return
        if proc.poll() is not None:
            raise RuntimeError(f"{label} exited before it became ready (code {proc.returncode})")
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for {label}")


def demo_main(output_directory: Path):
    check_demo_requirements()
    if set(NAMESPACES) & existing_namespaces():
        raise RuntimeError("Previous Network3 namespaces exist. Use 'cleanup' before 'demo'.")

    output_directory.mkdir(parents=True, exist_ok=True)
    output_directory = output_directory.resolve()
    processes: list[subprocess.Popen] = []
    log_files: list[tuple[str, Path]] = []
    handles = []
    created = False
    success = False

    with tempfile.TemporaryDirectory(prefix="network3_ready_") as temp:
        work = Path(temp)

        def launch(label: str, namespace: str, command: str, *extra: str):
            ready = work / f"{label}.ready"
            log_path = work / f"{label}.log"
            log_handle = open(log_path, "w", encoding="utf-8")
            handles.append(log_handle)
            proc = subprocess.Popen(
                ["ip", "netns", "exec", namespace, sys.executable,
                 str(Path(__file__).resolve()), command, "--ready-file", str(ready), *extra],
                stdout=log_handle, stderr=subprocess.STDOUT,
            )
            processes.append(proc)
            log_files.append((label, log_path))
            return ready, proc

        try:
            created = True
            setup_topology()
            r2, p2 = launch("device2", DEVICE2, "device2")
            r1, p1 = launch("device1", DEVICE1, "device1")
            wait_for_ready(r2, p2, "Device2")
            wait_for_ready(r1, p1, "Device1")

            receiver_path = output_directory / "received_plaintext.bin"
            wire_path = output_directory / "wire_payload.bin"
            rr, pr = launch("receiver", PC2, "receiver", "--output-file", str(receiver_path))
            rc, pc = launch("sniffer", DEVICE2, "sniffer", "--output-file", str(wire_path))
            wait_for_ready(rr, pr, "PC2 receiver")
            wait_for_ready(rc, pc, "wire capture")

            add_queue_rule(DEVICE1, QUEUE_1)
            add_queue_rule(DEVICE2, QUEUE_2)
            print("[Demo] Forward-path NFQUEUE rules installed", flush=True)

            sender = ns_exec(PC1, sys.executable, str(Path(__file__).resolve()),
                             "sender", "--message", DEMO_MESSAGE.decode("ascii"))
            print(sender.stdout.strip(), flush=True)
            for label, proc in (("receiver", pr), ("sniffer", pc)):
                try:
                    proc.wait(timeout=12)
                except subprocess.TimeoutExpired as exc:
                    raise RuntimeError(f"Timed out waiting for {label}") from exc
                if proc.returncode != 0:
                    raise RuntimeError(f"{label} failed (code {proc.returncode})")

            received = receiver_path.read_bytes()
            wire = wire_path.read_bytes()
            if received != DEMO_MESSAGE:
                raise AssertionError("PC2 did not receive the original plaintext")
            if wire == DEMO_MESSAGE or len(wire) != len(DEMO_MESSAGE) + NONCE_SIZE + TAG_SIZE:
                raise AssertionError("Wire payload was not correctly protected")

            print("[PASS] PC2 received the exact original plaintext", flush=True)
            print(f"[PASS] On-wire protected payload: {len(wire)} bytes "
                  f"(plaintext {len(DEMO_MESSAGE)} + 12-byte nonce + 16-byte tag)", flush=True)
            print("[PASS] Packet capture differs from plaintext", flush=True)
            success = True
        finally:
            # clean up the network rules, even if the test failed
            if created:
                try:
                    cleanup_topology()  # also deletes interfaces even on partial failure
                except Exception as exc:
                    print(f"[Cleanup] Warning: {exc}", file=sys.stderr)
            for proc in processes:
                if proc.poll() is None:
                    proc.terminate()
            for proc in processes:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            for handle in handles:
                handle.close()

            combined = []
            for label, path in log_files:
                if path.exists():
                    lines = path.read_text(encoding="utf-8", errors="replace").strip()
                    combined.append(f"=== {label} ===\n{lines}\n")
                    if lines:
                        print(f"=== {label} ===\n{lines}", flush=True)
            if combined:
                status = "PASS" if success else "INCOMPLETE OR FAILED"
                (output_directory / "test_evidence.txt").write_text(
                    f"Network3 demonstration status: {status}\n\n" + "\n".join(combined),
                    encoding="utf-8",
                )
    print(f"[Demo] Evidence saved in {output_directory}", flush=True)


def selftest():
    crypto_imports()
    a_private, a_public = generate_exchange_keypair()
    b_private, b_public = generate_exchange_keypair()
    key_a = derive_session_key(a_private, b_public)
    key_b = derive_session_key(b_private, a_public)
    assert key_a == key_b and len(key_a) == 32
    print(f"[PASS] X25519 + HKDF-SHA256: matching 256-bit keys ({fingerprint(key_a)})")

    aad = b"demo packet header"
    encrypted = encrypt_payload(key_a, DEMO_MESSAGE, aad)
    assert len(encrypted) == 53
    assert decrypt_payload(key_b, encrypted, aad) == DEMO_MESSAGE
    print("[PASS] AES-256-GCM: 25-byte plaintext -> 53-byte protected payload -> 25 bytes")

    tampered = bytearray(encrypted)
    tampered[-1] ^= 1
    from cryptography.exceptions import InvalidTag
    try:
        decrypt_payload(key_b, bytes(tampered), aad)
    except InvalidTag:
        print("[PASS] Modified ciphertext rejected (InvalidTag)")
    else:
        raise AssertionError("Tampering was not rejected")

    try:
        decrypt_payload(key_b, encrypted, b"modified header")
    except InvalidTag:
        print("[PASS] Modified authenticated header rejected")
    else:
        raise AssertionError("Header tampering was not rejected")
    print("[Selftest] All cryptographic checks passed")


def main():
    parser = argparse.ArgumentParser(description="Network3 secure inline encryption demo")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("selftest", help="Test X25519, HKDF, AES-GCM; no root needed")
    demo = sub.add_parser("demo", help="Run the full 4-namespace Linux demo as root")
    demo.add_argument("--output-dir", default="network3_results")
    sub.add_parser("cleanup", help="Delete the four Network3 demo namespaces")

    for command in ("device1", "device2", "receiver", "sniffer"):
        p = sub.add_parser(command, help=argparse.SUPPRESS)
        p.add_argument("--ready-file", default="")
        if command in ("receiver", "sniffer"):
            p.add_argument("--output-file", required=True)
    sender = sub.add_parser("sender", help=argparse.SUPPRESS)
    sender.add_argument("--message", default=DEMO_MESSAGE.decode("ascii"))

    args = parser.parse_args()
    try:
        if args.command == "selftest":
            selftest()
        elif args.command == "demo":
            demo_main(Path(args.output_dir))
        elif args.command == "cleanup":
            if os.geteuid() != 0:
                raise RuntimeError("cleanup requires root privileges")
            cleanup_topology()
        elif args.command in ("device1", "device2"):
            device_main(1 if args.command == "device1" else 2, args.ready_file)
        elif args.command == "receiver":
            receiver_main(args.ready_file, args.output_file)
        elif args.command == "sniffer":
            sniffer_main(args.ready_file, args.output_file)
        elif args.command == "sender":
            sender_main(args.message.encode("utf-8"))
    except (RuntimeError, OSError, subprocess.CalledProcessError, TimeoutError,
            AssertionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr.strip(), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
