#!/usr/bin/env python3
import argparse
import paramiko
import socket
import sys
import time
import os
import stat
import select
import termios
import tty

# Enable arrow key navigation and history support
try:
    import readline
except ImportError:
    pass

DEFAULT_KNOCK_DELAY = 0.5  # seconds between knocks

class EvilSSH:
    def __init__(self, hostname, username, password=None, keyfile=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.keyfile = keyfile
        self.client = None
        self.sftp = None
        self.remote_cwd = None   # current remote working directory
        self.remote_home = None  # remote home directory

    def port_knock(self, ports, delay=DEFAULT_KNOCK_DELAY):
        print("[*] Starting port knocking sequence...")
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    sock.connect((self.hostname, port))
                    print(f"[*] Knocked on port {port} (open)")
            except Exception:
                print(f"[*] Knocked on port {port}")
            time.sleep(delay)
        print("[*] Port knocking sequence completed.")

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.keyfile:
                private_key = paramiko.RSAKey.from_private_key_file(self.keyfile)
                self.client.connect(self.hostname, username=self.username, pkey=private_key)
            elif self.password:
                self.client.connect(
                    self.hostname,
                    username=self.username,
                    password=self.password,
                    allow_agent=False,
                    look_for_keys=False
                )
            else:
                print("[-] No authentication method provided. Use --password or --keyfile.")
                sys.exit(1)

            self.sftp = self.client.open_sftp()
            self.remote_home = self.sftp.getcwd() or "~"
            self.remote_cwd = self.remote_home
            print(f"[+] Connected to {self.hostname} as {self.username}")
            self.shell()
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            sys.exit(1)

    def _get_prompt_dir(self):
        if self.remote_cwd == self.remote_home:
            return "~"
        elif self.remote_cwd.startswith(self.remote_home):
            suffix = self.remote_cwd[len(self.remote_home):]
            if suffix.startswith("/"):
                return "~" + suffix
            else:
                return "~/" + suffix
        else:
            return self.remote_cwd

    def shell(self):
        try:
            while True:
                prompt_dir = self._get_prompt_dir()
                # Colored prompt: username in green, hostname in blue, directory in yellow.
                prompt = f"\033[1;32m{self.username}\033[0m@\033[1;34m{self.hostname}\033[0m:" \
                         f"\033[1;33m{prompt_dir}\033[0m$ "
                command = input(prompt).strip()
                if not command:
                    continue

                # Get the first token in lower case
                token = command.split()[0].lower()

                if token in ["exit", "quit"]:
                    print("[+] Exiting...")
                    break
                elif token == "cd":
                    self.change_directory(command)
                elif token == "upload":
                    self.handle_upload(command)
                elif token == "download":
                    self.handle_download(command)
                elif token == "su":
                    self.interactive_command(command)
                else:
                    full_command = f"cd {self.remote_cwd} && {command}"
                    self.execute_command(full_command)
        except KeyboardInterrupt:
            print("\n[+] Exiting...")
        finally:
            if self.sftp:
                self.sftp.close()
            if self.client:
                self.client.close()

    def change_directory(self, command):
        parts = command.split(maxsplit=1)
        if len(parts) == 1:
            try:
                self.sftp.chdir(self.remote_home)
                self.remote_cwd = self.sftp.getcwd()
            except Exception as e:
                print(f"[-] cd: {e}")
        else:
            arg = parts[1].strip()
            if arg == "~":
                new_dir = self.remote_home
            elif arg.startswith("/"):
                new_dir = arg
            else:
                new_dir = os.path.normpath(os.path.join(self.remote_cwd, arg))
            try:
                self.sftp.chdir(new_dir)
                self.remote_cwd = self.sftp.getcwd()
            except Exception as e:
                print(f"[-] cd: {e}")

    def handle_upload(self, command):
        parts = command.split(maxsplit=2)
        if len(parts) < 2:
            print("Usage: upload <localfile> [remotefile]")
            return
        localfile = parts[1]
        if len(parts) == 2:
            remotefile = os.path.join(self.remote_cwd, os.path.basename(localfile))
        else:
            remotefile = parts[2]
            if not os.path.isabs(remotefile):
                remotefile = os.path.join(self.remote_cwd, remotefile)
        self.upload(localfile, remotefile)

    def handle_download(self, command):
        parts = command.split(maxsplit=2)
        if len(parts) < 2:
            print("Usage: download <remotefile> [localfile]")
            return
        remotefile = parts[1]
        if not os.path.isabs(remotefile):
            remotefile = os.path.join(self.remote_cwd, remotefile)
        if len(parts) == 2:
            localfile = os.path.basename(remotefile)
        else:
            localfile = parts[2]
        self.download(remotefile, localfile)

    def execute_command(self, command, use_pty=False):
        try:
            stdin, stdout, stderr = self.client.exec_command(command, get_pty=use_pty)
            out = stdout.read().decode()
            err = stderr.read().decode()
            if out:
                print(out, end="")
            if err:
                print(err, end="")
        except Exception as e:
            print(f"[-] Command execution failed: {e}")

    def interactive_command(self, command):
        try:
            channel = self.client.invoke_shell()
            channel.send(command + "\n")
            oldtty = termios.tcgetattr(sys.stdin)
            try:
                tty.setraw(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
                channel.settimeout(0.0)
                while True:
                    r, w, e = select.select([channel, sys.stdin], [], [])
                    if channel in r:
                        try:
                            data = channel.recv(1024)
                            if not data:
                                break
                            sys.stdout.write(data.decode())
                            sys.stdout.flush()
                        except socket.timeout:
                            pass
                    if sys.stdin in r:
                        x = sys.stdin.read(1)
                        if not x:
                            break
                        channel.send(x)
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
                channel.close()
        except Exception as e:
            print(f"[-] Interactive command failed: {e}")

    def upload(self, localfile, remotefile):
        try:
            if not os.path.isfile(localfile):
                print(f"[-] Local file '{localfile}' does not exist.")
                return
            remote_dir = os.path.dirname(remotefile)
            try:
                self.sftp.chdir(remote_dir)
            except IOError:
                try:
                    self.sftp.mkdir(remote_dir)
                    print(f"[+] Created remote directory '{remote_dir}'.")
                except Exception as e:
                    print(f"[-] Failed to create remote directory '{remote_dir}': {e}")
                    return
            self.sftp.put(localfile, remotefile)
            print(f"[+] Uploaded '{localfile}' to '{remotefile}'")
        except Exception as e:
            print(f"[-] Upload failed: {e}")

    def download(self, remotefile, localfile):
        try:
            self.sftp.get(remotefile, localfile)
            print(f"[+] Downloaded '{remotefile}' to '{localfile}'")
        except Exception as e:
            print(f"[-] Download failed: {e}")

    def remote_port_scan(self, start_port, end_port):
        print(f"[*] Scanning ports {start_port} to {end_port} on {self.hostname}...")
        open_ports = []
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    result = sock.connect_ex((self.hostname, port))
                    if result == 0:
                        print(f"[+] Port {port} is open.")
                        open_ports.append(port)
            except Exception:
                continue
        if not open_ports:
            print("[-] No open ports found in the specified range.")
        else:
            print(f"[+] Open ports: {open_ports}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Evil-SSH: An interactive SSH tool with cd, upload, download, and interactive command support."
    )
    parser.add_argument("hostname", help="Target hostname or IP")
    parser.add_argument("username", help="Username for SSH authentication")
    parser.add_argument("--password", help="Password for SSH authentication")
    parser.add_argument("--keyfile", help="Path to private key file for SSH authentication")
    parser.add_argument("--knock", help="Comma-separated list of ports for port knocking", default=None)
    return parser.parse_args()

def main():
    args = parse_args()
    ssh_client = EvilSSH(args.hostname, args.username, password=args.password, keyfile=args.keyfile)
    if args.knock:
        try:
            ports = [int(port.strip()) for port in args.knock.split(",")]
            ssh_client.port_knock(ports)
        except ValueError:
            print("[-] Invalid port numbers in knock sequence.")
            sys.exit(1)
    ssh_client.connect()

if __name__ == "__main__":
    main()

