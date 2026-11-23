"""SSH, used only to bootstrap a node: pinned host keys, temporary credentials, sudo."""

import base64
import hashlib
import shlex
import socket

import paramiko

KEY_TYPES = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256']


class SSHError(RuntimeError):
    pass


class RemoteError(SSHError):
    def __init__(self, label, code, output):
        super().__init__(f'{label} failed (exit {code}): {output.strip()[-2000:]}')
        self.code = code
        self.output = output


def fingerprint(key_b64):
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')


def fetch_host_key(host, port=22, timeout=10):
    """The server's host key as ('type base64', fingerprint), without logging in."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise SSHError(f'cannot connect to {host}:{port}: {e}') from e
    transport = paramiko.Transport(sock)
    try:
        transport.get_security_options().key_types = KEY_TYPES
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
    except paramiko.SSHException as e:
        raise SSHError(f'SSH handshake with {host}:{port} failed: {e}') from e
    finally:
        transport.close()
    return f'{key.get_name()} {key.get_base64()}', fingerprint(key.get_base64())


class Remote:
    """An SSH session to a node whose host key must match the pinned one."""

    def __init__(self, host, port, host_key, username, password=None, sudo_password=None,
                 use_local_keys=False, timeout=15):
        self.host = host
        self.sudo_password = sudo_password if sudo_password is not None else password
        self.client = paramiko.SSHClient()
        key_type, key_b64 = host_key.split()
        known = host if port == 22 else f'[{host}]:{port}'
        self.client.get_host_keys().add(known, key_type, paramiko.PKey.from_type_string(
            key_type, base64.b64decode(key_b64)))
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            self.client.connect(host, port=port, username=username, password=password,
                                allow_agent=use_local_keys, look_for_keys=use_local_keys,
                                timeout=timeout, auth_timeout=timeout)
        except paramiko.BadHostKeyException as e:
            raise SSHError(f'host key for {host} does NOT match the pinned key; refusing to continue') from e
        except paramiko.AuthenticationException as e:
            raise SSHError(f'SSH login to {host} as {username} failed') from e
        except (paramiko.SSHException, OSError) as e:
            raise SSHError(f'SSH connection to {host}:{port} failed: {e}') from e

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def run_bytes(self, cmd, sudo=False, check=True, label=None, timeout=600):
        """Run a shell command (as root with sudo=True). Returns (exit code, stdout bytes, stderr text)."""
        if sudo:
            prefix = "sudo -S -p ''" if self.sudo_password else 'sudo -n'
            cmd = f'{prefix} sh -c {shlex.quote(cmd)}'
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        if sudo and self.sudo_password:
            stdin.write(self.sudo_password + '\n')
            stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read()
        err = stderr.read().decode(errors='replace')
        code = stdout.channel.recv_exit_status()
        if check and code != 0:
            raise RemoteError(label or cmd.split()[0], code, out.decode(errors='replace') + err)
        return code, out, err

    def run(self, cmd, sudo=False, check=True, label=None, timeout=600):
        code, out, err = self.run_bytes(cmd, sudo, check, label, timeout)
        return code, (out.decode(errors='replace') + err).strip()

    def upload(self, files):
        """Upload {name: bytes} into a fresh private temp dir; returns its path."""
        _, tmp = self.run('mktemp -d /tmp/liteblox.XXXXXX', label='mktemp')
        sftp = self.client.open_sftp()
        try:
            for name, data in files.items():
                with sftp.open(f'{tmp}/{name}', 'wb') as f:
                    f.write(data)
        finally:
            sftp.close()
        return tmp
