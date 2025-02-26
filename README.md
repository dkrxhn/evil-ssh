# Evil-SSH

Evil-SSH is a Python-based interactive SSH client inspired by Evil-WinRM, providing an improved shell experience with built-in file transfer, command execution, and interactive privilege escalation features (more soon!). It supports:
- **Upload & Download** functionality directly within the session
- **Persistent working directory tracking**
- **Port knocking support**
- **Interactive commands like `su`** (works with password prompts)
- **Remote port scanning**
- **Keyboard navigation (arrow keys, history, etc.)**

### **Requirements**
- Python 3.x
- `paramiko` library (for SSH & SFTP)
- `readline` (optional, for command history)
- `termios`, `tty`, `select` (for interactive shell handling)

To install dependencies, run:

```pip install paramiko```

## Usage
### Basic Connection

To connect using a password:

```python evil-ssh.py <target-ip> <username> --password <password>```

To connect using an SSH private key:

```python evil-ssh.py <target-ip> <username> --keyfile <path-to-key>```

To perform port knocking before connection:

```python evil-ssh.py <target-ip> <username> --password <password> --knock <port1,port2,port3>```

## Available Commands

### File Transfer Commands

```upload <localfile>```	Uploads a file to the current remote directory  
```upload <localfile>``` <remotefile>	Uploads a file with a specific name/path  
```download <remotefile>```	Downloads a file to the current local directory  
```download <remotefile>``` <localfile>	Downloads and saves the file under a different name  

Example:

`upload myscript.sh`  
`upload myscript.sh /tmp/myscript.sh`  
`download /tmp/results.txt`  
`download /tmp/results.txt results_local.txt`  

### Privilege Escalation
 
```su <username>```	Switch user and enter password interactively

Example:

`su tyler`

When prompted, enter the password.
### Remote Port Scanning

Evil-SSH allows you to scan ports on the remote machine:

```scan <start_port> <end_port>```

Example:

`scan 20 100`

This will scan ports 20 to 100 on the remote machine.

To exit the Evil-SSH shell:

'exit'  
'quit' 
CTRL+C  

