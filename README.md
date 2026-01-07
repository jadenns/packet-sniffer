# Network Traffic Capture and Upload System

A network monitoring script that captures live network traffic and automatically uploads captured data to a remote server for analysis and archival.


## Overview

This project provides a modular network traffic capture and management system consisting of two components:

- **sniffer.py**: A Python3 utility that captures live network packets from a specified interface and saves them in PCAP format
- **upload.sh**: A Bash automation script that transfers captured PCAP files to a remote AWS EC2 instance

The system is designed for network analysis, troubleshooting, monitoring, and compliance logging on Linux systems.

---

## Project Structure

```
.
├── sniffer.py          # Network packet capture utility
├── upload.sh           # Remote file transfer automation
├── .env                # Configuration file (create separately)
```

## Usage


**Step 1: Capture Network Traffic**

```bash
sudo python3 sniffer.py <interface>
```

Wait for packets to capture, then press `Ctrl+C` to stop. A PCAP file will be saved.

**Step 2: Upload Captured Files**

```bash
./upload.sh <interface>
```

The script will transfer all matching PCAP files to your EC2 instance.

---

## sniffer.py - Detailed Function Breakdown

The packet sniffer is organized into two main functions. Here's a line-by-line explanation:


### Global Variables

```python
captured_packets = []
```

**Purpose:** A list that stores all captured packets in memory during the sniffer's execution. Packets are appended here and later written to a PCAP file.

---

### Function 1: `packet_handler(packet)`

This is a **callback function** – it's called automatically each time a packet is captured.

```python
def packet_handler(packet):
    captured_packets.append(packet)
```
**Line explanation:**
- Every captured packet is added to the `captured_packets` list for later storage
- This happens automatically and continuously as packets arrive

**Layer 3 (IP) extraction:**

```python
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
```


- `packet.haslayer(IP)` – Checks if the packet contains an IP layer (most packets do)
- `packet[IP].src` – Extracts the source IP address from the IP header
- `packet[IP].dst` – Extracts the destination IP address from the IP header
- These are stored in variables for later use

**TCP protocol handling:**

```python
        if packet.haslayer(TCP):
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            print(f"[TCP] {ip_src}:{port_src} -> {ip_dst}:{port_dst}\n")
```

- `packet.haslayer(TCP)` – Checks if the packet is a TCP packet
- `packet[TCP].sport` – Extracts the source port (TCP layer)
- `packet[TCP].dport` – Extracts the destination port (TCP layer)
- `print()` – Displays the packet info to console in format: `[TCP] 192.168.1.100:54321 -> 8.8.8.8:443`
- The `\n` adds a newline for readability

**UDP protocol handling:**

```python
        elif packet.haslayer(UDP):
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            print(f"[UDP] {ip_src}:{port_src} -> {ip_dst}:{port_dst}\n")
```

- `packet.haslayer(UDP)` – Checks if the packet is a UDP packet (used instead of TCP)
- `packet[UDP].sport` – Extracts UDP source port
- `packet[UDP].dport` – Extracts UDP destination port
- `print()` – Displays the packet info in similar format: `[UDP] 10.0.0.5:53 -> 8.8.8.8:53`

**Note:** If a packet is neither TCP nor UDP (e.g., ICMP), it's captured in the list but not printed to console.

---

### Function 2: `main()`

This is the **entry point** of the program. It orchestrates the entire workflow.

```python
def main():
    if len(sys.argv) < 1:
        print("USAGE: python sniffer.py ")
        sys.exit(0)
```

**Command-line argument validation:**
`sys.argv[1]` – Network interface name (required by user)
- `len(sys.argv) < 1` – Checks if an interface is provided in the argument
- If invalid, prints usage and exits with status code 0


```python
if len(sys.argv) < 2:  # Need script name + interface name
    print("USAGE: python3 sniffer.py <interface>")
    print("Example: python3 sniffer.py eth0")
    sys.exit(1)
```

```python
    print("Packet Sniffer Starting")
    print("-----------------------")
```

**User feedback:**
- Displays messages to console indicating the sniffer is initializing
- The dashed line provides visual separation

**Core packet capture:**

```python
    sniff(iface=sys.argv[1], prn=packet_handler, store=0)
```

- `sniff()` – Scapy function that captures live packets
- `iface=sys.argv[1]` – Specifies which network interface to sniff on (e.g., "eth0", "wlan0")
- `prn=packet_handler` – Specifies the callback function to run for each packet
- `store=0` – **Important:** Tells Scapy NOT to store packets in its own buffer (saves memory; we store them manually in `packet_handler`)

**This line blocks execution** – The sniffer runs continuously until interrupted (Ctrl+C)

```python
    if captured_packets:
        date_regex = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        filename = f"traffic_{sys.argv[1]}_{date_regex}.pcap"
        wrpcap(filename, captured_packets)
        print("Saved!")
```

**File saving logic:**
- `if captured_packets:` – Only saves if packets were actually captured
- `datetime.now().strftime("%Y-%m-%d_%H_%M_%S")` – Gets current date/time and formats as: `2026-01-07_02_55_33`
- `f"traffic_{sys.argv[1]}_{date_regex}.pcap"` – Constructs filename like: `traffic_eth0_2026-01-07_02_55_33.pcap`
- `wrpcap(filename, captured_packets)` – Writes all captured packets to the PCAP file in standard format (readable by Wireshark, tcpdump, etc.)
- `print("Saved!")` – Confirms the file was written

**Graceful exit:**

```python
    sys.exit(0)
```

- Terminates the program with exit code 0 (success)

---

### Main Execution Block

```python
if __name__ == "__main__":
    main()
```

**Purpose:** This ensures `main()` only runs when the script is executed directly, not when imported as a module in another Python script. It's a Python best practice.

---

## upload.sh - Detailed Script Breakdown

The upload script is a Bash automation tool for transferring files. Here's a line-by-line explanation:

---

### Configuration Loading

```bash
source .env
```

**What it does:**
- Reads the `.env` file in the current directory
- Imports all variables defined there into the current shell session
- Required variables: `LOCAL_DIR`, `PATTERN`, `KEY`, `HOST`

**Example .env file:**
```bash
LOCAL_DIR="/home/user/captured_traffic"
PATTERN="traffic_$1_*.pcap"
KEY="/home/user/.ssh/ec2_key.pem"
HOST="ec2-user@ec2-instance.amazonaws.com"
```

**Why separate file?** Keeps sensitive credentials separate from script code. Never commit `.env` to version control.

---

### Main Loop

```bash
for f in "$LOCAL_DIR"/$PATTERN; do
```

**Purpose:** Iterates over all files matching the pattern

**Breakdown:**
- `for f in` – Starts a loop that assigns each matching filename to variable `f`
- `"$LOCAL_DIR"/$PATTERN` – Expands to all files matching the pattern
  - Example: `for f in "/home/user/captured_traffic"/traffic_*.pcap; do`
  - If `/home/user/captured_traffic/` contains:
    - `traffic_eth0_2026-01-07_02_55_33.pcap` ✓ matches
    - `traffic_eth1_2026-01-07_03_00_00.pcap` ✓ matches
    - `old_data.txt` ✗ doesn't match
- `do` – Indicates the start of the loop body

---

### Existence Check

```bash
[ -e "$f" ] || continue
```

**Purpose:** Skips files that don't actually exist (handles empty pattern matches gracefully)

**Breakdown:**
- `[ -e "$f" ]` – Tests if file `$f` exists
  - `-e` = "exists" test
  - Returns true (0) if file exists, false (1) if not
- `||` – Logical OR operator (executes next command only if previous failed)
- `continue` – Skips to the next iteration of the loop

**Example scenario:**
- If pattern matches no files, bash expands `"$f"` to literal string `"traffic_*.pcap"` (a non-existent file)
- The `-e` test fails, `||` triggers, `continue` skips the upload attempt
- This prevents error messages about non-existent files

---

### File Transfer

```bash
(scp -i $KEY $f $HOST:/home/ec2-user/traffics)
```

**Purpose:** Transfers the file to the remote server

**Breakdown:**
- `scp` – Secure Copy Protocol (SSH-based file transfer, encrypted)
- `-i $KEY` – Specifies the SSH private key file for authentication
  - Example: `-i /home/user/.ssh/ec2_key.pem`
- `$f` – The local file to transfer
  - Example: `/home/user/captured_traffic/traffic_eth0_2026-01-07_02_55_33.pcap`
- `$HOST:/home/ec2-user/traffics` – The remote destination
  - `$HOST` = `ec2-user@ec2-instance.amazonaws.com`
  - `:/home/ec2-user/traffics` = destination directory on remote server
  - Full command: `scp ... /home/user/captured_traffic/traffic_eth0_2026-01-07_02_55_33.pcap ec2-user@ec2-instance.amazonaws.com:/home/ec2-user/traffics`

---

### Status Feedback

```bash
echo -e "\e[32mSUCCESSFUL UPLOAD:\e[0m $f"
```

**Purpose:** Displays a colored success message for each uploaded file

**Breakdown:**
- `echo -e` – Enables interpretation of backslash escape sequences
- `\e[32m` – ANSI color code for green text
  - `[32m` = green color code
- `SUCCESSFUL UPLOAD:` – Static text
- `\e[0m` – ANSI code to reset text color to default
- `$f` – The filename that was uploaded

**Console output example:**
```
SUCCESSFUL UPLOAD: /home/user/captured_traffic/traffic_eth0_2026-01-07_02_55_33.pcap
```
(The text "SUCCESSFUL UPLOAD:" will be displayed in green)

---

### Loop Closure

```bash
done
```

**Purpose:** Marks the end of the `for` loop. The script returns to the top of the loop for the next matching file, or exits if no more files.

---

## Configuration

### .env File Template

Create a `.env` file in the same directory as your scripts:

```bash
# Local directory containing captured traffic files
LOCAL_DIR="/home/user/captured_traffic"

# Pattern to match files
PATTERN="traffic_$1_*.pcap"

# Path to SSH private key
KEY="/home/user/.ssh/ec2_key.pem"

# Remote host (format: user@hostname)
HOST="ec2-user@ec2-instance.amazonaws.com"
```

### Key Configuration Points

| Variable | Purpose | Example |
|----------|---------|---------|
| `LOCAL_DIR` | Directory where sniffer saves PCAP files | `/home/user/captured_traffic` |
| `PATTERN` | Glob pattern to match files for upload | `traffic_*.pcap` or `traffic_eth*.pcap` |
| `KEY` | Path to SSH private key (must be readable by user) | `~/.ssh/ec2_key.pem` |
| `HOST` | Remote user and host | `ec2-user@ec2-instance.amazonaws.com` |

### File Permissions

```bash
# Restrict .env file (contains sensitive data)
chmod 600 .env

# Restrict SSH private key
chmod 600 ~/.ssh/ec2_key.pem

# Make scripts executable
chmod +x sniffer.py upload.sh
```

---

## Examples

### Example 1: Capture Traffic on Ethernet Interface

```bash
sudo python3 sniffer.py eth0
```

**Output:**
```
Packet Sniffer Starting
-----------------------
[TCP] 192.168.1.100:54321 -> 142.251.46.228:443
[UDP] 192.168.1.100:53426 -> 8.8.8.8:53
[TCP] 192.168.1.100:54322 -> 142.251.46.228:443
^C
Saved!
```

**Result:** File created: `traffic_eth0_2026-01-07_14_30_45.pcap`

---

### Example 2: Upload Captured Files

```bash
./upload.sh eth0
```

**Output:**
```
SUCCESSFUL UPLOAD: /home/user/captured_traffic/traffic_eth0_2026-01-07_14_30_45.pcap
SUCCESSFUL UPLOAD: /home/user/captured_traffic/traffic_eth0_2026-01-07_15_00_12.pcap
```

**Result:** Both files transferred to EC2 instance at `/home/ec2-user/traffics/`

---

## Troubleshooting

### Issue 1: "Permission denied" when running sniffer

**Problem:**
```
PermissionError: [Errno 1] Operation not permitted
```

**Solution:**
```bash
sudo python3 sniffer.py eth0
```

Packet capture requires elevated privileges. Always use `sudo`.

---

### Issue 2: "No such file or directory" for .env

**Problem:**
```
.env: No such file or directory
```

**Solution:**
```bash
# Create .env in the same directory as upload.sh
cat > .env << EOF
LOCAL_DIR="/home/user/captured_traffic"
PATTERN="traffic_*.pcap"
KEY="/home/user/.ssh/ec2_key.pem"
HOST="ec2-user@ec2-instance.amazonaws.com"
EOF

chmod 600 .env
```

---

### Issue 3: SCP "Connection refused" to EC2

**Problem:**
```
ssh: connect to host ec2-instance.amazonaws.com port 22: Connection refused
```

**Solutions:**
1. Verify EC2 instance is running: `aws ec2 describe-instances`
2. Check security group allows SSH (port 22)
3. Verify correct hostname in `.env`
4. Test SSH directly: `ssh -i ~/.ssh/ec2_key.pem ec2-user@ec2-instance.amazonaws.com`

---

### Issue 4: "Interface not found" error

**Problem:**
```
Traceback (most recent call last):
  ...
OSError: No such device exists
```

**Solution:**
```bash
# List available network interfaces
ip link show
# or
ifconfig

# Use correct interface name
sudo python3 sniffer.py eth0  # or wlan0, ens3, etc.
```
---

## License and Attribution

This project uses:
- **Scapy** – Python packet manipulation library
- **Standard Unix utilities** – SCP, SSH, Bash
- **PCAP format** – Standard packet capture format (compatible with Wireshark, tcpdump)
