import subprocess
import time
import sys

def do_traceroute(host):
    try:
        process = subprocess.Popen(
            ["traceroute", "-I", "-m", "20", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        return stdout.strip(), stderr.strip()
    except FileNotFoundError:
        print("Error: Traceroute not installed");
        sys.exit(1)

def printing_traceroute(output):
    print("Output:")
    for line in output.splitlines():
        print(line)

def count_hops(output):
    hop_lines = []
    for line in output.splitlines():
        line = line.strip()
        if line.split()[0].isdigit():
            hop_lines.append(line)
    return len(hop_lines)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("To Use: python lab1.py host_name")
        print("Ex: python lab1.py google.com")
        sys.exit(1)

    link = sys.argv[1]

    print(f"Running traceroute to {link} (max hops = 20)...\n")
    stdout, stderr = do_traceroute(link)

    if stderr:
        print(f"\nSummary - Traceroute cannot run: hostname unknown")
    else:
        printing_traceroute(stdout)
        hops = count_hops(stdout)
        print(f"\nSummary - {hops} hops to destination ({link})\n")

