# NetPIDTracer v1.0 – Network Connection Analyzer and PID Path Extractor
# This tool analyzes network connections and retrieves the executable path of the process associated with each connection.

import subprocess
import psutil
import argparse
import platform
from tabulate import tabulate
from PIL import Image, ImageDraw, ImageFont
import numpy as np
from termcolor import colored

# تحميل الصورة
image = Image.open(r'G:\new_data\Python_Projects\anubis.jpg')
image = image.resize((80, 40))  # تغيير حجم الصورة لتتناسب مع التيرمنال

# تحويل الصورة إلى تدرجات الرمادي
image = image.convert('L')

# تحويل الصورة إلى مصفوفة numpy
pixels = np.array(image)

# تعريف مجموعة من الرموز لتمثيل درجات الرمادي
ascii_chars = "@%#*+=- "

# تحويل بكسلات الصورة إلى ASCII art
ascii_art = ""
for row in pixels:
    for pixel in row:
        ascii_art += ascii_chars[pixel // 32]
    ascii_art += "\n"

# عرض ASCII art في التيرمنال
print(colored(ascii_art, 'green'))





def execute_netstat():
    command = "netstat -ano"
    output = subprocess.check_output(command, shell=True).decode('utf-8')
    return output

def parse_netstat_output(output, proto_filter=None, port_filter=None):
    lines = output.split('\n')[4:]
    results = []
    for line in lines:
        line = line.strip()
        if line:
            columns = line.split()
            if len(columns) >= 5:
                proto, local_addr, foreign_addr, state, pid = columns[:5]
                if proto_filter and proto.lower() != proto_filter.lower():
                    continue
                if port_filter and f":{port_filter}" not in local_addr:
                    continue
                results.append((proto, local_addr, foreign_addr, state, pid))
    return results

def get_process_path(pid):
    try:
        process = psutil.Process(int(pid))
        return process.exe()
    except Exception:
        return "Access Denied / Not Found"

def display_results(data):
    headers = ["Protocol", "Local Address", "Foreign Address", "State", "PID", "Path"]
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))

def main():
    parser = argparse.ArgumentParser(description="NetPIDTracer - Network PID to Path Analyzer")
    parser.add_argument("--proto", help="Filter by protocol (TCP/UDP)")
    parser.add_argument("--port", help="Filter by port number")
    parser.add_argument("--output", help="File to save results", default="netpid_output.txt")
    args = parser.parse_args()

    output = execute_netstat()
    parsed_data = parse_netstat_output(output, args.proto, args.port)

    enriched_data = []
    for proto, local, foreign, state, pid in parsed_data:
        path = get_process_path(pid)
        enriched_data.append((proto, local, foreign, state, pid, path))

    display_results(enriched_data)

    with open(args.output, 'w', encoding='utf-8') as f:
        for row in enriched_data:
            f.write(" | ".join(row) + "\n")

if __name__ == '__main__':
    if platform.system() != "Windows":
        print("This tool runs only on Windows.")
    else:
        main()
