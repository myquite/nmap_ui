import itertools
import time
import tkinter as tk
from tkinter import scrolledtext
import threading
import nmap

def run_scan():
    def scan():
        try:
            nm = nmap.PortScanner()
            print("Scanning...")
            for c in itertools.cycle(['|', '/', '-', '\\']):
                if done:
                    break
                status_label.config(text=c)
                time.sleep(0.1)
            nm.scan(hosts=entry.get(), arguments='-sV')
            print("Scan complete.")
            output_text.delete(1.0, tk.END)
            for host in nm.all_hosts():
                output_text.insert(tk.INSERT, f'Host: {host} ({nm[host].hostname()})\n')
                output_text.insert(tk.INSERT, f'State: {nm[host].state()}\n')
                for proto in nm[host].all_protocols():
                    output_text.insert(tk.INSERT, f'Protocol: {proto}\n')
                    lport = nm[host][proto].keys()
                    for port in lport:
                        output_text.insert(tk.INSERT, f'Port: {port}\tState: {nm[host][proto][port]["state"]}\n')
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            done = True
            status_label.config(text="Done")

    done = False
    threading.Thread(target=scan).start()

root = tk.Tk()
root.title("Nmap Scanner")

entry_label = tk.Label(root, text="Enter Host:")
entry_label.pack()

entry = tk.Entry(root)
entry.pack()

scan_button = tk.Button(root, text="Run Scan", command=run_scan)
scan_button.pack()

status_label = tk.Label(root, text="")
status_label.pack()

output_text = scrolledtext.ScrolledText(root)
output_text.pack()

root.mainloop()