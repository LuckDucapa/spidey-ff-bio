import json
import requests
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colors
G = '\033[92m'  # Green
R = '\033[91m'  # Red
Y = '\033[93m'  # Yellow
C = '\033[96m'  # Cyan
W = '\033[0m'   # White/Reset
P = '\033[95m'  # Purple
B = '\033[1m'   # Bold

API_ENDPOINT = "https://spidey-ff-bio.vercel.app/bio"

def resolve_path(user_input):
    """Handles /, ~, /sdcard/ and relative paths."""
    clean = user_input.replace("'", "").replace('"', "").strip()
    if clean == "/":
        return os.getcwd()
    expanded = os.path.expanduser(clean)
    return os.path.abspath(expanded)

def get_file_from_folder(folder_path):
    """Lists files numbered [1], [2]..."""
    try:
        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f)) and not f.startswith('.')]
        files.sort()
        if not files:
            print(f"{R}[!] This folder is empty.{W}")
            return None

        print(f"\n{C}[*] Files found in: {B}{folder_path}{W}")
        print(f"{P}{'-'*40}{W}")
        for i, f in enumerate(files, 1):
            color = G if f.endswith('.json') else W
            print(f"{Y}[{i}] {color}{f}{W}")
        print(f"{P}{'-'*40}{W}")

        while True:
            choice = input(f"{B}>> Select a number (1-{len(files)}): {W}").strip()
            if not choice: continue
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                return os.path.join(folder_path, files[idx])
            print(f"{R}[!] Invalid number.{W}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{W}")
        return None

def process_account(account, bio_text):
    uid = str(account.get('uid', ''))
    password = account.get('password', '')
    
    if not uid or not password:
        return None, f"{R}[-] Skipped: Missing UID or Password{W}"
        
    payload = {
        "uid": uid, 
        "pass": password,
        "bio": bio_text
    }
    
    try:
        # Changed to requests.post
        response = requests.post(API_ENDPOINT, data=payload, timeout=15)
        
        # Parse JSON safely
        try:
            data = response.json()
        except json.JSONDecodeError:
            return None, f"{R}[x] Failed: {uid} | Invalid API Response{W}"

        # FIX 3: Check for code == 200 instead of status == 'success'
        if response.status_code == 200 and data.get('code') == 200:
            name = data.get('name', 'Unknown')
            # Extract status string (which will be "✅ Success" from your API)
            msg = data.get('status', 'Bio Updated') 
            return {"uid": uid, "name": name, "status": "updated"}, f"{G}[+] Success: {uid} | {name} | {msg}{W}"
            
        else:
            # FIX 4: Your API returns errors in 'error' or 'status' keys, not 'message'
            error_msg = data.get('error') or data.get('status') or 'Unknown API Error'
            return None, f"{R}[x] Failed: {uid} | {error_msg}{W}"
            
    except requests.exceptions.Timeout:
        return None, f"{Y}[!] Error: {uid} | Connection Timed Out{W}"
    except Exception as e:
        return None, f"{Y}[!] Error: {uid} | Connection Failed ({str(e)}){W}"

def main():
    while True:
        try:
            os.system('clear')
            print(f"{P}{'='*40}")
            print(f"{B}          AUTO BIO UPDATER           ")
            print(f"{'='*40}{W}\n")

            print(f"{C}Please enter the path to your accounts file:{W}")
            print(f"{Y}(Examples: /sdcard/data.json OR folder/accounts.json OR / for current){W}")
            
            user_input = input(f"{B}>> {W}").strip()
            if not user_input: continue

            path = resolve_path(user_input)
            input_file = None

            if os.path.exists(path):
                if os.path.isfile(path):
                    input_file = path
                elif os.path.isdir(path):
                    input_file = get_file_from_folder(path)
                
                if not input_file: continue
            else:
                print(f"{R}[!] Path not found: {path}{W}")
                time.sleep(2)
                continue

            # Load accounts
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                accounts_list = data.get('accounts', []) if isinstance(data, dict) else data

            if not accounts_list:
                print(f"{R}[!] No accounts found in file.{W}")
                time.sleep(2)
                continue

            print(f"\n{C}[*] Loaded {len(accounts_list)} accounts.{W}")
            
            # Ask for the Bio they want to set
            bio_text = input(f"\n{B}>> Enter the new Bio for all accounts: {W}").strip()
            if not bio_text:
                print(f"{R}[!] Bio cannot be empty.{W}")
                time.sleep(2)
                continue

            print(f"\n{C}[*] Starting bulk bio update...{W}\n")
            successful_updates = []

            with ThreadPoolExecutor(max_workers=15) as executor:
                # Pass the account and the bio_text to the process_account function
                futures = {executor.submit(process_account, acc, bio_text): acc for acc in accounts_list}
                for future in as_completed(futures):
                    result_data, log_msg = future.result()
                    print(log_msg)
                    if result_data:
                        successful_updates.append(result_data)

            # Saving logic (Logs successfully updated accounts)
            output_filename = "updated_bios_log.json"
            existing_logs = []
            if os.path.exists(output_filename):
                try:
                    with open(output_filename, 'r', encoding='utf-8') as f:
                        existing_logs = json.load(f)
                except: existing_logs = []

            if successful_updates:
                all_logs = existing_logs + successful_updates
                with open(output_filename, 'w', encoding='utf-8') as out_f:
                    json.dump(all_logs, out_f, indent=2)
                print(f"\n{G}[✔] Process Complete! Successfully updated {len(successful_updates)} accounts.{W}")
                print(f"{C}[*] Log saved to {output_filename}{W}")
            else:
                print(f"\n{R}[!] No accounts were successfully updated.{W}")

            input(f"\n{Y}Press [ENTER] to run again...{W}")

        except KeyboardInterrupt:
            print(f"\n\n{R}[!] Interrupted by user.{W}")
            print(f"{C}👋 Closing Auto Bio Updater... Have a great day!{W}\n\n")
            sys.exit(0)
        except Exception as e:
            print(f"{R}[!] Critical Error: {e}{W}")
            time.sleep(2)

if __name__ == "__main__":
    main()