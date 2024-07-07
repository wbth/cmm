#!/usr/bin/python

import requests
import json
import argparse
import os
import pyzipper
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

parser = argparse.ArgumentParser(description="Pull samples from MalwareBazaar by specifying tags associated with the malware and download all available samples.")
parser.add_argument("tags", help="Specify the tags used on MalwareBazaar to identify the malware to download. Multiple tags can be specified separated by commas.")
parser.add_argument("--sample_directory", "-s", default=".", help="Specify a directory for saving the samples. Defaults to current directory.")
parser.add_argument("--unzip", "-u", help="Specify a directory for saving unzipped samples. Defaults to creating a directory named Unzipped.")
parser.add_argument("--password", "-p", default="infected", help="Specify a password for unzipping files. Defaults to 'infected'")
parser.add_argument("--threads", "-t", default=5, type=int, help="Specify the number of concurrent download threads. Defaults to 5.")
parser.add_argument("--limit", "-l", default=400, type=int, help="Specify the number of samples to download. Defaults to 400.")
args = parser.parse_args()

# Save the current directory in case we need it later
cwd = os.getcwd()

# If a directory was specified for saving samples, check if it exists. If it does not exist
# create the directory and then move into the directory.
if args.sample_directory:
    os.makedirs(args.sample_directory, exist_ok=True)

resultsSHA = []

# Split tags by comma
tags = args.tags.split(',')

# Make request for data for each tag with pagination
for tag in tags:
    offset = 0
    while True:
        query = {"query": "get_taginfo", "tag": tag.strip(), "limit": 1000, "offset": offset}
        dataRequest = requests.post("https://mb-api.abuse.ch/api/v1/", data=query)
        
        # Throw error if request did not complete successfully
        dataRequest.raise_for_status()
        
        # Convert response to form usable by python script
        jsonString = dataRequest.text
        jsonPythonValue = json.loads(jsonString)
        
        if "data" not in jsonPythonValue:
            break
        
        # Collect SHA256 hashes of exe files
        sha256_hashes = [sample["sha256_hash"] for sample in jsonPythonValue["data"] if sample["file_type"] == "exe"]
        resultsSHA.extend(sha256_hashes)
        
        if len(sha256_hashes) < 1000:
            break
        
        offset += 1000

# Limit the number of results if specified
if args.limit:
    resultsSHA = resultsSHA[:args.limit]

# Display the number of samples found and prompt user for confirmation
print(f"Number of samples found: {len(resultsSHA)}")

proceed = input("Do you want to download these samples? (yes/no): ")
if proceed.lower() != "yes":
    print("Download cancelled.")
    exit()

def download_file(sha256, sample_directory):
    file_path = os.path.join(sample_directory, sha256 + '.zip')
    if not os.path.exists(file_path):
        query = {"query": "get_file", "sha256_hash": sha256}
        fileRequest = requests.post("https://mb-api.abuse.ch/api/v1/", data=query)
        with open(file_path, "wb") as filetosave:
            for chunk in fileRequest.iter_content(chunk_size=8192):
                filetosave.write(chunk)
    return file_path

# Download files concurrently
with ThreadPoolExecutor(max_workers=args.threads) as executor:
    futures = [executor.submit(download_file, sha256, args.sample_directory) for sha256 in resultsSHA]
    for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading samples"):
        future.result()

# Go back to the original directory if needed
if args.unzip:
    if os.getcwd() != cwd:
        os.chdir(cwd)

    # Ensure the unzip directory exists
    os.makedirs(args.unzip, exist_ok=True)

    zip_files = [os.path.join(args.sample_directory, f) for f in os.listdir(args.sample_directory) if f.endswith('.zip')]

    for file_path in tqdm(zip_files, desc="Extracting samples"):
        try:
            with pyzipper.AESZipFile(file_path, 'r') as zf:
                zf.pwd = bytes(args.password, "UTF-8")
                zf.extractall(args.unzip)
        except Exception as e:
            print(f"Failed to extract {file_path}: {e}")

print("Download and extraction process completed.")
