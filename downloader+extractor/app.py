#!/usr/bin/python

import requests
import os
import sqlite3
import pyzipper
from tqdm import tqdm
from fuzzywuzzy import fuzz
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed
import logging

# Setup logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# SQLite Setup
def setup_database():
    conn = sqlite3.connect("downloaded_files.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS downloads (
            sha256 TEXT PRIMARY KEY,
            file_path TEXT,
            tag TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS search_history (
            tag TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()

def is_already_downloaded(sha256):
    conn = sqlite3.connect("downloaded_files.db")
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM downloads WHERE sha256 = ?", (sha256,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def save_to_database(sha256, file_path, tag):
    try:
        conn = sqlite3.connect("downloaded_files.db")
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO downloads (sha256, file_path, tag) VALUES (?, ?, ?)", (sha256, file_path, tag))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

def save_to_history(tag):
    try:
        conn = sqlite3.connect("downloaded_files.db")
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO search_history (tag) VALUES (?)", (tag,))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def safe_request_post(url, data):
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response

def fetch_file_details(tags, similarity_threshold):
    resultsSHA = {}
    tags = [tag.strip().lower() for tag in tags.split(',')]

    for tag in tags:
        offset = 0
        resultsSHA[tag] = []
        while True:
            query = {"query": "get_taginfo", "tag": tag, "limit": 1000, "offset": offset}
            try:
                response = safe_request_post("https://mb-api.abuse.ch/api/v1/", query)
                data = response.json()
            except Exception as e:
                logging.error(f"API error for tag '{tag}': {e}")
                break

            if "data" not in data or not data["data"]:
                break

            # Hanya pilih hash dengan file tipe `exe`
            sha256_hashes = [
                sample["sha256_hash"]
                for sample in data["data"]
                if fuzz.partial_ratio(tag, " ".join(sample.get("tags", [])).lower()) >= similarity_threshold
                and sample.get("file_type", "").lower() == "exe"  # Filter hanya file exe
            ]
            resultsSHA[tag].extend(sha256_hashes)

            if len(sha256_hashes) < 1000:
                break

            offset += 1000

        if resultsSHA[tag]:
            save_to_history(tag)

    # Deduplicate hasil
    return {tag: list(set(files)) for tag, files in resultsSHA.items()}


def download_and_extract_files(sha256_list, tags, password, threads):
    base_directory = os.path.dirname(os.path.abspath(__file__))
    zip_directory = os.path.join(base_directory, "zip")
    exe_directory = os.path.join(base_directory, "exe")
    os.makedirs(zip_directory, exist_ok=True)
    os.makedirs(exe_directory, exist_ok=True)

    def download_file(sha256, tag):
        tag_dir = os.path.join(zip_directory, tag)
        os.makedirs(tag_dir, exist_ok=True)  # Pastikan direktori dibuat
        file_path = os.path.join(tag_dir, f"{sha256}.zip")

        if is_already_downloaded(sha256):
            logging.info(f"File {sha256} already downloaded.")
            return None

        try:
            response = safe_request_post("https://mb-api.abuse.ch/api/v1/", {"query": "get_file", "sha256_hash": sha256})
            with open(file_path, "wb") as file:
                file.write(response.content)
            save_to_database(sha256, file_path, tag)
        except Exception as e:
            logging.error(f"Error downloading file {sha256}: {e}")
        return file_path

    # Filter hanya tag dengan hasil pencarian
    filtered_sha256_list = {tag: hashes for tag, hashes in sha256_list.items() if hashes}

    # Proses unduhan file
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(download_file, sha256, tag)
            for tag, hashes in filtered_sha256_list.items()
            for sha256 in hashes
        ]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading files"):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Thread error: {e}")

    # Proses ekstraksi file
    for tag, hashes in filtered_sha256_list.items():
        tag_dir = os.path.join(zip_directory, tag)
        if not os.path.exists(tag_dir) or not os.listdir(tag_dir):
            logging.info(f"No files to extract for tag: {tag}")
            continue

        zip_files = [os.path.join(tag_dir, f) for f in os.listdir(tag_dir) if f.endswith('.zip')]

        for file_path in tqdm(zip_files, desc=f"Extracting files for tag {tag}"):
            try:
                with pyzipper.AESZipFile(file_path, 'r') as zf:
                    zf.pwd = bytes(password, "UTF-8")
                    zf.extractall(exe_directory)  # Ekstrak langsung ke folder 'exe'
                    logging.info(f"Extracted: {file_path}")
            except Exception as e:
                logging.error(f"Extraction error for {file_path}: {e}")

    logging.info("Download and extraction completed.")

    # Otomatis Ekstraksi PE-header setelah proses ekstraksi
    st.info("Starting PE Header Extraction...")
    pe_headers = process_directory(exe_directory)
    if pe_headers:
        # Cek apakah file CSV sudah ada
        output_csv_path = os.path.join(exe_directory, "pe_headers.csv")
        if os.path.exists(output_csv_path):
            # Jika ada, gabungkan tanpa duplikat
            existing_df = pd.read_csv(output_csv_path)
            new_df = pd.DataFrame(pe_headers)
            combined_df = pd.concat([existing_df, new_df]).drop_duplicates(subset=["Name", "md5"])
        else:
            # Jika belum ada, buat file baru
            combined_df = pd.DataFrame(pe_headers)

        # Simpan ke file CSV
        combined_df.to_csv(output_csv_path, index=False)
        st.success(f"PE headers extracted and saved to {output_csv_path}")
    else:
        st.warning("No PE headers extracted.")



# Tambahkan bagian ini ke kode Anda setelah fungsi download_and_extract_files()

import pefile
import pandas as pd
import math
import hashlib

# Fungsi untuk menghitung entropi
def calculate_entropy(data):
    if not data:
        return 0
    occurences = [0] * 256
    for byte in data:
        occurences[byte] += 1

    entropy = 0
    for count in occurences:
        if count == 0:
            continue
        p_x = count / len(data)
        entropy -= p_x * math.log2(p_x)

    return entropy

# Fungsi untuk mendapatkan hash MD5
def get_md5_hash(file_path):
    with open(file_path, "rb") as file:
        hash_md5 = hashlib.md5()
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Fungsi untuk mengekstrak header PE
def extract_pe_headers(file_path):
    try:
        pe = pefile.PE(file_path)
        resource_entries = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, 'data'):
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    entropy = calculate_entropy(data)
                                    resource_entries.append({
                                        'Size': resource_lang.data.struct.Size,
                                        'Entropy': entropy
                                    })

        pe_header = {
            'Name': os.path.basename(file_path),
            'md5': get_md5_hash(file_path),
            'Machine': pe.FILE_HEADER.Machine,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            'SectionsNb': len(pe.sections),
            'SectionsMeanEntropy': sum(section.get_entropy() for section in pe.sections) / len(pe.sections) if pe.sections else 0,
            'ResourcesNb': len(resource_entries),
            'ResourcesMeanEntropy': sum(entry['Entropy'] for entry in resource_entries) / len(resource_entries) if resource_entries else 0,
            'LoadConfigurationSize': pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') else 0,
        }
        return pe_header
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return None

# Fungsi untuk memproses file dalam direktori
def process_directory(directory):
    pe_headers = []
    files = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files if file.endswith(('.exe', '.dll', '.sys'))]
    for file_path in tqdm(files, desc="Extracting PE Headers"):
        pe_header = extract_pe_headers(file_path)
        if pe_header:
            pe_headers.append(pe_header)
    return pe_headers

# Tambahkan fungsi ini setelah proses download selesai
if st.button("Extract PE Headers"):
    # Proses direktori 'exe'
    exe_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exe")
    if os.path.exists(exe_directory):
        st.info("Extracting PE headers. This may take some time...")
        pe_headers = process_directory(exe_directory)
        if pe_headers:
            # Simpan hasil ke CSV
            df = pd.DataFrame(pe_headers)
            output_csv_path = os.path.join(exe_directory, "pe_headers.csv")
            df.to_csv(output_csv_path, index=False)
            st.success(f"PE headers extracted and saved to {output_csv_path}")
        else:
            st.warning("No PE headers extracted.")
    else:
        st.error("The directory 'exe' does not exist. Please complete the download process first.")

# Streamlit Interface
st.title("Babarsari43 Malware Sample Downloader")
setup_database()

# Input fields
tags = st.text_input("Enter tags (comma-separated):", "")
password = st.text_input("Password for zip files:", "infected")
threads = st.number_input("Number of threads:", min_value=1, max_value=20, value=5)

# Limit and similarity slider
limit_options = ["Unlimited"] + [str(i) for i in range(100, 10001, 100)]
limit_selected = st.selectbox("Limit the number of samples to download:", options=limit_options, index=0)
similarity_threshold = st.slider("Similarity threshold for fuzzy matching:", min_value=0, max_value=100, value=80)

# Initialize session state for UI control
if "download_visible" not in st.session_state:
    st.session_state["download_visible"] = False
if "search_results" not in st.session_state:
    st.session_state["search_results"] = {}
if "download_success" not in st.session_state:
    st.session_state["download_success"] = False

# Search Files
if st.button("Search Files", key="search_button"):
    if not tags.strip():
        st.error("Tags cannot be empty!")
    else:
        # Reset UI states
        st.session_state["download_visible"] = False
        st.session_state["download_success"] = False

        with st.spinner("Searching..."):
            st.session_state["search_results"] = fetch_file_details(tags, similarity_threshold)

        # Count total files found
        total_files = sum(len(files) for files in st.session_state["search_results"].values())
        st.write(f"Found {total_files} files matching the tags: {tags}")

        # Handle cases for no results or results found
        if total_files == 0:
            st.warning("No files found matching the tags provided.")
        else:
            st.session_state["download_visible"] = True  # Show Download button
            for tag, files in st.session_state["search_results"].items():
                already_downloaded_count = sum(1 for sha256 in files if is_already_downloaded(sha256))
                st.write(f"- {tag}: {len(files)} files ({already_downloaded_count} already downloaded)")

# Show Download Button Only If Search Results Exist
if st.session_state["download_visible"] and not st.session_state["download_success"]:
    if st.button("Download", key="download_button"):
        # Prepare for download
        sha256_list = st.session_state["search_results"]
        if limit_selected != "Unlimited":
            limit = int(limit_selected)
            sha256_list = {tag: files[:limit] for tag, files in sha256_list.items()}

        # Execute download and extraction
        download_and_extract_files(sha256_list, sha256_list.keys(), password, threads)

        # Update UI state after download
        st.session_state["download_visible"] = False  # Hide Download button
        st.session_state["download_success"] = True  # Mark download success

# Display Success Message If Download Completed
if st.session_state["download_success"]:
    st.success("Download and extraction process completed!")
    st.info("Ready for a new search.")


