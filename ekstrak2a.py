import os
import pefile
import pandas as pd
import math
import hashlib
from tqdm import tqdm

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
            'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),  # BaseOfData is not always present
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
            'SectionsMinEntropy': min(section.get_entropy() for section in pe.sections) if pe.sections else 0,
            'SectionsMaxEntropy': max(section.get_entropy() for section in pe.sections) if pe.sections else 0,
            'SectionsMeanRawsize': sum(section.SizeOfRawData for section in pe.sections) / len(pe.sections) if pe.sections else 0,
            'SectionsMinRawsize': min(section.SizeOfRawData for section in pe.sections) if pe.sections else 0,
            'SectionMaxRawsize': max(section.SizeOfRawData for section in pe.sections) if pe.sections else 0,
            'SectionsMeanVirtualsize': sum(section.Misc_VirtualSize for section in pe.sections) / len(pe.sections) if pe.sections else 0,
            'SectionsMinVirtualsize': min(section.Misc_VirtualSize for section in pe.sections) if pe.sections else 0,
            'SectionMaxVirtualsize': max(section.Misc_VirtualSize for section in pe.sections) if pe.sections else 0,
            'ImportsNbDLL': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'ImportsNb': sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'ImportsNbOrdinal': sum(1 for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports if imp.ordinal) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'ExportNb': len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            'ResourcesNb': len(resource_entries),
            'ResourcesMeanEntropy': sum(entry['Entropy'] for entry in resource_entries) / len(resource_entries) if resource_entries else 0,
            'ResourcesMinEntropy': min(entry['Entropy'] for entry in resource_entries) if resource_entries else 0,
            'ResourcesMaxEntropy': max(entry['Entropy'] for entry in resource_entries) if resource_entries else 0,
            'ResourcesMeanSize': sum(entry['Size'] for entry in resource_entries) / len(resource_entries) if resource_entries else 0,
            'ResourcesMinSize': min(entry['Size'] for entry in resource_entries) if resource_entries else 0,
            'ResourcesMaxSize': max(entry['Size'] for entry in resource_entries) if resource_entries else 0,
            'LoadConfigurationSize': pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') else 0,
            'VersionInformationSize': len(pe.FileInfo) if hasattr(pe, 'FileInfo') else 0
        }
        return pe_header
    except pefile.PEFormatError:
        return None
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

# Proses file dalam direktori
def process_directory(directory):
    pe_headers = []
    files = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files if file.endswith(('.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.efi'))]
    
    for file_path in tqdm(files, desc="Processing files"):
        pe_header = extract_pe_headers(file_path)
        if pe_header:
            pe_headers.append(pe_header)
    return pe_headers

# Direktori yang berisi file-file malware
directory_path = '/Users/ancla/Desktop/skrip/thesis/unzip-mine-extract/'

# Ekstraksi header PE dari file dalam direktori
pe_headers = process_directory(directory_path)

# Konversi hasil ekstraksi ke DataFrame
df = pd.DataFrame(pe_headers)

# Simpan hasil ekstraksi ke file CSV
output_csv_path = 'unzip_mine_peheaders.csv'
df.to_csv(output_csv_path, index=False)

print(f'PE headers have been extracted and saved to {output_csv_path}')
