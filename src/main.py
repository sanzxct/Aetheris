import sys
import os 

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.reader import AetherisReader
from utils.crypto import AetherisCrypto
from parsers.image import ImageMetadataParser
from parsers.document import PDFMetadataParser 
from parsers.executable import ExecutableParser
from parsers.strings import StringsExtractor
from parsers.universal import UniversalParser
from parsers.archive import ArchiveParser

def analyze_file(file_path):
    if os.path.isdir(file_path):
        return

    print("\n" + "=" * 80)
    print(f" FILE: {os.path.basename(file_path).upper()}")
    print("=" * 80)

    try:
        engine = AetherisReader(file_path)
        crypto = AetherisCrypto(file_path)
        uni_parser = UniversalParser(file_path)
        str_extractor = StringsExtractor(file_path)

        file_fmt, info = engine.identify_format()
        description = info.get('description')
        category = info.get('category')
        stats = engine.get_basic_stats()
        hashes = crypto.get_file_hashes()

        print(f" [IDENTIFICATION]")
        print(f"  - {'Category':15}: {category}")
        print(f"  - {'Magic Type':15}: {file_fmt} ({description})")
        print(f"  - {'File Size':15}: {stats['file_size']} bytes")
        print(f"  - {'SHA-256':15}: {hashes.get('sha256')}")
        print("-" * 40)

        print(f" [SYSTEM METADATA]")
        sys_meta = uni_parser.get_system_metadata()
        if "error" not in sys_meta:
            for k, v in sys_meta.items():
                print(f"  - {k:15}: {v}")
        else:
            print(f"  [!] {sys_meta['error']}")
        print("-" * 40)

        print(f" [STRINGS & IOCS]")
        ioc_results = str_extractor.extract_strings()
        if ioc_results and "error" not in ioc_results:
            if ioc_results['ips']:
                print(f"  - Found IPs   : {', '.join(ioc_results['ips'][:5])}")
            if ioc_results['urls']:
                print(f"  - Found URLs  : {', '.join(ioc_results['urls'][:5])}")
            if ioc_results['interesting_files']:
                print(f"  - Found Files : {', '.join(ioc_results['interesting_files'][:5])}")
            
            if not any([ioc_results['ips'], ioc_results['urls'], ioc_results['interesting_files']]):
                print("  [!] No interesting strings found.")
        print("-" * 40)

        if category == "IMAGE":
            print(f" [IMAGE ANALYSIS]")
            img_parser = ImageMetadataParser(file_path)
            exif = img_parser.extract_exif()
            if exif and "error" not in exif:
                max_display = 10
                keys = list(exif.keys())
                for key in keys[:max_display]:
                    print(f"  - {key:15}: {exif[key]}")
            print("-" * 40)

        elif category == "DOCUMENT" and file_fmt == "PDF":
            print(f" [PDF ANALYSIS]")
            doc_parser = PDFMetadataParser(file_path)
            pdf_meta = doc_parser.extract_metadata()
            if pdf_meta and "error" not in pdf_meta:
                for key, val in list(pdf_meta.items())[:10]:
                    print(f"  - {key:15}: {val}")
            print("-" * 40)

        elif category == "EXECUTABLE" and file_fmt == 'EXE_DLL':
            print(f" [PE ANALYSIS]")
            exe_parser = ExecutableParser(file_path)
            exe_meta = exe_parser.extract_pe_info()
            if exe_meta and "error" not in exe_meta:
                for key, val in exe_meta.items():
                    if key == 'Sections':
                        print(f"  - Sections (Entropy):")
                        for s in val:
                            print(f"    -> {s}")
                    else:
                        print(f"  - {key:15}: {val}")
            print("-" * 40)

        elif category == "ARCHIVE" and file_fmt == "ZIP":
            print(f" [ARCHIVE ANALYSIS]")
            arc_parser = ArchiveParser(file_path)
            zip_contents = arc_parser.extract_zip_info()
            if isinstance(zip_contents, list):
                print(f"  - Total Files : {len(zip_contents)}")
                for item in zip_contents[:10]:
                    status = "[!]" if item['is_suspicious'] else "[+]"
                    print(f"    {status} {item['filename']} ({item['file_size']} bytes)")
            elif isinstance(zip_contents, dict) and "error" in zip_contents:
                print(f"  [!] {zip_contents['error']}")
            print("-" * 40)

        declared_ext = stats['extension'].replace('.','')
        if file_fmt != "UNKNOWN":
            is_match = (
                (declared_ext == file_fmt) or 
                (file_fmt == "JPEG" and declared_ext in ["JPG", "JPEG"]) or 
                (file_fmt == "EXE_DLL" and declared_ext in ["EXE", "DLL"]) or
                (file_fmt == "PNG" and declared_ext == "PNG") or
                (file_fmt == "PDF" and declared_ext == "PDF")
            )
            if not is_match:
                print(f"\n [!] ALERT: Extension Mismatch! Real: {file_fmt} | Named: .{declared_ext}")

        print("=" * 80)

    except Exception as e:
        print(f" [!] Error analyzing {os.path.basename(file_path)}: {e}")

def main():
    if len(sys.argv) < 2:
        print("[!] Usage: python3 main.py <target_file_or_folder>")
        return

    target = sys.argv[1]

    print("\n" + "#" * 60)
    print(" AETHERIS ENGINE 1.0")
    print("#" * 60)

    if os.path.isfile(target):
        analyze_file(target)
    elif os.path.isdir(target):
        print(f"[*] Scanning Directory: {target}")
        for filename in sorted(os.listdir(target)):
            full_path = os.path.join(target, filename)
            if os.path.isfile(full_path) and not filename.startswith('.'):
                analyze_file(full_path)
    else:
        print(f"[!] Target not found: {target}")

if __name__ == "__main__":
    main()