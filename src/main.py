import sys
import os 

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.reader import AetherisReader
from utils.crypto import AetherisCrypto
from parsers.image import ImageMetadataParser
from parsers.document import PDFMetadataParser 
from parsers.executable import ExecutableParser
from parsers.strings import StringsExtractor

def main():
    print("=" * 60)
    print(" AETHERIS 1.0 ")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("[!] Usage: python3 main.py <target_file>")
        return

    file_path = sys.argv[1]

    try:
        engine = AetherisReader(file_path)
        crypto = AetherisCrypto(file_path)

        file_fmt, info = engine.identify_format()
        description = info.get('description')
        category = info.get('category')
        stats = engine.get_basic_stats()
        hashes = crypto.get_file_hashes()

        print(f"[*] Filename  : {stats['file_name']}")
        print(f"[*] Category  : {category}")
        print(f"[+] Magic Type: {file_fmt} ({description})")
        print(f"[+] File Size : {stats['file_size']} bytes")

        print("-" * 30)
        print(f"[#] MD5       : {hashes.get('md5')}")
        print(f"[#] SHA-1     : {hashes.get('sha1')}")
        print(f"[#] SHA-256   : {hashes.get('sha256')}")
        print("-" * 30)

        if category == "IMAGE":
            print("[*] Extracting Image Metadata (EXIF)...")
            img_parser = ImageMetadataParser(file_path)
            exif = img_parser.extract_exif()

            if exif and "error" not in exif:
                max_display = 15
                keys = list(exif.keys())
                for key in keys[:max_display]:
                    val = exif[key]
                    print(f"    - {key:20}: {exif[key]}")

                    decoded = AetherisCrypto.quick_base64_decode(str(val))
                    if decoded:
                        print(f"      [!] Decoded Base64: {decoded}")
                
                if len(keys) > max_display:
                    print(f"    ... and {len(keys) - max_display} more metadata items.")
            elif "error" in exif:
                print(f"    [!] {exif['error']}")
            else:
                print("    [!] No EXIF metadata found.")
            print("-" * 40)

        elif category == "DOCUMENT" and file_fmt == "PDF":
            print("[*] Extracting PDF Metadata...")
            doc_parser = PDFMetadataParser(file_path)
            pdf_meta = doc_parser.extract_metadata()

            if pdf_meta and "error" not in pdf_meta:
                max_display = 15
                keys = list(pdf_meta.keys())
                for key in keys[:max_display]:
                    val = pdf_meta[key]
                    print(f"    - {key:20}: {pdf_meta[key]}")

                    decoded = AetherisCrypto.quick_base64_decode(str(val))
                    if decoded:
                        print(f"      [!] Decoded Base64: {decoded}")
                
                if len(keys) > max_display:
                    print(f"    ... and {len(keys) - max_display} more metadata items.")
            elif "error" in pdf_meta:
                print(f"    [!] {pdf_meta['error']}")
            else:
                print("    [!] No PDF metadata found.")
            print("-" * 40)

        elif category == "EXECUTABLE" and file_fmt == 'EXE_DLL':
            print("[*] Performing Executable (PE) Analysis...")
            exe_parser = ExecutableParser(file_path)
            exe_meta = exe_parser.extract_pe_info()

            if exe_meta and "error" not in exe_meta:
                for key, val in exe_meta.items():
                    if key == 'Sections':
                        print(f"    - Sections (Entropy) :")
                        for s in val:
                            print(f"        -> {s}")
                    else:
                        print(f"    - {key:20}: {val}")
            print("[*] Extracting Interesting Strings (IoCs)...")
            str_extractor = StringsExtractor(file_path)
            ioc_results = str_extractor.extract_strings()

            if ioc_results and "error" not in ioc_results:
                if ioc_results['ips']:
                    print(f"    - Found IPs   : {', '.join(ioc_results['ips'][:5])}")
                if ioc_results['urls']:
                    print(f"    - Found URLs  : {', '.join(ioc_results['urls'][:5])}")
                if ioc_results['interesting_files']:
                    print(f"    - Found Files : {', '.join(ioc_results['interesting_files'][:5])}")
            elif "error" in exe_meta:
                print(f"    [!] {exe_meta['error']}")
            print("-" * 40)


        declared_ext = stats['extension'].replace('.','')
        is_match = True
        
        if file_fmt != "UNKNOWN":
            is_match = (
                (declared_ext == file_fmt) or 
                (file_fmt == "JPEG" and declared_ext in ["JPG", "JPEG"]) or 
                (file_fmt == "EXE_DLL" and declared_ext in ["EXE", "DLL"]) or
                (file_fmt == "PNG" and declared_ext == "PNG") or
                (file_fmt == "PDF" and declared_ext == "PDF")
            )
            
        if not is_match:
            print(f"[!] ALERT: Extension Mismatch! File is {file_fmt} but named .{declared_ext}")

    except Exception as e:
        print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    main()