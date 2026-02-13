import sys
import os 


sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.reader import AetherisReader
from utils.crypto import AetherisCrypto
from parsers.image import ImageMetadataParser

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

        declared_ext = stats['extension'].replace('.', '')
        is_match = True


        if category == "IMAGE":
            print("[*] Extracting Image Metadata (EXIF)...")
            img_parser = ImageMetadataParser(file_path)
            exif = img_parser.extract_exif()

            if exif and "error" not in exif:
                max_display = 15
                keys = list(exif.keys())

                for key in keys[:max_display]:
                    print(f"    - {key:20}: {exif[key]}")
                
                # PESAN INI HARUS DI LUAR FOR LOOP (Sejajar dengan for)
                if len(keys) > max_display:
                    print(f"    ... and {len(keys) - max_display} more metadata items.")
            
            elif "error" in exif:
                print(f"    [!] {exif['error']}")
            else:
                print("    [!] No EXIF metadata found.")
            print("-" * 40)

        declared_ext = stats['extension'].replace('.','')
        is_match = True
        
        if file_fmt != "UNKNOWN":
            is_match = (
                (declared_ext == file_fmt) or 
                (file_fmt == "JPEG" and declared_ext in ["JPG", "JPEG"]) or 
                (file_fmt == "EXE_DLL" and declared_ext in ["EXE", "DLL"]) or
                (file_fmt == "PNG" and declared_ext == "PNG")
            )
            
        if not is_match:
            print(f"[!] ALERT: Extension Mismatch! File is {file_fmt} but named .{declared_ext}")


    except Exception as e:
        print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    main()