import sys
import os 


sys.path.append(os.path.dirname(os.path.abspath(__file__)))


from core.reader import AetherisReader

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

        file_fmt, description = engine.identify_format()
        stats = engine.get_basic_stats()

        print(f"[*] Filename  : {stats['file_name']}")
        print(f"[+] Magic Type: {file_fmt} ({description})")
        print(f"[+] File Size : {stats['file_size']} bytes")

        declared_ext = stats['extension'].replace('.', '')
        is_match = True
        
        if file_fmt != "UNKNOWN":
            is_match = (
                (declared_ext == file_fmt) or 
                (file_fmt == "JPEG" and declared_ext in ["JPG", "JPEG"]) or 
                (file_fmt == "EXE_DLL" and declared_ext in ["EXE", "DLL"])
            )
            
        if not is_match:
            print(f"[!] ALERT: Extension Mismatch! File is {file_fmt} but named .{declared_ext}")


    except Exception as e:
        print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    main()