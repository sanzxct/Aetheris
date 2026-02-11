#format of signatures by default
FILE_SIGNATURES = {
    # IMAGES
    'JPEG': {'hex': b'\xFF\xD8\xFF', 'offset': 0, 'description': 'Joint Photographic Experts Group'},
    'PNG':  {'hex': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 'offset': 0, 'desc': 'Portable Network Graphics'},
    'GIF':  {'hex': b'\x47\x49\x46\x38', 'offset': 0, 'desc': 'Graphics Interchange Format (GIF87a/89a)'},
    'BMP':  {'hex': b'\x42\x4D', 'offset': 0, 'desc': 'Windows Bitmap'},
    'TIFF_LE': {'hex': b'\x49\x49\x2A\x00', 'offset': 0, 'desc': 'TIFF Image (Little Endian)'},
    'TIFF_BE': {'hex': b'\x4D\x4D\x00\x2A', 'offset': 0, 'desc': 'TIFF Image (Big Endian)'},
    'WEBP': {'hex': b'\x57\x45\x42\x50', 'offset': 8, 'desc': 'Google WebP Image'},

    # DOCUMENTS
    'PDF':  {'hex': b'\x25\x50\x44\x46', 'offset': 0, 'desc': 'Adobe Portable Document Format'},
    'RTF':  {'hex': b'\x7B\x5C\x72\x74\x66', 'offset': 0, 'desc': 'Rich Text Format'},
    'MS_OFFICE_OLD': {'hex': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'offset': 0, 'desc': 'MS Office Compound File (Doc/Xls/Ppt)'},
    
    # ARCHIVES (Note: docx, xlsx, pptx detected as ZIP)
    'ZIP':  {'hex': b'\x50\x4B\x03\x04', 'offset': 0, 'desc': 'ZIP Archive / Modern MS Office'},
    'RAR_V4': {'hex': b'\x52\x61\x72\x21\x1A\x07\x00', 'offset': 0, 'desc': 'RAR Archive v1.5+'},
    'RAR_V5': {'hex': b'\x52\x61\x72\x21\x1A\x07\x01\x00', 'offset': 0, 'desc': 'RAR Archive v5.0+'},
    '7Z':   {'hex': b'\x37\x7A\xBC\xAF\x27\x1C', 'offset': 0, 'desc': '7-Zip Compressed File'},
    'GZIP': {'hex': b'\x1F\x8B', 'offset': 0, 'desc': 'GZIP Compressed File'},

    # EXECUTABLES / BINARY
    'EXE_DLL': {'hex': b'\x4D\x5A', 'offset': 0, 'desc': 'Windows Executable (MZ)'},
    'ELF':  {'hex': b'\x7F\x45\x4C\x46', 'offset': 0, 'desc': 'Linux Executable (ELF)'},
    'MACHO_64': {'hex': b'\xFE\xED\xFA\xCF', 'offset': 0, 'desc': 'macOS Mach-O 64-bit'},
    'JAVA_CLASS': {'hex': b'\xCA\xFE\xBA\xBE', 'offset': 0, 'desc': 'Java Class File'},
    
    # SYSTEM & DATABASE
    'SQLITE': {'hex': b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33', 'offset': 0, 'desc': 'SQLite Database'},
    'PCAP': {'hex': b'\xD4\xC3\xB2\xA1', 'offset': 0, 'desc': 'Libpcap Network Capture (LE)'},
    'PCAP_BE': {'hex': b'\xA1\xB2\xC3\xD4', 'offset': 0, 'desc': 'Libpcap Network Capture (BE)'},
}