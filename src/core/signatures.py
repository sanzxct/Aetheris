FILE_SIGNATURES = {
    # IMAGES
    'JPEG': {'hex': b'\xFF\xD8\xFF', 'offset': 0, 'description': 'Joint Photographic Experts Group', 'category': 'IMAGE'},
    'PNG':  {'hex': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 'offset': 0, 'description': 'Portable Network Graphics', 'category': 'IMAGE'},
    'GIF':  {'hex': b'\x47\x49\x46\x38', 'offset': 0, 'description': 'Graphics Interchange Format (GIF87a/89a)', 'category': 'IMAGE'},
    'BMP':  {'hex': b'\x42\x4D', 'offset': 0, 'description': 'Windows Bitmap', 'category': 'IMAGE'},
    'TIFF_LE': {'hex': b'\x49\x49\x2A\x00', 'offset': 0, 'description': 'TIFF Image (Little Endian)', 'category': 'IMAGE'},
    'TIFF_BE': {'hex': b'\x4D\x4D\x00\x2A', 'offset': 0, 'description': 'TIFF Image (Big Endian)', 'category': 'IMAGE'},
    'WEBP': {'hex': b'\x57\x45\x42\x50', 'offset': 8, 'description': 'Google WebP Image', 'category': 'IMAGE'},

    # DOCUMENTS
    'PDF':  {'hex': b'\x25\x50\x44\x46', 'offset': 0, 'description': 'Adobe Portable Document Format', 'category': 'DOCUMENT'},
    'RTF':  {'hex': b'\x7B\x5C\x72\x74\x66', 'offset': 0, 'description': 'Rich Text Format', 'category': 'DOCUMENT'},
    'MS_OFFICE_OLD': {'hex': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'offset': 0, 'description': 'MS Office Compound File (Doc/Xls/Ppt)', 'category': 'DOCUMENT'},
    
    # ARCHIVES
    'ZIP':  {'hex': b'\x50\x4B\x03\x04', 'offset': 0, 'description': 'ZIP Archive / Modern MS Office', 'category': 'ARCHIVE'},
    'RAR_V4': {'hex': b'\x52\x61\x72\x21\x1A\x07\x00', 'offset': 0, 'description': 'RAR Archive v1.5+', 'category': 'ARCHIVE'},
    'RAR_V5': {'hex': b'\x52\x61\x72\x21\x1A\x07\x01\x00', 'offset': 0, 'description': 'RAR Archive v5.0+', 'category': 'ARCHIVE'},
    '7Z':   {'hex': b'\x37\x7A\xBC\xAF\x27\x1C', 'offset': 0, 'description': '7-Zip Compressed File', 'category': 'ARCHIVE'},
    'GZIP': {'hex': b'\x1F\x8B', 'offset': 0, 'description': 'GZIP Compressed File', 'category': 'ARCHIVE'},

    # EXECUTABLES / BINARY
    'EXE_DLL': {'hex': b'\x4D\x5A', 'offset': 0, 'description': 'Windows Executable (MZ)', 'category': 'EXECUTABLE'},
    'ELF':  {'hex': b'\x7F\x45\x4C\x46', 'offset': 0, 'description': 'Linux Executable (ELF)', 'category': 'EXECUTABLE'},
    'MACHO_64': {'hex': b'\xFE\xED\xFA\xCF', 'offset': 0, 'description': 'macOS Mach-O 64-bit', 'category': 'EXECUTABLE'},
    'JAVA_CLASS': {'hex': b'\xCA\xFE\xBA\xBE', 'offset': 0, 'description': 'Java Class File', 'category': 'EXECUTABLE'},
    
    # SYSTEM & DATABASE
    'SQLITE': {'hex': b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33', 'offset': 0, 'description': 'SQLite Database', 'category': 'DATABASE'},
    'PCAP': {'hex': b'\xD4\xC3\xB2\xA1', 'offset': 0, 'description': 'Libpcap Network Capture (LE)', 'category': 'NETWORK'},
    'PCAP_BE': {'hex': b'\xA1\xB2\xC3\xD4', 'offset': 0, 'description': 'Libpcap Network Capture (BE)', 'category': 'NETWORK'},
}