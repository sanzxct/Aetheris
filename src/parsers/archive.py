import zipfile
import datetime

class ArchiveParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract_zip_info(self):
        results = []

        try:
            with zipfile.ZipFile(self.file_path, 'r') as z:
                for info in z.infolist():
                    is_suspicious = any(info.filename.lower().endswith(ext) for ext in ['.exe', '.dll', '.bat', '.sys', '.sh', '.py', '.vbs'])

                    results.append({
                        "filename" : info.filename,
                        "file_size" : info.file_size,
                        "compressed_size" : info.compress_size,
                        "modified" : "%d-%02d-%02d %02d:%02d:%02d" % info.date_time,
                        "is_suspicious" : is_suspicious
                    })
            return results 
        except Exception as e:
            return {
                'error' : str(e)
            }