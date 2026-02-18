import os 
import time 
import mimetypes 
import stat

class UniversalParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def get_system_metadata(self):
        try:
            file_stats = os.stat(self.file_path)
            mime_type, _ = mimetypes.guess_type(self.file_path)
            perms = stat.filemode(file_stats.st_mode)

            return {
                "MIME Type": mime_type or "application/octet-stream",
                "Permissions": perms,
                "Size (Bytes)": file_stats.st_size,
                "Created": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stats.st_ctime)),
                "Modified": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stats.st_mtime)),
                "Accessed": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stats.st_atime))
            }

        except Exception as e:
            return {
                'error': str(e)
            }