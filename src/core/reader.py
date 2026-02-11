import os 
from core.signatures import FILE_SIGNATURES

class AetherisReader:
    def __init__ (self, target_path):
        self.target_path = target_path
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Path not found: {target_path}")

    def identify_format(self):
        """Analyze file using signature database with offset support."""
        try:
            with open(self.target_path, 'rb') as f:
                chunk = f.read(64)

                for fmt, info in FILE_SIGNATURES.items():
                    sig = info['hex']
                    off = info['offset']
                    
                    if len(chunk) >=off + len(sig):
                        if chunk[off:off+len(sig)] == sig:
                            return fmt, info['description']

                return "UNKNOWN", "unknown binary format"
        except Exception as e:
            return "UNKNOWN", f"Error during analysis: {str(e)}"

    def get_basic_stats(self):
        stats = os.stat(self.target_path)
        return {
            'file_name' : os.path.basename(self.target_path),
            'file_size' : stats.st_size,
            'abs_path'  : os.path.abspath(self.target_path),
            'extension' : os.path.splitext(self.target_path)[1].upper()
        }