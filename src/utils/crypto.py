import hashlib

class AetherisCrypto:
    def __init__(self, file_path):
        self.file_path = file_path

        self.buffer_size = 65536

    def get_file_hashes(self):
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(self.file_path, 'rb') as f:
                while True:
                    data = f.read(self.buffer_size)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)
                
            return {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        
        except Exception as e:
            return {
                'error': str(e)
            }