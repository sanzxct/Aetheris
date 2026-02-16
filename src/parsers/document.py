from PyPDF2 import PdfReader

class PDFMetadataParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract_metadata(self):
        results = {}
        try:
            reader = PdfReader(self.file_path)
            meta = reader.metadata

            if meta:
                for key, value in meta.items():
                    clean_key = key.replace('/', '')
                    results[clean_key] = value

            results['Page_Count'] = len(reader.pages)
            results['Is_Encrypted'] = reader.is_encrypted

            return results

        except Exception as e:
            return {
                'error' : str(e)
            }
