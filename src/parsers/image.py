from PIL import Image
from PIL.ExifTags import TAGS 

class ImageMetadataParser:
    def __init__(self, file_path):
        self.file_path = file_path
    
    def extract_exif(self):
        metadata = {}
        try:
            img = Image.open(self.file_path)
            exif_data = img.getexif()

            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)

                    if isinstance(value,(str,int,float)):
                        metadata[tag_name] = value


            return metadata

        except Exception as e:
            return {
                "error": f"Failed to extract metadata: {e}"
            }