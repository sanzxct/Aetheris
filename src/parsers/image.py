from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

class ImageMetadataParser:
    def __init__(self, file_path):
        self.file_path = file_path
    
    def extract_exif(self):
        results = {}
        try:
            img = Image.open(self.file_path)
            
            results['Image_Width'] = img.width
            results['Image_Height'] = img.height
            results['Color_Mode'] = img.mode
            results['Format_Description'] = getattr(img, 'format_description', 'N/A')
            
            exif_data = img.getexif()
            if not exif_data:
                return results


            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)

                if tag_name != "GPSInfo":
                    if isinstance(value, (str, int, float, bytes)):
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore').strip('\x00')
                            except:
                                value = str(value)
                        results[tag_name] = value


            gps_info = exif_data.get_ifd(0x8825) 
            if gps_info:
                for key in gps_info:
                    tag_name = GPSTAGS.get(key, key)
                    results[f"GPS_{tag_name}"] = gps_info[key]

            return results

        except Exception as e:
            return {"error": str(e)}