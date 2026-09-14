import json


class CustomJSONEncoder(json.JSONEncoder):
    """
    Expert JSON Encoder that handles bytes and other non-serializable objects 
    returned by YARA and internal bx2trace components.
    """

    def default(self, obj):
        if isinstance(obj, bytes):
            try:
                # Try decoding as UTF-8 for readable strings
                return obj.decode('utf-8', errors='ignore')
            except:
                # Fallback to hex representation for binary data
                return obj.hex()

        # Handle datetime if present in any payload
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()

        # Fallback to string representation for anything else to prevent crashes
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)
