import os
from datetime import datetime

class ReportPathManager:
    """
    Handles flexible resolution for output report paths.
    Ensures directories exist and generates intelligent default names.
    """
    
    DEFAULT_DIR = "reports"
    
    @staticmethod
    def resolve(target_name: str, custom_path: str = None) -> str:
        """
        Resolves the final absolute path for the JSON report.
        - If custom_path is a directory: saves inside it with an auto-name.
        - If custom_path is a file path: saves exactly there.
        - If None: saves in the default 'reports' directory with an auto-name.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        auto_name = f"report_{target_name}_{timestamp}.json"
        
        if custom_path is None:
            os.makedirs(ReportPathManager.DEFAULT_DIR, exist_ok=True)
            return os.path.join(ReportPathManager.DEFAULT_DIR, auto_name)
            
        custom_path = os.path.abspath(custom_path)
        
        if custom_path.endswith('.json'):
            parent = os.path.dirname(custom_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            return custom_path
            
        os.makedirs(custom_path, exist_ok=True)
        return os.path.join(custom_path, auto_name)
