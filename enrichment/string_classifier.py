import re


class StringClassifier:
    """
    Classifies raw memory strings extracted by bx2trace into meaningful IOC categories.
    Filters out noise and groups data for the final analyst report.
    """

    URL_PATTERN  = re.compile(r'(?:https?://|www\.)[^\s"\'<>]{4,}', re.IGNORECASE)
    IP_PATTERN   = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    PATH_PATTERN = re.compile(r'(?:[A-Za-z]:\\[^\s"\'<>|]{3,}|\\{2}[^\s"\'<>|]{3,})')
    REG_PATTERN  = re.compile(r'(HKEY_|HKLM\\|HKCU\\|SOFTWARE\\)[^\s"\']{4,}', re.IGNORECASE)
    CMD_PATTERN  = re.compile(r'\b(cmd|powershell|wscript|cscript|mshta|regsvr32)\b', re.IGNORECASE)

    # Assembly epilogue/prologue sequences — these are x64 register-save patterns
    # that appear as raw bytes in memory dumps. They have zero analytical value.
    _ASSEMBLY_GARBAGE_PATTERN = re.compile(
        r'^[A-Z0-9+$\[\]^_;!@#%&*()\-=<>,.?/\\|~` ]{5,}$'
    )

    # Minimum string length to avoid single-token noise
    MIN_LENGTH = 5

    # .NET / Windows assembly version patterns — octets like X.0.0.0 or X.Y.0.0
    # are not network IPs; they are version numbers embedded in assembly metadata.
    @staticmethod
    def _is_version_number(ip_str: str) -> bool:
        """
        Returns True if the IP string looks like a .NET or Windows assembly
        version number rather than a real network address.
        Rules:
        - If the last two octets are both 0 (e.g., 4.0.0.0, 13.0.0.0), it's a version.
        - If all octets are below 20, it's almost certainly a version (e.g., 5.9.0.0).
        """
        parts = ip_str.strip().split('.')
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        # Last two octets are zero → version number pattern (e.g., 4.0.0.0)
        if octets[2] == 0 and octets[3] == 0:
            return True
        # All octets tiny → version number (e.g., 5.9.0.0)
        if all(o < 20 for o in octets):
            return True
        return False

    @staticmethod
    def _is_assembly_garbage(s: str) -> bool:
        """
        Detects x64 assembly epilogue/prologue strings that appear as raw memory
        artifacts. These patterns match register-save sequences like:
          UAWAVAUATWVSH, D$0+A8;A suA, Ki_^!Q, [^_A\\A]A^A_]
        Returns True if the string should be discarded as noise.
        """
        # High ratio of non-alphanumeric symbols relative to length → garbage
        non_alpha = sum(1 for c in s if not c.isalnum() and c != ' ')
        if len(s) > 0 and non_alpha / len(s) > 0.5:
            return True
        # Pure uppercase letter clusters typical of x64 epilogues
        if re.fullmatch(r'[A-Z]{4,}', s):
            return True
        return False

    def classify(self, strings: list) -> dict:
        """
        Takes a raw list of strings and returns a categorized dictionary.
        Short strings (under MIN_LENGTH) are discarded to reduce noise.
        Assembly garbage and version numbers are filtered out.
        """
        # Use sets to avoid O(N^2) list searches
        result = {
            "URLs":               set(),
            "File Paths":         set(),
            "Network Indicators": set(),
            "Registry Keys":      set(),
            "Suspicious Commands":set(),
            "Miscellaneous":      set(),
        }

        for s in strings:
            if not isinstance(s, str) or len(s) < self.MIN_LENGTH:
                continue
            # Drop assembly garbage before classifying
            if self._is_assembly_garbage(s):
                continue

            if self.URL_PATTERN.search(s):
                result["URLs"].add(s)
            elif self.IP_PATTERN.search(s.strip()):
                # Extract the matched IP and validate it is not a version number
                match = self.IP_PATTERN.search(s.strip())
                if match and not self._is_version_number(match.group()):
                    result["Network Indicators"].add(s)
                else:
                    result["Miscellaneous"].add(s)
            elif self.PATH_PATTERN.match(s):
                result["File Paths"].add(s)
            elif self.REG_PATTERN.match(s):
                result["Registry Keys"].add(s)
            elif self.CMD_PATTERN.search(s):
                result["Suspicious Commands"].add(s)
            else:
                result["Miscellaneous"].add(s)

        # Convert sets back to lists for JSON serialization; remove empty categories
        return {k: list(v) for k, v in result.items() if v}
