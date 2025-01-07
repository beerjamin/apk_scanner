import os
import sys
import xml.etree.ElementTree as ET
import subprocess
import re

def decode_android_manifest_and_decompile(apk_file, output_dir):
    """
    Decompiles the APK and extracts the AndroidManifest.xml.

    Parameters:
        apk_file (str): The path to the APK file.
        output_dir (str): The directory to save the decompiled APK files.

    Returns:
        str: The path to the extracted AndroidManifest.xml.

    Raises:
        RuntimeError: If the decompilation fails.
    """
    if not os.path.isfile(apk_file):
        raise FileNotFoundError(f"The file '{apk_file}' does not exist.")

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    try:
        command = [
            "apktool",
            "d",
            apk_file,
            "-o",
            output_dir,
            "--force-all"
        ]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"Failed to decompile APK: {result.stderr.strip()}")

        return os.path.join(output_dir, "AndroidManifest.xml")

    except Exception as e:
        raise RuntimeError(f"Error during APK decompilation: {e}")

def parse_android_permissions(manifest_file):
    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()

        permissions = []
        for element in root.iter("uses-permission"):
            permission = element.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if permission:
                permissions.append(permission)

        return permissions
    except Exception as e:
        raise RuntimeError(f"Failed to parse AndroidManifest.xml: {e}")

def check_dangerous_permissions(permission_list):
    dangerous_permissions = {
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.BODY_SENSORS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    }

    found_dangerous = [perm for perm in permission_list if perm in dangerous_permissions]
    return found_dangerous

def decompiled_search_urls(output_dir):
    url_pattern = re.compile(r'\b(?:http|ws|tcp|udp)://[\w.-]+(?:/[^\s]*)?')
    excluded_domains = {"www.w3.org", "google.com", "mozilla.org", "duckduckgo.com",
                    "http://schemas.android.com", "https://www.example.com" , "www.apache.org",
                    "www.android.com", "www.youtube.com", "bugs.chromium.org", "www.slf4j.org",
                    "developer.android", "ns.adobe.com", "www.figma.com"}
    matching_files = {}

    for root, _, files in os.walk(output_dir):
        # Skip files in the res/ subfolder
        if "res" in root.split(os.path.sep):
            continue

        for file in files:
            # Skip XML files
            if file.endswith(".xml"):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    urls = url_pattern.findall(content)
                    filtered_urls = [url for url in urls if all(domain not in url for domain in excluded_domains)]
                    filtered_urls = list(dict.fromkeys(filtered_urls))
                    if filtered_urls:
                        matching_files[file_path] = filtered_urls
            except Exception:
                continue

    return matching_files

def write_html_table(output_file, matching_files):
    with open(output_file, 'w', encoding='utf-8') as out_file:
        out_file.write("<html><body><table border='1'>")
        out_file.write("<tr><th>File Path</th><th>URLs</th></tr>")
        for file_path, urls in matching_files.items():
            out_file.write(f"<tr><td>{file_path}</td><td>{' | '.join(urls)}</td></tr>")
        out_file.write("</table></body></html>")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <apk_file_path> <output_dir>")
        sys.exit(1)

    apk_file_path = sys.argv[1]
    output_directory = sys.argv[2]
    try:
        manifest_path = decode_android_manifest_and_decompile(apk_file_path, output_directory)
        print(f"AndroidManifest.xml extracted to: {manifest_path}")
        permissions = parse_android_permissions(manifest_path)
        dangerous_permissions = check_dangerous_permissions(permissions)
        if dangerous_permissions:
            print("Dangerous Permissions Found:")
            for perm in dangerous_permissions:
                print(perm)
        else:
            print("No dangerous permissions found.")

        # Search for URLs in decompiled files
        matching_files = decompiled_search_urls(output_directory)
        output_file = os.path.join(output_directory, 'hardcoded_links.html')
        if matching_files:
            write_html_table(output_file, matching_files)
            print("Hardcoded links were found, check the output file.")
        else:
            print("No URLs found in any files.")

    except Exception as e:
        print(f"Error: {e}")
