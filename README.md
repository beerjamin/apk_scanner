# apk_scanner

This project is used to scan apks for strange or suspicious behavior.

## Dependencies

[apktool](https://apktool.org/docs/install/) If you dont have it, go ahead and install it.

apktool is used to decompile the apk in order to parse the Manifest for Dangerous permissions and scan the classes for hardcoded urls.

## Usage

`python3 scan_apk.py yourapk.apk out/`
