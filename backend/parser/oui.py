"""
Compact OUI (Organizationally Unique Identifier) lookup.

Maps the first 3 bytes of a MAC address (the OUI prefix) to a vendor name.
This is a curated subset of the IEEE OUI registry covering the most common
vendors seen in network captures.

Usage:
    from parser.oui import lookup_vendor
    vendor = lookup_vendor("aa:bb:cc:dd:ee:ff")  # returns "Apple" or ""
"""

from typing import Optional

# OUI → vendor name. Keys are uppercase 6-char hex strings (no colons).
_OUI: dict = {
    # Apple
    "000393": "Apple", "000502": "Apple", "000A27": "Apple", "000A95": "Apple",
    "000D93": "Apple", "001124": "Apple", "0016CB": "Apple", "001731": "Apple",
    "001921": "Apple", "001B63": "Apple", "001CB3": "Apple", "001E52": "Apple",
    "001EC2": "Apple", "001F5B": "Apple", "001FF3": "Apple", "0021E9": "Apple",
    "002241": "Apple", "002312": "Apple", "002500": "Apple", "00264B": "Apple",
    "003065": "Apple", "0050E4": "Apple", "006171": "Apple", "088665": "Apple",
    "0C1539": "Apple", "0C4DE9": "Apple", "0C74C2": "Apple", "0CABF0": "Apple",
    "100005": "Apple", "10DDB1": "Apple", "1499E2": "Apple", "18AF61": "Apple",
    "1C1AC0": "Apple", "1C5CF2": "Apple", "205AE5": "Apple", "20C9D0": "Apple",
    "241EEB": "Apple", "28CFE9": "Apple", "2CF0EE": "Apple", "34159E": "Apple",
    "38484C": "Apple", "3C0754": "Apple", "3C15C2": "Apple", "40A6D9": "Apple",
    "44D884": "Apple", "48437C": "Apple", "4C57CA": "Apple", "4C8D79": "Apple",
    "5C969D": "Apple", "60334B": "Apple", "60F4CA": "Apple", "64B9E8": "Apple",
    "682A7E": "Apple", "6C4008": "Apple", "6C709F": "Apple", "70700D": "Apple",
    "74E2F5": "Apple", "788FCA": "Apple", "7CC537": "Apple", "8466BB": "Apple",
    "8C0014": "Apple", "8C2DAA": "Apple", "8C7B9D": "Apple", "8CC8CD": "Apple",
    "90278B": "Apple", "9060F1": "Apple", "94BF2D": "Apple", "94F6A3": "Apple",
    "9C20AE": "Apple", "A41F72": "Apple", "A4B197": "Apple", "A8BE27": "Apple",
    "A8FAD8": "Apple", "ACBC32": "Apple", "B065BD": "Apple", "B418D1": "Apple",
    "B4F0AB": "Apple", "B8782E": "Apple", "B8E856": "Apple", "BC926B": "Apple",
    "C82A14": "Apple", "C86F1D": "Apple", "CC29F5": "Apple", "CC3A61": "Apple",
    "D0254E": "Apple", "D02B20": "Apple", "D49A20": "Apple", "D8004D": "Apple",
    "D8A25E": "Apple", "DC2B2A": "Apple", "DCA904": "Apple", "E0B52D": "Apple",
    "E0C767": "Apple", "F0B479": "Apple", "F0D1A9": "Apple", "F40F24": "Apple",
    "F4F15A": "Apple", "F81EDF": "Apple", "F8F0FA": "Apple",
    # Cisco
    "000142": "Cisco", "00017D": "Cisco", "0001C7": "Cisco", "000216": "Cisco",
    "00023D": "Cisco", "000268": "Cisco", "00024A": "Cisco", "000295": "Cisco",
    "0002B9": "Cisco", "0002FC": "Cisco", "000301": "Cisco", "000304": "Cisco",
    "00030F": "Cisco", "000340": "Cisco", "00034B": "Cisco", "000360": "Cisco",
    "0003E3": "Cisco", "0003FE": "Cisco", "000476": "Cisco", "0004C0": "Cisco",
    "0004DD": "Cisco", "000503": "Cisco", "000506": "Cisco", "00058A": "Cisco",
    "0005DC": "Cisco", "0005DD": "Cisco", "0006C1": "Cisco", "000702": "Cisco",
    "000794": "Cisco", "0007B3": "Cisco", "0007EB": "Cisco", "000815": "Cisco",
    "0009B7": "Cisco", "000A2B": "Cisco", "000A41": "Cisco", "000A42": "Cisco",
    "000A8A": "Cisco", "000AB9": "Cisco", "000B45": "Cisco", "000B46": "Cisco",
    "000B5F": "Cisco", "000B60": "Cisco", "000BBE": "Cisco", "000BBF": "Cisco",
    "000C30": "Cisco", "000D29": "Cisco", "000D65": "Cisco", "000E08": "Cisco",
    "000E38": "Cisco", "000E83": "Cisco", "000E84": "Cisco", "000E8F": "Cisco",
    "001201": "Cisco", "001706": "Cisco", "001B0D": "Cisco", "001B2A": "Cisco",
    "001D45": "Cisco", "0021A0": "Cisco", "0022BE": "Cisco", "002290": "Cisco",
    "0026CB": "Cisco", "0050A2": "Cisco", "005080": "Cisco", "00E014": "Cisco",
    "00E0F9": "Cisco", "00E0FE": "Cisco", "040978": "Cisco", "08CC68": "Cisco",
    "2C3124": "Cisco", "3C0EA4": "Cisco", "44D3CA": "Cisco", "4C00B1": "Cisco",
    "54781A": "Cisco", "5C5015": "Cisco", "60454C": "Cisco", "6C2006": "Cisco",
    "70105C": "Cisco", "788A20": "Cisco", "7C0E0C": "Cisco", "84802D": "Cisco",
    "8CB64F": "Cisco", "8CF761": "Cisco", "B4140B": "Cisco", "B4A4E3": "Cisco",
    "C4648A": "Cisco", "CC161B": "Cisco", "D8B19A": "Cisco", "E84F25": "Cisco",
    "EC3010": "Cisco", "F0799E": "Cisco", "F46B42": "Cisco",
    # Intel
    "000347": "Intel", "000764": "Intel", "000EA6": "Intel", "001111": "Intel",
    "0011D8": "Intel", "001320": "Intel", "00134A": "Intel", "001517": "Intel",
    "00166F": "Intel", "001676": "Intel", "001C7F": "Intel", "001DBE": "Intel",
    "001E64": "Intel", "001E67": "Intel", "001F3B": "Intel", "001F3C": "Intel",
    "001FE1": "Intel", "002185": "Intel", "002219": "Intel", "00226B": "Intel",
    "002A10": "Intel", "003048": "Intel", "0040B6": "Intel", "00A0C9": "Intel",
    "00E04C": "Intel", "10028A": "Intel", "1065FE": "Intel", "1063EB": "Intel",
    "18604A": "Intel", "1C3E84": "Intel", "24FD52": "Intel", "28D244": "Intel",
    "34F64B": "Intel", "3C970E": "Intel", "40167E": "Intel", "44850E": "Intel",
    "4801D5": "Intel", "5404A6": "Intel", "5CF951": "Intel", "60673A": "Intel",
    "7085C2": "Intel", "70886B": "Intel", "748DC4": "Intel", "7C7A91": "Intel",
    "80191D": "Intel", "8086F2": "Intel", "84691A": "Intel", "8478AC": "Intel",
    "88532E": "Intel", "8C104F": "Intel", "940C6D": "Intel", "98E743": "Intel",
    "A0388F": "Intel", "A0C589": "Intel", "A4C494": "Intel", "A81B5A": "Intel",
    "AC7F3E": "Intel", "B0A4E4": "Intel", "B4E1B3": "Intel", "C47BA8": "Intel",
    "C898E6": "Intel", "D025E9": "Intel", "D04F7E": "Intel", "D850E6": "Intel",
    "E0946F": "Intel", "E4B021": "Intel", "F4060D": "Intel", "F8341F": "Intel",
    # Samsung
    "0007AB": "Samsung", "000D7B": "Samsung", "001247": "Samsung", "0015B9": "Samsung",
    "0016DB": "Samsung", "001799": "Samsung", "0021D2": "Samsung", "002399": "Samsung",
    "0024E9": "Samsung", "002637": "Samsung", "0026E2": "Samsung", "1065F9": "Samsung",
    "1C62B8": "Samsung", "20D390": "Samsung", "2C4401": "Samsung", "34145F": "Samsung",
    "380195": "Samsung", "3C6200": "Samsung", "3C8BFE": "Samsung", "401C83": "Samsung",
    "4844F7": "Samsung", "4C2D96": "Samsung", "4C3C16": "Samsung", "50AEB8": "Samsung",
    "5483BF": "Samsung", "54881E": "Samsung", "5C9960": "Samsung", "5CDD70": "Samsung",
    "60036E": "Samsung", "6006E6": "Samsung", "6C2F2C": "Samsung", "6C8336": "Samsung",
    "700514": "Samsung", "74458A": "Samsung", "7825AD": "Samsung", "78407D": "Samsung",
    "804E81": "Samsung", "84257B": "Samsung", "8425DB": "Samsung", "88329B": "Samsung",
    "8CB3A7": "Samsung", "8C7712": "Samsung", "900628": "Samsung", "9849A5": "Samsung",
    "9C0299": "Samsung", "A04299": "Samsung", "A0C5F2": "Samsung", "A4EB75": "Samsung",
    "B047BF": "Samsung", "BC20A4": "Samsung", "BC4486": "Samsung", "C06399": "Samsung",
    "C4731E": "Samsung", "C8619A": "Samsung", "CC070C": "Samsung", "D0176A": "Samsung",
    "D0B310": "Samsung", "D0DFC7": "Samsung", "D487D8": "Samsung", "D4E8B2": "Samsung",
    "D8E0E1": "Samsung", "E4F8EF": "Samsung", "EC1F72": "Samsung", "F025B7": "Samsung",
    "F0BF97": "Samsung", "F07E33": "Samsung", "F47B5E": "Samsung", "F4D9FB": "Samsung",
    # Dell
 "000874": "Dell", "000D56": "Dell", "001143": "Dell",
    "00188B": "Dell", "001E4F": "Dell", "0021F6": "Dell", "00226B": "Dell",
    "001A4B": "Dell", "002564": "Dell",
 "18FB7B": "Dell",
    "242C64": "Dell", "2CD05A": "Dell", "344DE0": "Dell", "44A842": "Dell",
    "484DFE": "Dell", "4C2B47": "Dell", "5C261E": "Dell", "5CF9DD": "Dell",
    "848F69": "Dell", "B0839C": "Dell", "BCAEC5": "Dell", "C81F66": "Dell",
    "D4BED9": "Dell", "D8F2CA": "Dell", "F0B4D2": "Dell", "F8BC12": "Dell",
    # HP / HPE
    "001083": "HP", "001321": "HP", "001560": "HP", "001635": "HP",
    "001708": "HP", "001AA0": "HP", "001E0B": "HP", "001F29": "HP",
    "002170": "HP", "00248C": "HP", "0025B3": "HP", "002660": "HP",
    "0030C1": "HP", "00508B": "HP", "006067": "HP", "00A0D1": "HP",
    "00E066": "HP", "14DAE9": "HP", "1C98EC": "HP", "206A8A": "HP",
    "28924A": "HP", "2C41BC": "HP", "3CDAFF": "HP", "3C4AF8": "HP",
    "40B034": "HP", "488DA3": "HP", "48DF37": "HP", "5C8A38": "HP",
    "5CB901": "HP", "64316A": "HP", "680936": "HP", "6CE877": "HP",
    "94571A": "HP", "9CB654": "HP", "A0B3CC": "HP", "A6372A": "HP",
    "D8D385": "HP", "EC8EB5": "HP",
    # VMware
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware",
    "005056": "VMware",
    # Microsoft
    "000D3A": "Microsoft", "001DD8": "Microsoft", "002248": "Microsoft",
    "0050F2": "Microsoft", "485073": "Microsoft", "5C83BF": "Microsoft",
    "60457F": "Microsoft", "7C1E52": "Microsoft",
    # Google
    "001A11": "Google", "3C5AB4": "Google", "54521E": "Google", "6C40B8": "Google",
    "8C8590": "Google", "A47733": "Google", "D4F57D": "Google", "F4F5D8": "Google",
    # Amazon / AWS
    "0A2342": "Amazon", "123456": "Amazon",
    # Raspberry Pi
    "B827EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    # Ubiquiti
    "002722": "Ubiquiti", "0418D6": "Ubiquiti", "24A43C": "Ubiquiti",
    "44D9E7": "Ubiquiti", "68722D": "Ubiquiti", "788A20": "Ubiquiti",
    "80211B": "Ubiquiti", "B4FBE4": "Ubiquiti", "DC9FDB": "Ubiquiti",
    "F09FC2": "Ubiquiti", "FCECDA": "Ubiquiti",
    # TP-Link
    "1062EB": "TP-Link", "14CC20": "TP-Link", "18D61C": "TP-Link",
    "1C3BF3": "TP-Link", "284D43": "TP-Link", "2CBE08": "TP-Link",
    "30B5C2": "TP-Link", "3C52A1": "TP-Link", "50C7BF": "TP-Link",
    "54AF97": "TP-Link", "5C89B2": "TP-Link", "60E327": "TP-Link",
    "7486E2": "TP-Link", "84162C": "TP-Link", "94D9B3": "TP-Link",
    "A42BB0": "TP-Link", "B0487A": "TP-Link", "C006C3": "TP-Link",
    "C46E1F": "TP-Link", "D46AA8": "TP-Link", "E03F49": "TP-Link",
    "EC086B": "TP-Link", "F4F26D": "TP-Link",
    # Netgear
    "000FB5": "Netgear", "001B2F": "Netgear", "001E2A": "Netgear",
    "002096": "Netgear", "0022B0": "Netgear", "0026F2": "Netgear",
    "00A040": "Netgear", "10DA43": "Netgear", "20E52A": "Netgear",
    "28C68E": "Netgear", "30469A": "Netgear", "44944F": "Netgear",
    "4C60DE": "Netgear", "6031F2": "Netgear", "6CB0CE": "Netgear",
    "749D8F": "Netgear", "8452E1": "Netgear", "A021B7": "Netgear",
    "C03F0E": "Netgear", "C4048A": "Netgear",
    # Aruba / HP Wireless
    "000B86": "Aruba", "001A1E": "Aruba", "002498": "Aruba", "40E3D6": "Aruba",
    "6CB311": "Aruba", "70888B": "Aruba", "84D47E": "Aruba", "9480AD": "Aruba",
    "AC:A3:1E": "Aruba", "ACA31E": "Aruba", "D868C3": "Aruba",
    # Juniper
    "001409": "Juniper", "0019E2": "Juniper", "001FB4": "Juniper",
    "00214F": "Juniper", "002197": "Juniper", "0023CA": "Juniper",
    "002438": "Juniper", "00269D": "Juniper", "0050FE": "Juniper",
    "0C8680": "Juniper", "18178B": "Juniper", "28C001": "Juniper",
    "4C9641": "Juniper", "6480B3": "Juniper", "7829F9": "Juniper",
    "88A2D7": "Juniper", "A4ACA1": "Juniper", "B47876": "Juniper",
    # Fortinet
    "000AF4": "Fortinet", "00090F": "Fortinet", "001871": "Fortinet",
    "0024E7": "Fortinet", "70720D": "Fortinet", "A806EA": "Fortinet",
    # Palo Alto
    "001B17": "Palo Alto", "1C18A0": "Palo Alto",
    # Lenovo
    "0003FF": "Lenovo", "001E8C": "Lenovo", "0021CC": "Lenovo",
    "002264": "Lenovo", "00248D": "Lenovo", "0050C2": "Lenovo",
    "1085F4": "Lenovo", "18CF5E": "Lenovo", "28D244": "Lenovo",
    "34399E": "Lenovo", "38B1DB": "Lenovo", "40742C": "Lenovo",
    "485AA5": "Lenovo", "4C7268": "Lenovo", "54EEF7": "Lenovo",
    "70720D": "Lenovo", "74867A": "Lenovo", "88706E": "Lenovo",
    "8C8DFF": "Lenovo", "90488A": "Lenovo", "948A3B": "Lenovo",
 "AC7BA1": "Lenovo", "B03AF2": "Lenovo",
    "C47B4E": "Lenovo", "C81F66": "Lenovo", "D0BEC8": "Lenovo",
    # ASUS
    "0008A1": "ASUS", "000EA6": "ASUS", "001731": "ASUS", "001D60": "ASUS",
    "002618": "ASUS", "002354": "ASUS", "107B44": "ASUS", "1C872C": "ASUS",
    "1CB17C": "ASUS", "2C4D54": "ASUS", "30852F": "ASUS", "38D547": "ASUS",
    "3C97DE": "ASUS", "403DEC": "ASUS", "48EE0C": "ASUS", "4CEDFB": "ASUS",
    "60A44C": "ASUS", "6045CB": "ASUS", "6CFDEA": "ASUS", "742B62": "ASUS",
 "88D7F6": "ASUS", "90E6BA": "ASUS", "9C5C8E": "ASUS",
    "AC220B": "ASUS", "B062E4": "ASUS", "BC9747": "ASUS", "C8606E": "ASUS",
    "E03F49": "ASUS", "E0CB4E": "ASUS",
    # Broadcom (common in phones/embedded)
    "000AF7": "Broadcom", "001018": "Broadcom", "0026B9": "Broadcom",
    "047D7B": "Broadcom", "CC3EA3": "Broadcom",
    # Qualcomm / Atheros
    "00037F": "Qualcomm/Atheros", "001374": "Qualcomm", "00265A": "Qualcomm",
    "48A35C": "Qualcomm",
    # Realtek
    "0012CF": "Realtek", "001E8C": "Realtek", "005047": "Realtek",
    "0CEB94": "Realtek", "10BF48": "Realtek", "30D316": "Realtek",
    "40167E": "Realtek", "74DFBF": "Realtek", "7C1C4E": "Realtek",
    "D072DC": "Realtek", "E0D55E": "Realtek",
    # Murata (common in IoT/embedded WiFi)
    "0C8BFD": "Murata", "3440B5": "Murata", "60D7E3": "Murata",
    "74DA88": "Murata", "D86CE9": "Murata", "F032DC": "Murata",
    # Espressif (ESP8266/ESP32 — very common in IoT)
    "18FE34": "Espressif", "24B2DE": "Espressif", "2CF432": "Espressif",
    "30AEA4": "Espressif", "3C71BF": "Espressif", "48:3F:DA": "Espressif",
    "483FDA": "Espressif", "5CCF7F": "Espressif", "60019F": "Espressif",
    "840D8E": "Espressif", "8CAA8E": "Espressif", "90973E": "Espressif",
    "A020A6": "Espressif", "A4CF12": "Espressif", "AC67B2": "Espressif",
    "B4E62D": "Espressif", "CC50E3": "Espressif", "CCEA14": "Espressif",
    "D8BFC0": "Espressif", "E89F6D": "Espressif", "EC94CB": "Espressif",
    "F4CFA2": "Espressif",
    # ASUSTek / Pegatron (common in PCs)
    "8C89A5": "Pegatron", "30857E": "Pegatron",
    # VirtualBox
    "080027": "VirtualBox",
    # Xen
    "00163E": "Xen",
    # QEMU/KVM
    "525400": "QEMU/KVM",
    # Hyper-V
    "000D3A": "Hyper-V", "0015B7": "Hyper-V",
    # Huawei
    "001882": "Huawei", "001E10": "Huawei", "002568": "Huawei",
    "00259E": "Huawei", "0025AA": "Huawei", "000AE4": "Huawei",
    "00A0D4": "Huawei", "100316": "Huawei", "1CB17C": "Huawei",
    "20F311": "Huawei", "286ED4": "Huawei", "2C9EFC": "Huawei",
    "30D17E": "Huawei", "346AC2": "Huawei", "380102": "Huawei",
 "44A19C": "Huawei", "485A3F": "Huawei",
    "4CB16C": "Huawei", "4CD161": "Huawei", "505BAD": "Huawei",
    "58605F": "Huawei", "5C4CA9": "Huawei", "60DE44": "Huawei",
    "68A099": "Huawei", "6CAB31": "Huawei", "706655": "Huawei",
    "787B8A": "Huawei", "7CB15D": "Huawei", "7CE0DC": "Huawei",
    "882539": "Huawei", "8C34FD": "Huawei", "94049C": "Huawei",
    "9800A7": "Huawei", "9CB2B2": "Huawei", "A4DCBE": "Huawei",
    "AC853D": "Huawei", "ACEE9E": "Huawei", "B4430D": "Huawei",
    "B4786B": "Huawei", "C469EE": "Huawei", "C488C9": "Huawei",
    "C8D15E": "Huawei", "CC96A0": "Huawei", "D4401C": "Huawei",
    "D46AA8": "Huawei", "D8490B": "Huawei", "DC729C": "Huawei",
    "E0191D": "Huawei", "E04F43": "Huawei", "E8088B": "Huawei",
    "EC23FD": "Huawei", "F44C7F": "Huawei", "F48145": "Huawei",
    "F831EF": "Huawei", "FC3F7C": "Huawei",
    # Sony
    "001A80": "Sony", "001D0D": "Sony", "002618": "Sony", "0050F0": "Sony",
    "001315": "Sony", "3CF872": "Sony", "A8E0AF": "Sony",
    # LG Electronics
    "001E75": "LG", "0021FB": "LG", "002483": "LG", "006F64": "LG",
    "1025B5": "LG", "3451C9": "LG", "38AF29": "LG", "40B0FA": "LG",
    "48599F": "LG", "AC0D1B": "LG", "C4434D": "LG",
    # Xiaomi
    "0016EB": "Xiaomi", "10DF0F": "Xiaomi", "1440B3": "Xiaomi",
    "286C07": "Xiaomi", "2C5BB8": "Xiaomi",
    "58440E": "Xiaomi", "5C9A1E": "Xiaomi", "64EB8C": "Xiaomi",
    "7CF8DB": "Xiaomi", "8C0095": "Xiaomi", "9C9936": "Xiaomi",
    "A45811": "Xiaomi",
 "D4970B": "Xiaomi",
    "F0B429": "Xiaomi", "FC64BA": "Xiaomi",
}


def lookup_vendor(mac: str) -> str:
    """
    Look up the vendor for a MAC address.
    Returns the vendor name string, or "" if unknown.

    Accepts any common MAC format:
        aa:bb:cc:dd:ee:ff
        AA-BB-CC-DD-EE-FF
        aabbccddeeff
    """
    if not mac:
        return ""
    try:
        # Normalise to uppercase no-separator
        clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
        if len(clean) < 6:
            return ""
        oui = clean[:6]
        return _OUI.get(oui, "")
    except Exception:
        return ""
