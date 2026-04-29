"""
Compact OUI (Organizationally Unique Identifier) lookup.

Maps the first 3 bytes of a MAC address (the OUI prefix) to a vendor name.
Focused on vendors most relevant to security research: Microsoft ecosystem
(Windows OEMs), network infrastructure, virtual machines, and printers.

Usage:
    from workspaces.network.parser.oui import lookup_vendor
    vendor = lookup_vendor("aa:bb:cc:dd:ee:ff")  # returns "Intel" or ""
"""

# OUI → vendor name. Keys are uppercase 6-char hex strings (no colons).
_OUI: dict = {
    # ══════════════════════════════════════════════════════════════════════
    # Microsoft
    # ══════════════════════════════════════════════════════════════════════
    "0003FF": "Microsoft", "0050F2": "Microsoft", "00155D": "Microsoft HV",
    "000D3A": "Microsoft HV", "28187D": "Microsoft", "485B39": "Microsoft",
    "60455E": "Microsoft", "7CED8D": "Microsoft", "B83A5A": "Microsoft",
    "C83DD4": "Microsoft", "CC9E00": "Microsoft", "D83BBF": "Microsoft",
    "DC5360": "Microsoft", "001DD8": "Microsoft",

    # ══════════════════════════════════════════════════════════════════════
    # Intel — most common NIC vendor in Windows PCs / laptops
    # ══════════════════════════════════════════════════════════════════════
    "001111": "Intel", "001302": "Intel", "001500": "Intel", "001517": "Intel",
    "001CC0": "Intel", "001E64": "Intel", "001E65": "Intel", "001E67": "Intel",
    "001F3B": "Intel", "001F3C": "Intel", "002314": "Intel", "002618": "Intel",
    "003000": "Intel", "003EE1": "Intel", "0050F1": "Intel", "00A0C9": "Intel",
    "081196": "Intel", "083E8E": "Intel", "084E1C": "Intel", "08D40C": "Intel",
    "0C7A15": "Intel", "100BA9": "Intel", "103B59": "Intel", "14ABC5": "Intel",
    "1802AE": "Intel", "18DB3C": "Intel", "1C1BB5": "Intel", "1C6F65": "Intel",
    "1CCCA3": "Intel", "206374": "Intel", "2477FC": "Intel", "284C77": "Intel",
    "288023": "Intel", "2C0E3D": "Intel", "2C3361": "Intel", "2C4138": "Intel",
    "309C23": "Intel", "30B49E": "Intel", "3413E8": "Intel", "34028B": "Intel",
    "34CF80": "Intel", "38BA58": "Intel", "380F4A": "Intel", "3C18A0": "Intel",
    "3C6AA7": "Intel", "3C9509": "Intel", "3CA067": "Intel", "3CE1A1": "Intel",
    "40743E": "Intel", "4085F6": "Intel", "44032C": "Intel", "48B02D": "Intel",
    "484D7E": "Intel", "4C34CB": "Intel", "4CEB42": "Intel", "50E085": "Intel",
    "5489A2": "Intel", "54BF64": "Intel", "5820B1": "Intel", "5C5F67": "Intel",
    "5CCF7F": "Intel", "5CE0C5": "Intel", "60D819": "Intel", "60F262": "Intel",
    "643476": "Intel", "6805CA": "Intel", "6C29D2": "Intel", "6C88CB": "Intel",
    "7077A9": "Intel", "70185E": "Intel", "745D22": "Intel", "748114": "Intel",
    "7483C8": "Intel", "7C7A91": "Intel", "7C8AE1": "Intel", "80000B": "Intel",
    "80C5F2": "Intel", "80CE62": "Intel", "847BEB": "Intel", "849D16": "Intel",
    "88B4A6": "Intel", "8C8D28": "Intel", "906EBB": "Intel", "9402B3": "Intel",
    "94659C": "Intel", "94B86D": "Intel", "94E6F7": "Intel", "9C2A83": "Intel",
    "9CDA3E": "Intel", "A41142": "Intel", "A44CC8": "Intel", "A4340D": "Intel",
    "A48880": "Intel", "A4C494": "Intel", "AC7BA1": "Intel", "B09BE7": "Intel",
    "B46D83": "Intel", "B4969B": "Intel", "BC7737": "Intel", "BC77BF": "Intel",
    "C87E75": "Intel", "CC2F71": "Intel", "D0C637": "Intel", "D46D6D": "Intel",
    "D85DE2": "Intel", "DCA632": "Intel", "E00C7F": "Intel", "E0D55E": "Intel",
    "E4A471": "Intel", "E4B318": "Intel", "E836BB": "Intel", "EC0ED6": "Intel",
    "F40669": "Intel", "F48C50": "Intel", "F8167E": "Intel", "F87AEF": "Intel",
    "FC3577": "Intel", "483D33": "Intel", "98AFC6": "Intel", "A0369F": "Intel",
    "082E5F": "Intel", "D4258B": "Intel", "E8B1FC": "Intel", "B44BD2": "Intel",

    # ══════════════════════════════════════════════════════════════════════
    # Realtek — very common in consumer/budget NICs and USB adapters
    # ══════════════════════════════════════════════════════════════════════
    "001C25": "Realtek", "007F28": "Realtek", "0C5415": "Realtek",
    "107880": "Realtek", "48E244": "Realtek", "500B32": "Realtek",
    "6045CB": "Realtek", "9072E2": "Realtek", "B8A386": "Realtek",
    "D86CE9": "Realtek", "E04F43": "Realtek", "E848B8": "Realtek",
    "001731": "Realtek", "00E04C": "Realtek", "529A4C": "Realtek",
    "A81B5A": "Realtek", "50A0B4": "Realtek",

    # ══════════════════════════════════════════════════════════════════════
    # Broadcom / Qualcomm / MediaTek — common wireless chipsets in laptops
    # ══════════════════════════════════════════════════════════════════════
    "001018": "Broadcom", "0010A7": "Broadcom", "001BE9": "Broadcom",
    "00264D": "Broadcom", "0090D9": "Broadcom", "28CB5A": "Broadcom",
    "A0F459": "Broadcom", "D86BF7": "Broadcom", "2067B1": "Broadcom",
    "000E8E": "Qualcomm", "001306": "Qualcomm", "001A1E": "Qualcomm",
    "001B3F": "Qualcomm", "001DBA": "Qualcomm", "0CB749": "Qualcomm",
    "1C48CE": "Qualcomm", "34BB1F": "Qualcomm", "5CE0C5": "Qualcomm",
    "785DC8": "Qualcomm", "8C7EB3": "Qualcomm",
    "000CE7": "MediaTek", "001360": "MediaTek", "08152F": "MediaTek",
    "1C1B68": "MediaTek", "501A2D": "MediaTek", "C08ADC": "MediaTek",
    "D4B297": "MediaTek", "E8DE27": "MediaTek",

    # ══════════════════════════════════════════════════════════════════════
    # Dell
    # ══════════════════════════════════════════════════════════════════════
    "001422": "Dell", "001A4D": "Dell", "001C23": "Dell", "001D09": "Dell",
    "001E4F": "Dell", "001E8C": "Dell", "002170": "Dell", "002219": "Dell",
    "0024E8": "Dell", "00269E": "Dell", "00B0D0": "Dell", "0C8230": "Dell",
    "109836": "Dell", "143E60": "Dell", "14187D": "Dell", "14B31F": "Dell",
    "14FEB5": "Dell", "180373": "Dell", "18A99B": "Dell", "18DB43": "Dell",
    "18FB7B": "Dell", "1C727A": "Dell", "24B6FD": "Dell", "280CF5": "Dell",
    "2C768A": "Dell", "34E6D7": "Dell", "3417EB": "Dell", "38B1DB": "Dell",
    "409FC6": "Dell", "4493C4": "Dell", "44A842": "Dell", "484DFE": "Dell",
    "4C7625": "Dell", "508B4D": "Dell", "5C260A": "Dell", "646058": "Dell",
    "6CB7F4": "Dell", "742857": "Dell", "749D8F": "Dell", "7845C4": "Dell",
    "78AC44": "Dell", "7CF30D": "Dell", "8048EB": "Dell", "843835": "Dell",
    "885A92": "Dell", "8C164D": "Dell", "8C473A": "Dell", "8C47BE": "Dell",
    "90B11C": "Dell", "9480EB": "Dell", "980D2E": "Dell", "9840BB": "Dell",
    "9C8E99": "Dell", "A41F72": "Dell", "A4BA8B": "Dell", "A4BBAF": "Dell",
    "AC16E0": "Dell", "B083FE": "Dell", "B499BA": "Dell", "B82A72": "Dell",
    "B85510": "Dell", "BC305B": "Dell", "C0C6E4": "Dell", "C81F66": "Dell",
    "CC48EC": "Dell", "D067E5": "Dell", "D489E7": "Dell", "D4AE52": "Dell",
    "D4BE97": "Dell", "D4BED9": "Dell", "D89402": "Dell", "E4F047": "Dell",
    "F01FAF": "Dell", "F04DA2": "Dell", "F48E38": "Dell", "F8B156": "Dell",
    "F8BC12": "Dell", "F8DB88": "Dell",

    # ══════════════════════════════════════════════════════════════════════
    # HP / HPE
    # ══════════════════════════════════════════════════════════════════════
    "0001E6": "HP", "0001E7": "HP", "000396": "HP", "000802": "HP",
    "000A57": "HP", "000BCD": "HP", "000E7F": "HP", "000EB3": "HP",
    "000F20": "HP", "000F61": "HP", "001083": "HP", "0010E3": "HP",
    "001185": "HP", "001321": "HP", "001560": "HP", "001635": "HP",
    "001708": "HP", "001871": "HP", "001A4B": "HP", "001B78": "HP",
    "001CC4": "HP", "001E0B": "HP", "001F29": "HP", "0021B7": "HP",
    "002481": "HP", "0025B3": "HP", "0026F1": "HP", "002710": "HP",
    "002890": "HP", "080009": "HP", "0C47C9": "HP", "10604B": "HP",
    "1CC1DE": "HP", "1CC23D": "HP", "2C2317": "HP", "2C41A1": "HP",
    "308D99": "HP", "3464A9": "HP", "388602": "HP", "38EAA7": "HP",
    "3C4A92": "HP", "3C52A1": "HP", "3CA82A": "HP", "402CF4": "HP",
    "4431C3": "HP", "48DF37": "HP", "501162": "HP", "5065F3": "HP",
    "50EB71": "HP", "5CB901": "HP", "6476BA": "HP", "68B599": "HP",
    "70106F": "HP", "740ABC": "HP", "7883C4": "HP", "7C5CF8": "HP",
    "9457A5": "HP", "94B866": "HP", "985AEB": "HP", "9CB654": "HP",
    "A02BB8": "HP", "A0D3C1": "HP", "A45630": "HP", "A4516F": "HP",
    "AC162D": "HP", "B07D64": "HP", "B0A772": "HP", "B4B676": "HP",
    "BC8893": "HP", "C06618": "HP", "C46044": "HP", "C8CBE8": "HP",
    "CC3ADF": "HP", "D07E28": "HP", "D48564": "HP", "D4C94B": "HP",
    "DC4A3E": "HP", "E4115B": "HP", "E8393C": "HP", "EC9A74": "HP",
    "F092B4": "HP", "F430B9": "HP", "F4CE46": "HP", "FC15B4": "HP",
    # HPE (server/network)
    "0014C2": "HPE", "001708": "HPE", "3822D6": "HPE", "48DF37": "HPE",
    "9457A5": "HPE", "A0B3CC": "HPE", "EC13DB": "HPE",

    # ══════════════════════════════════════════════════════════════════════
    # Lenovo
    # ══════════════════════════════════════════════════════════════════════
    "008064": "Lenovo", "1C39D2": "Lenovo", "2C8158": "Lenovo",
    "345760": "Lenovo", "38BAF8": "Lenovo", "440EA8": "Lenovo",
    "500F80": "Lenovo", "5CF3FC": "Lenovo", "70720D": "Lenovo",
    "74E50B": "Lenovo", "8C1645": "Lenovo", "8CB25D": "Lenovo",
    "984BE1": "Lenovo", "C4346B": "Lenovo", "CCFB65": "Lenovo",
    "E8E0B7": "Lenovo", "F03246": "Lenovo", "28D244": "Lenovo",
    "6C7220": "Lenovo", "7872E4": "Lenovo", "9048BD": "Lenovo",
    "98E743": "Lenovo", "B4692F": "Lenovo", "E04F43": "Lenovo",
    "EC2A72": "Lenovo", "50EB71": "Lenovo",

    # ══════════════════════════════════════════════════════════════════════
    # ASUS — motherboards, laptops
    # ══════════════════════════════════════════════════════════════════════
    "001A92": "ASUS", "001FC6": "ASUS", "002215": "ASUS", "00248C": "ASUS",
    "049226": "ASUS", "04421A": "ASUS", "08606E": "ASUS", "086266": "ASUS",
    "0C9D92": "ASUS", "1C872C": "ASUS", "2C4D54": "ASUS", "2C56DC": "ASUS",
    "305A3A": "ASUS", "3085A9": "ASUS", "3497F6": "ASUS", "381428": "ASUS",
    "40167E": "ASUS", "504E00": "ASUS", "50465D": "ASUS", "54A050": "ASUS",
    "6045BD": "ASUS", "6CF5E8": "ASUS", "708BCD": "ASUS", "74D02B": "ASUS",
    "788C54": "ASUS", "9C5C8E": "ASUS", "AC220B": "ASUS", "B06EBF": "ASUS",
    "BC5FF4": "ASUS", "C86000": "ASUS", "D85D4C": "ASUS", "E03F49": "ASUS",
    "F07959": "ASUS", "F46D04": "ASUS", "F832E4": "ASUS",

    # ══════════════════════════════════════════════════════════════════════
    # Acer / MSI / Gigabyte — other Windows OEMs
    # ══════════════════════════════════════════════════════════════════════
    "001195": "Acer", "18F46A": "Acer", "300167": "Acer", "502B73": "Acer",
    "D0577B": "Acer", "FC4596": "Acer",
    "0026CE": "MSI", "4006A0": "MSI", "D43D7E": "MSI", "8078CD": "MSI",
    "001E67": "Gigabyte", "009C02": "Gigabyte", "E0D55E": "Gigabyte",
    "502B73": "Gigabyte", "94DE80": "Gigabyte",
    # Toshiba / Dynabook
    "000B46": "Toshiba", "002693": "Toshiba", "3C970E": "Toshiba",
    "4865EE": "Toshiba", "B88687": "Toshiba",

    # ══════════════════════════════════════════════════════════════════════
    # VIRTUAL MACHINES
    # ══════════════════════════════════════════════════════════════════════
    "000C29": "VMware", "000569": "VMware", "005056": "VMware",
    "001C14": "VMware",
    "080027": "VirtualBox", "0A0027": "VirtualBox",
    "525400": "QEMU/KVM",
    "00163E": "Xen",
    "7C1E52": "Microsoft HV",

    # ══════════════════════════════════════════════════════════════════════
    # NETWORK INFRASTRUCTURE — Routers / Switches / APs / Firewalls
    # ══════════════════════════════════════════════════════════════════════

    # ── Cisco ──
    "00000C": "Cisco", "000142": "Cisco", "0001C7": "Cisco", "000164": "Cisco",
    "0002B9": "Cisco", "00036B": "Cisco", "0003FD": "Cisco", "0004DD": "Cisco",
    "00055E": "Cisco", "000628": "Cisco", "0006D7": "Cisco", "0006F6": "Cisco",
    "000740": "Cisco", "0007B3": "Cisco", "00082F": "Cisco", "000A41": "Cisco",
    "000A42": "Cisco", "000A8A": "Cisco", "000B45": "Cisco", "000BFD": "Cisco",
    "000D28": "Cisco", "000D65": "Cisco", "000DBC": "Cisco", "000DED": "Cisco",
    "000E38": "Cisco", "000E83": "Cisco", "000ED7": "Cisco", "000F23": "Cisco",
    "000F35": "Cisco", "000F8F": "Cisco", "00101F": "Cisco", "001011": "Cisco",
    "001079": "Cisco", "0010F6": "Cisco", "00110A": "Cisco", "001195": "Cisco",
    "001200": "Cisco", "001217": "Cisco", "001259": "Cisco", "0012D9": "Cisco",
    "001315": "Cisco", "001319": "Cisco", "001438": "Cisco", "00146C": "Cisco",
    "0014A9": "Cisco", "001557": "Cisco", "0015C6": "Cisco", "0015FA": "Cisco",
    "001636": "Cisco", "001678": "Cisco", "0016C7": "Cisco", "001759": "Cisco",
    "001795": "Cisco", "00180A": "Cisco", "001839": "Cisco", "001868": "Cisco",
    "0018BA": "Cisco", "001906": "Cisco", "00192F": "Cisco", "00196C": "Cisco",
    "0019AA": "Cisco", "001A2F": "Cisco", "001A30": "Cisco", "001A6C": "Cisco",
    "001A6D": "Cisco", "001AE2": "Cisco", "001AE3": "Cisco", "001B2A": "Cisco",
    "001B2B": "Cisco", "001B53": "Cisco", "001B54": "Cisco", "001B67": "Cisco",
    "001BD4": "Cisco", "001BD5": "Cisco", "001BD7": "Cisco", "001C0E": "Cisco",
    "001C10": "Cisco", "001C57": "Cisco", "001C58": "Cisco", "001D45": "Cisco",
    "001D46": "Cisco", "001D70": "Cisco", "001D71": "Cisco", "001DE5": "Cisco",
    "001DE6": "Cisco", "001E13": "Cisco", "001E14": "Cisco", "001E49": "Cisco",
    "001E4A": "Cisco", "001E7A": "Cisco", "001E7B": "Cisco", "001EB5": "Cisco",
    "001EB6": "Cisco", "001F26": "Cisco", "001F27": "Cisco", "001F6C": "Cisco",
    "001F6D": "Cisco", "001F9D": "Cisco", "001F9E": "Cisco", "0021A0": "Cisco",
    "0021A1": "Cisco", "0021D7": "Cisco", "0021D8": "Cisco", "002216": "Cisco",
    "002255": "Cisco", "002293": "Cisco", "0022BD": "Cisco", "002319": "Cisco",
    "002350": "Cisco", "002351": "Cisco", "00238B": "Cisco", "0023AB": "Cisco",
    "0023AC": "Cisco", "0023EB": "Cisco", "0023EC": "Cisco", "002420": "Cisco",
    "002451": "Cisco", "0024C3": "Cisco", "0024C4": "Cisco", "0024F7": "Cisco",
    "0024F9": "Cisco", "002556": "Cisco", "002584": "Cisco", "002608": "Cisco",
    "002609": "Cisco", "00267E": "Cisco", "00270D": "Cisco", "0040F4": "Cisco",
    "004096": "Cisco", "00500F": "Cisco", "005054": "Cisco", "006009": "Cisco",
    "00602F": "Cisco", "006047": "Cisco", "006070": "Cisco", "006083": "Cisco",
    "0060B0": "Cisco", "006B4E": "Cisco", "00906D": "Cisco", "00908F": "Cisco",
    "009065": "Cisco", "04C5A4": "Cisco", "04FE7F": "Cisco", "0C2724": "Cisco",
    "0C756C": "Cisco", "0C8525": "Cisco", "0C8DDB": "Cisco", "100F35": "Cisco",
    "1CDF0F": "Cisco", "1CE85D": "Cisco", "200C71": "Cisco", "24E9B3": "Cisco",
    "2C31E5": "Cisco", "2C3ECF": "Cisco", "2C542D": "Cisco", "30E4DB": "Cisco",
    "34BDC8": "Cisco", "381C1A": "Cisco", "3C0E23": "Cisco", "3C5EC3": "Cisco",
    "3890A5": "Cisco", "40A6E8": "Cisco", "44ADD9": "Cisco", "500604": "Cisco",
    "50067F": "Cisco", "5475D0": "Cisco", "588D09": "Cisco", "5C5015": "Cisco",
    "5C838F": "Cisco", "5CE176": "Cisco", "6073BC": "Cisco", "6400F1": "Cisco",
    "64A0E7": "Cisco", "64D814": "Cisco", "680715": "Cisco", "68BDAB": "Cisco",
    "68EFBD": "Cisco", "6C416A": "Cisco", "70CA9B": "Cisco", "70DB98": "Cisco",
    "74A02F": "Cisco", "7813BE": "Cisco", "78BA5D": "Cisco", "7C0ECE": "Cisco",
    "7C1DEB": "Cisco", "7C95F3": "Cisco", "7CAD74": "Cisco", "843DC6": "Cisco",
    "84B80A": "Cisco", "88908D": "Cisco", "8843E1": "Cisco", "8C94CF": "Cisco",
    "A07A95": "Cisco", "A4187B": "Cisco", "A4563F": "Cisco", "A4B1E9": "Cisco",
    "A896B1": "Cisco", "AC4BC8": "Cisco", "AC7E8A": "Cisco", "B000B4": "Cisco",
    "B0AA77": "Cisco", "B0FA47": "Cisco", "B4A4E3": "Cisco", "B4E9B0": "Cisco",
    "BC671C": "Cisco", "C025E9": "Cisco", "C0626B": "Cisco", "C067AF": "Cisco",
    "C47295": "Cisco", "C4B36A": "Cisco", "C80084": "Cisco", "C8B5AD": "Cisco",
    "CC462D": "Cisco", "CC5A53": "Cisco", "CC7F76": "Cisco", "D077CE": "Cisco",
    "D0A5A6": "Cisco", "D0C282": "Cisco", "D46AA8": "Cisco", "D46D50": "Cisco",
    "D4D7F5": "Cisco", "D8B190": "Cisco", "DCA5F4": "Cisco", "E0553D": "Cisco",
    "E4AA5D": "Cisco", "E4C722": "Cisco", "E84040": "Cisco", "E8BA70": "Cisco",
    "EC44E5": "Cisco", "F05A09": "Cisco", "F07F06": "Cisco", "F09E63": "Cisco",
    "F40FBB": "Cisco", "F44E05": "Cisco", "F84F57": "Cisco", "F87B20": "Cisco",
    "FC5B39": "Cisco", "FCD4F2": "Cisco",

    # ── Meraki (Cisco) ──
    "00184D": "Meraki", "0C8DDB": "Meraki", "0CD996": "Meraki",
    "34567D": "Meraki", "68EA8A": "Meraki", "88152D": "Meraki",
    "AC17C8": "Meraki", "E8ED05": "Meraki",

    # ── Juniper ──
    "000585": "Juniper", "000DB7": "Juniper", "0010DB": "Juniper",
    "001256": "Juniper", "001BC0": "Juniper", "0019E2": "Juniper",
    "001F12": "Juniper", "002159": "Juniper", "0022B3": "Juniper",
    "0024DC": "Juniper", "002688": "Juniper", "00315A": "Juniper",
    "0090CB": "Juniper", "0C8606": "Juniper", "283A4D": "Juniper",
    "2C2172": "Juniper", "2C6BF5": "Juniper", "306B3D": "Juniper",
    "3C6199": "Juniper", "3C61AF": "Juniper", "40B4F0": "Juniper",
    "44F477": "Juniper", "4C9614": "Juniper", "546C0E": "Juniper",
    "54E032": "Juniper", "5C459A": "Juniper", "641225": "Juniper",
    "6491DB": "Juniper", "6C3B6B": "Juniper", "78194E": "Juniper",
    "78FE3D": "Juniper", "88A25E": "Juniper", "88E0F3": "Juniper",
    "9C8C06": "Juniper", "A8D0E5": "Juniper", "B0C69A": "Juniper",
    "D4041E": "Juniper", "EC3873": "Juniper", "EC38DB": "Juniper",
    "F017E8": "Juniper", "F01C2D": "Juniper", "F4A739": "Juniper",
    "F86CE1": "Juniper",

    # ── Aruba ──
    "000B86": "Aruba", "002083": "Aruba", "00247B": "Aruba",
    "04BD88": "Aruba", "18644C": "Aruba", "1C287D": "Aruba",
    "24DEC6": "Aruba", "40E3D6": "Aruba", "6C8BD3": "Aruba",
    "940014": "Aruba", "9C1C12": "Aruba", "AC1F8A": "Aruba",
    "D8C7C8": "Aruba", "20A6CD": "Aruba", "246FE1": "Aruba",

    # ── Ubiquiti ──
    "002722": "Ubiquiti", "0418D6": "Ubiquiti", "04E2B2": "Ubiquiti",
    "18E829": "Ubiquiti", "245A4C": "Ubiquiti", "249A30": "Ubiquiti",
    "24A43C": "Ubiquiti", "2C26C5": "Ubiquiti", "44D9E7": "Ubiquiti",
    "680F77": "Ubiquiti", "687251": "Ubiquiti", "6C198F": "Ubiquiti",
    "708DC3": "Ubiquiti", "74ACB9": "Ubiquiti", "784558": "Ubiquiti",
    "78458C": "Ubiquiti", "7C87CE": "Ubiquiti", "802AA8": "Ubiquiti",
    "B4FBE4": "Ubiquiti", "D021F9": "Ubiquiti", "DC9FDB": "Ubiquiti",
    "E063DA": "Ubiquiti", "F09FC2": "Ubiquiti", "FCECDA": "Ubiquiti",

    # ── Palo Alto Networks ──
    "00EB2E": "Palo Alto", "0C837F": "Palo Alto", "586356": "Palo Alto",
    "B4F18A": "Palo Alto", "0024AC": "Palo Alto",

    # ── Fortinet ──
    "000938": "Fortinet", "005045": "Fortinet", "001700": "Fortinet",
    "08E843": "Fortinet", "70481F": "Fortinet", "90ACC7": "Fortinet",
    "D4FFD3": "Fortinet",

    # ── MikroTik ──
    "000C42": "MikroTik", "2CC8A8": "MikroTik", "482C6A": "MikroTik",
    "4CFA6E": "MikroTik", "6C2C06": "MikroTik", "74D435": "MikroTik",
    "B8695A": "MikroTik", "B8CBB8": "MikroTik", "C4AD34": "MikroTik",
    "CC2DE0": "MikroTik", "D4CA6D": "MikroTik", "E483FC": "MikroTik",
    "E4896B": "MikroTik", "2C9D1E": "MikroTik",

    # ── Sophos ──
    "000C25": "Sophos", "001A8C": "Sophos", "0019D6": "Sophos",
    "B4748C": "Sophos", "C8F750": "Sophos",

    # ── WatchGuard ──
    "002682": "WatchGuard", "006B4E": "WatchGuard",

    # ── Brocade ──
    "000533": "Brocade", "0027F8": "Brocade", "0050EB": "Brocade",
    "008048": "Brocade", "0090F5": "Brocade",

    # ── Extreme Networks ──
    "000496": "Extreme", "00049B": "Extreme", "0001F4": "Extreme",
    "005057": "Extreme", "B0E75D": "Extreme",

    # ── Arista ──
    "001C73": "Arista", "28993A": "Arista", "30862D": "Arista",
    "444CA8": "Arista",

    # ── Ruckus ──
    "001F41": "Ruckus", "2C5D93": "Ruckus", "3C0771": "Ruckus",
    "645A04": "Ruckus", "C07B5C": "Ruckus", "C4A81D": "Ruckus",

    # ── Huawei (networking gear) ──
    "001882": "Huawei", "002568": "Huawei", "002EC7": "Huawei",
    "00E0FC": "Huawei", "041E64": "Huawei", "048D38": "Huawei",
    "0819A6": "Huawei", "087A4C": "Huawei", "0C37DC": "Huawei",
    "0C45BA": "Huawei", "101B54": "Huawei", "107B44": "Huawei",
    "10C61F": "Huawei", "20A680": "Huawei", "20F3A3": "Huawei",
    "24DF6A": "Huawei", "24FD52": "Huawei", "28310E": "Huawei",
    "282CB2": "Huawei", "303955": "Huawei", "30469A": "Huawei",
    "30D17E": "Huawei", "34B354": "Huawei", "34CDBE": "Huawei",
    "380E4D": "Huawei", "384C4F": "Huawei", "40F385": "Huawei",
    "44C346": "Huawei", "487B6B": "Huawei", "4C1FCC": "Huawei",
    "4CB16C": "Huawei", "54A51B": "Huawei", "5C4CA9": "Huawei",
    "5C7D5E": "Huawei", "607039": "Huawei", "64A2F9": "Huawei",
    "688F84": "Huawei", "6C7220": "Huawei", "70194E": "Huawei",
    "707990": "Huawei", "740E9B": "Huawei", "7429AF": "Huawei",
    "7482CE": "Huawei", "78D752": "Huawei", "7C1CF1": "Huawei",
    "80FB06": "Huawei", "84DBAC": "Huawei", "88CEFA": "Huawei",
    "9017AC": "Huawei", "906FA9": "Huawei", "9467A3": "Huawei",
    "9885D6": "Huawei", "98E7F5": "Huawei", "9C37F4": "Huawei",
    "A40913": "Huawei", "A47E33": "Huawei", "A4A6A9": "Huawei",
    "A8CA7B": "Huawei", "AC4E91": "Huawei", "AC853D": "Huawei",
    "ACE215": "Huawei", "B05B67": "Huawei", "B4306C": "Huawei",
    "B83861": "Huawei", "BC7574": "Huawei", "BC96D4": "Huawei",
    "C0B4A2": "Huawei", "C40528": "Huawei", "C8D15E": "Huawei",
    "CC53B5": "Huawei", "CC96A0": "Huawei", "D065CA": "Huawei",
    "D440F0": "Huawei", "D4B110": "Huawei", "D8490B": "Huawei",
    "DC094C": "Huawei", "DCD2FC": "Huawei", "E0247F": "Huawei",
    "E0CC7A": "Huawei", "E46897": "Huawei", "F4C714": "Huawei",
    "F4E3FB": "Huawei", "F84ABF": "Huawei", "FCDF0E": "Huawei",

    # ── TP-Link ──
    "001D0F": "TP-Link", "003192": "TP-Link", "10FE47": "TP-Link",
    "14CF92": "TP-Link", "14CC20": "TP-Link", "18A6F7": "TP-Link",
    "1C3BF3": "TP-Link", "30DE4B": "TP-Link", "3460F9": "TP-Link",
    "38835D": "TP-Link", "50C7BF": "TP-Link", "54C80F": "TP-Link",
    "5C628B": "TP-Link", "60E327": "TP-Link", "647002": "TP-Link",
    "6C5AB0": "TP-Link", "788CB5": "TP-Link", "7CC2C6": "TP-Link",
    "8C210A": "TP-Link", "903A7E": "TP-Link", "98DA33": "TP-Link",
    "A842A1": "TP-Link", "AC84C6": "TP-Link", "B0A7B9": "TP-Link",
    "B09575": "TP-Link", "C0E42D": "TP-Link", "C4E984": "TP-Link",
    "CC3226": "TP-Link", "D80D17": "TP-Link", "D84651": "TP-Link",
    "E005C5": "TP-Link", "E48D8C": "TP-Link", "EC086B": "TP-Link",
    "EC172F": "TP-Link", "F4F26D": "TP-Link", "F81A67": "TP-Link",
    "F8D111": "TP-Link",

    # ── Netgear ──
    "0024B2": "Netgear", "004A77": "Netgear", "08028E": "Netgear",
    "08BD43": "Netgear", "10DA43": "Netgear", "204E7F": "Netgear",
    "28C68E": "Netgear", "2CB05D": "Netgear", "4494FC": "Netgear",
    "6CB0CE": "Netgear", "803773": "Netgear", "848EDF": "Netgear",
    "9CD36D": "Netgear", "A00460": "Netgear", "A021B7": "Netgear",
    "A42B8C": "Netgear", "B03956": "Netgear", "B07FB9": "Netgear",
    "C03F0E": "Netgear", "C43DC7": "Netgear", "E0469A": "Netgear",
    "E091F5": "Netgear", "E4F4C6": "Netgear",

    # ══════════════════════════════════════════════════════════════════════
    # PRINTERS
    # ══════════════════════════════════════════════════════════════════════

    # ── HP Printers (separate OUIs from HP compute) ──
    "00215A": "HP Printer", "002590": "HP Printer", "00D0B9": "HP Printer",
    "3C2AF4": "HP Printer", "3CD92B": "HP Printer", "58206A": "HP Printer",
    "5C0726": "HP Printer", "6CAE8B": "HP Printer", "80CE62": "HP Printer",
    "886395": "HP Printer", "A03C31": "HP Printer", "A0481C": "HP Printer",
    "B4B676": "HP Printer", "C481AA": "HP Printer", "CCC5E5": "HP Printer",
    "D0BF9C": "HP Printer", "ECC882": "HP Printer",

    # ── Canon ──
    "0013E0": "Canon", "001E8F": "Canon", "002507": "Canon",
    "002E08": "Canon", "04B1A1": "Canon", "18E829": "Canon",
    "2C9EFC": "Canon", "409C28": "Canon", "4C1FCC": "Canon",
    "585857": "Canon", "6C9373": "Canon", "8024BD": "Canon",
    "881880": "Canon", "9068F6": "Canon", "A4EBD3": "Canon",
    "AC3870": "Canon", "B47443": "Canon", "C80257": "Canon",
    "E4478B": "Canon", "E8B4C8": "Canon", "F03295": "Canon",

    # ── Epson ──
    "004042": "Epson", "0011B2": "Epson", "001FB4": "Epson",
    "7CF854": "Epson", "D4E8B2": "Epson", "ECE5D2": "Epson",
    "A4AE11": "Epson", "BCC342": "Epson", "E0227E": "Epson",
    "642737": "Epson",

    # ── Brother ──
    "000CA7": "Brother", "001BA9": "Brother", "002085": "Brother",
    "002628": "Brother", "0035CF": "Brother", "4C4544": "Brother",
    "903C92": "Brother", "B4B024": "Brother", "CC8008": "Brother",
    "E00C7F": "Brother",

    # ── Lexmark ──
    "000027": "Lexmark", "00200D": "Lexmark", "002118": "Lexmark",
    "00236C": "Lexmark", "009072": "Lexmark", "0040F4": "Lexmark",
    "8019FE": "Lexmark",

    # ── Xerox ──
    "000000": "Xerox", "0000AA": "Xerox", "002018": "Xerox",
    "00040A": "Xerox", "000808": "Xerox", "5CE924": "Xerox",
    "64006A": "Xerox", "6C9B02": "Xerox", "784859": "Xerox",
    "9C93E4": "Xerox", "A04EA7": "Xerox", "C87F54": "Xerox",

    # ── Konica Minolta ──
    "005ACA": "Konica Minolta", "00DD0F": "Konica Minolta",
    "0025DF": "Konica Minolta", "002673": "Konica Minolta",

    # ── Ricoh ──
    "000874": "Ricoh", "0016CB": "Ricoh", "001F52": "Ricoh",
    "002217": "Ricoh", "645A04": "Ricoh", "741489": "Ricoh",

    # ══════════════════════════════════════════════════════════════════════
    # IoT / Embedded (commonly seen on Windows networks)
    # ══════════════════════════════════════════════════════════════════════
    "B827EB": "Raspberry Pi", "D83ADD": "Raspberry Pi",
    "DC2632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "0C8A67": "Espressif", "2462AB": "Espressif", "246F28": "Espressif",
    "2CF432": "Espressif", "3C71BF": "Espressif", "5CCF7F": "Espressif",
    "840D8E": "Espressif", "A4CF12": "Espressif", "BCDDC2": "Espressif",
    "CC50E3": "Espressif", "DC4F22": "Espressif", "E868E7": "Espressif",

    # ══════════════════════════════════════════════════════════════════════
    # Special addresses
    # ══════════════════════════════════════════════════════════════════════
    "01005E": "IPv4 Multicast", "0180C2": "IEEE 802.1",
    "333300": "IPv6 Multicast",
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
        clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
        if len(clean) < 6:
            return ""
        oui = clean[:6]
        return _OUI.get(oui, "")
    except Exception:
        return ""
