#!/usr/bin/env python3

# ip2as DB_091803.txt IPlist.txt
# Sources used:
# https://www.programiz.com/python-programming/methods/built-in/format


"""
Authors: Eric Lee 915044258
         Zaw Aung 915448472

Usage:
run "./ip2as.py DB_091803.txt IPlist.txt“

Sources used:
1. https://www.programiz.com/python-programming/methods/built-in/format
2. https://mypy.readthedocs.io/en/stable/cheat_sheet_py3.html
3. https://www.ipaddressguide.com/cidr
4. https://stackoverflow.com/questions/8928240/convert-base-2-binary-number-string-to-int
5. https://www.browserling.com/tools/bin-to-ip
6. https://www.browserling.com/tools/ip-to-bin
7. https://www.w3schools.com/python/ref_string_format.asp
8. https://www.w3schools.com/python/gloss_python_raise.asp
9. https://www.geeksforgeeks.org/python-map-function/
10. https://realpython.com/python-f-strings/
11. https://www.w3schools.com/python/ref_string_split.asp
12. https://askubuntu.com/questions/1189360/how-to-make-python-shebang-use-python3
13. https://docs.python.org/3/tutorial/classes.html
"""

import sys


class IPAddress:
    def __init__(self, ip_addr: str):
        """
        __init__ creates a new IPAddress object when reading in a new IP address from IPlist.txt
        """
        self.ip_addr = ip_addr
        self.best_db = None
        self.bit_addr, self.sections = convert_ip(ip_addr)


class DBEntry:
    def __init__(
        self, addr: str, bit_addr: str, sections: list[int], mask: int, asn: int
    ):
        """
        __init__ creates a new DBEntry object when reading from DB.txt
        """
        self.addr = addr
        self.bit_addr = bit_addr
        self.mask = mask
        self.asn = asn
        self.sections = sections
        self.low, self.high = self.calculate_range()

    def match(self, ip_addr: IPAddress) -> bool:
        """
        match checks whether an IPAddress is this DBEntry's address range or not. It does so by checking each
        byte of the IPAddress and making sure that it is between the DBEntry's low and high value for that same byte.
        """
        for i in range(4):
            val = ip_addr.sections[i]
            if val < self.low[i] or val > self.high[i]:
                return False

        return True

    def calculate_range(self) -> (list[int], list[int]):
        """
        get_range calculate and returns two lists of integers that represent the low and high ranges of this
        DB entry. Each list contains 4 decimals representing the four octets of an address.

        e.g 1.1.1.1 becomes [1, 1, 1, 1]
        """

        low, high = "", ""
        for i in range(32):
            if i < self.mask:  # the mask bits are always the same
                low += self.bit_addr[i]
                high += self.bit_addr[i]
            else:  # extra bits at the end are either 0 or 1
                low += "0"
                high += "1"

            # Add a period after each byte and make sure one doesnt appear at the very end or the beginning
            if (i + 1) % 8 == 0 and i > 0 and i != 31:
                low += "."
                high += "."

        # Convert the strings into lists of integers
        low = low.split(".")
        high = high.split(".")
        low = [int(x, 2) for x in low]
        high = [int(x, 2) for x in high]

        return low, high


def convert_ip(ip_addr: str) -> (list[int], str):
    """
    convert_ip converts an IP address string into a bitstring by:
    1. splitting the ip address into 4 string sections (one for each byte)
    2. converting each section into binary (8-bit)
    3. joining the sections together to form the bitstring
    """

    def transform_binary(val):
        """
        transform converts an integer string to binary. It first converts the string to an integer then
        formats the integer as binary. The width is set at 8 and is left-padded with 0s.
        """
        return format(val, "0>8b")

    sections = ip_addr.split(".")
    sections = [int(s) for s in sections]
    for val in sections:
        if val < 0 or val > 255:
            raise Exception("section value should be between 0 and 255")

    bin_sections = [transform_binary(s) for s in sections]
    bit_addr = "".join(bin_sections)
    return (bit_addr, sections)


def parse_db_str(entry: str):
    """
    parse_db_str parses a single line from the DB.txt file and returns a new DBEntry object.
    """

    # Split database entry into sections and make sure that the address, mask, and ASN are there
    sections = entry.split(" ")
    if len(sections) < 3:
        return None

    addr = sections[0]
    mask = int(sections[1])
    asn = int(sections[2])

    # Attempt to convert the ip address into binary. If it fails for any reason, exit the function.
    try:
        bit_addr, addr_sections = convert_ip(addr)
    except Exception:
        return None

    # Make sure that the mask is between 0 and 32
    if mask < 0 or mask > 32:
        return None

    return DBEntry(addr, bit_addr, addr_sections, mask, asn)


DB_addr = open(sys.argv[1], "r")  # Open Database File
DB_list = []
for line in DB_addr:
    db_entry = parse_db_str(line.strip())
    
    # Store DB entry in list if not invalid
    if db_entry is not None:
        DB_list.append(db_entry)

IPlist = open(sys.argv[2], "r")  # Open IPlist File
IPaddr_list = []
for line in IPlist:
    IPaddr_list.append(IPAddress(line.strip()))

for ip in IPaddr_list:
    bestDB_mask = 0
    # Check for match between IP and DB
    for db in DB_list:
        matches = db.match(ip)
        # Replace bestDB_mask if new mask is larger
        if matches and db.mask > bestDB_mask:
            # Store DB within class object
            ip.best_db = db

# Print out the results
for ip in IPaddr_list:
    print(f"{ip.best_db.addr}/{ip.best_db.mask} {ip.best_db.asn} {ip.ip_addr}")
print()
