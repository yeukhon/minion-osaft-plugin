# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import copy
import re
from datetime import datetime

def convert_rows_to_dict(section, lines):
    """
    Convert each row in a section into
    key-value pair by splitting on ``:``
    character in each row. The first ``:``
    is the key.

    Parameters
    ----------
    section : str
        The key used in the report corresponding to
        this section of lines.
    lines : list
        A list of lines orginated from spliting on ":" 
        on a section.

    Returns
    -------
    section_dict : dict
    
    """

    if "Checklist" in section:
        return convert_cipher_checks_to_dict(lines)
    else:
        new_list = []
        for line in lines:
            temp = line.split(":", 1)
            if len(temp) == 2:
                new_list.append([temp[0], temp[1].strip()])
        return {item[0]: item[1] for item in new_list}

def convert_cipher_checks_to_dict(cipher_list):
    ciphers = cipher_list[3:]
    cipher_dict = {"high": {}, "medium": {}, "weak": {}, "low": {}, "unknown": {}}
    for cipher in ciphers:
        empty, cipher_name, present, strength = re.split("\s*", cipher)
        if "-?-" == strength:
            strength = "unknown"
        else:
            strength = strength.lower()
        cipher_dict[strength][cipher_name] = present
    return cipher_dict

def split_cipher_check(cipher_list, title):
    ciphers = cipher_list[3:]
    cipher_dict = {title : {"high": {}, "medium": {}, "weak": {}, "low": {}}}
    for cipher in ciphers:
        empty, cipher_name, present, strength = re.split("\s*", cipher)
        strength = strength.lower()
        cipher_dict[title][strength][cipher_name] = present
    return cipher_dict

def split_sections(command, stdout):
    """
    Split the stdout report into a list of sections based on command.

    Different command has different output so different sections will
    be found. To further split each section down into key-value dict,
    call ``convert_rows_to_dict``.

    Parameters
    ----------
    command : str
        One of the followings: +info, +quick, +check
    stdout : str
        The full report collected from stdout.

    Returns
    -------
    sections_list : list
        A list of sections split by finding the \n at the end of the
        line of the section header.

    """

    all_lines = stdout.split("\n")
    spliter = {
        "+info": split_info_sections,
        "+quick": split_quick_sections,
        "+check": split_check_sections
    }
    return spliter[command](all_lines)

def split_info_sections(all_lines):
    """
    Return a dict of sections in the info report.

    Parameters
    ----------
    all_lines : list
        A list of lines from the original stdout which is generated
        by splitting on ``\n``.

    Returns
    -------
    sections_dict : dict

    """

    info_sections = [
        "=== Informations ==="
    ]
    titles = [
        "Certificate Information"
    ]

    return section_processor(all_lines, info_sections, titles)

def split_check_sections(all_lines):
    """
    Return a dict of sections from the check report.

    See Also
    --------
    split_info_sections function.

    """

    check_sections = [
        "=== Ciphers: Checking SSLv3 ===",
        "== Ciphers: Summary SSLv3 ==",
        "=== Ciphers: Checking TLSv1 ===",
        "== Ciphers: Summary TLSv1 ==",
        "== Ciphers: Summary  ==",
        "=== Performed Checks ===",
        "=== Scoring Results ==="
    ]
    titles = [
        "SSLv3 Ciphers Checklist",
        "SSLv3 Ciphers Summary",
        "TLSv1 Ciphers Checklist",
        "TLSv1 Ciphers Summary",
        "Ciphers Checks Summary",
        "Certificate Check Summary",
        "Certificate Check Scores",
    ]
    return section_processor(all_lines, check_sections, titles)

def split_quick_sections(all_lines):
    quick_sections = [
        "=== Ciphers: Checking SSLv3 ===",
        "== Ciphers: Summary SSLv3 ==",
        "=== Ciphers: Checking TLSv1 ===",
        "== Ciphers: Summary TLSv1 ==",
        "== Ciphers: Summary  ==",
        "=== Informations ===",
        "=== Performed Checks ==="
    ]
    titles = [
        "SSLv3 Ciphers Checklist",
        "SSLv3 Ciphers Summary",
        "TLSv1 Ciphers Checklist",
        "TLSv1 Ciphers Summary",
        "Ciphers Checks Summary",
        "Certificate Information",
        "Certificate Check Summary"
    ]
    return section_processor(all_lines, quick_sections, titles)

def section_processor(all_lines, sections_headers, titles):
    """
    Break down sections and rows into a dictionary of the form
    ``{report_section_title: {row_key: row_value}``.

    Parameters
    ----------
    all_lines : list
    sections_headers : list
    titles : list

    Returns
    -------
    sections_dict : dict

    """

    sections = []
    sections_count = len(sections_headers)
    next_h_index = 0

    # to split by section, we find the index of the section header in
    # and the location of the next header (if not already last) from
    # all the lines.
    for index, section_header in enumerate(sections_headers):
        header_index = all_lines.index(section_header)
        # skip the entire header we don't need it in the report
        starting_index = header_index + 1
        if index == sections_count - 1:
            # we hit the last section so we don't need to the last index
            ending_index = None
        else:
            # we are not at the last section so we better find the index
            # of the next section
            next_h_index = all_lines.index(sections_headers[index+1])
            # go one line up before the next header appears
            ending_index = next_h_index - 1
        # once we split, we need to remove empty lines
        sections.append(filter(None, all_lines[starting_index:ending_index]))

    # sections now contains all the lines for each individual section
    # zip each section with the title we will use in the report
    sections_dict = dict(zip(titles, sections))

    # we need to further process the dictionary by breaking into
    # key/value.
    for section, rows in sections_dict.items():
        sections_dict[section] = convert_rows_to_dict(section, rows)

    return sections_dict

BASIC_FURTHER_INFO = [
    {
        "URL": "https://www.ssllabs.com/projects/best-practices/",
        "Title": "QUALYS SSL Labs - SSL/TLS Deployment Best Practices",
    },
    {
        "URL": "http://httpd.apache.org/docs/2.2/ssl/ssl_intro.html",
        "Title": "Apache - SSL/TLS Strong Encryption: An Introduction",
    },
    {
        "URL": "https://developer.mozilla.org/en-US/docs/Introduction_to_SSL",
        "Title": "Mozilla Developer Network - Introduction to SSL",
    },
    {
        "URL": "https://wiki.mozilla.org/Security/Server_Side_TLS",
        "Title": "Mozilla Developer Network - Security/Server Side TLS",
    },
    {
        "URL": "https://www.owasp.org/index.php/Testing_for_SSL-TLS_(OWASP-CM-001)",
        "Title": "OWASP - Testing for SSL-TLS",
    },
    {
        "URL": "http://www.openssl.org/related/ssl.html",
        "Title": "OpenSSL - SSL/TLS"
    }
]

FURTHER_INFO_ON_KEY_SIZE = [
    {
        "URL": "https://www.globalsign.com/ssl-information-center/choosing-safe-key-sizes.html",
        "Title": "GlobalSign SSL Authority - Algorithms, key size and Digital Certificates"
    }
]
FURTHER_INFO_ON_KEY_SIZE += BASIC_FURTHER_INFO

FURTHER_INFO_ON_RENGO = [
    {
        "URL": "http://www.digicert.com/news/2011-06-03-ssl-renego.htm",
        "Title": "digicert - Fixing TLS Renegotiation on Your Server",
    },
    {
        "URL": "https://wiki.mozilla.org/Security:Renegotiation",
        "Title": "Mozilla Wiki - Security:Renegotiation"
    },
    {
        "URL": "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555",
        "Title": "Vulnerability Summary for CVE-2009-3555"
    }
]
FURTHER_INFO_ON_RENGO += BASIC_FURTHER_INFO

FURTHER_INFO_ON_CERT_VALID = [
    {
        "URL": "https://www.globalsign.com/blog/the-dangers-of-ssl-certificate-expiration.html",
        "Title": "GlobalSign Certificate Authority - The Dangers of SSL Certificate Expiration",
    }
]
FURTHER_INFO_ON_CERT_VALID += BASIC_FURTHER_INFO

FURTHER_INFO_ON_CIPHER_LEVEL = BASIC_FURTHER_INFO

FURTHER_INFO_ON_SELF_SIGNED_CERT = [
    {
        "URL": "https://www.globalsign.com/ssl-information-center/dangers-of-self-signed-certificates.html",
        "Title": "GlobalSign CA - Dangers of Self-signed SSL Certificates",
    },
    {
        "URL": "http://www.symantec.com/connect/blogs/self-signed-certificates-how-and-when-use-them-symantec",
        "Title": "Symantec - Self-Signed Certificates: How and When to Use Them",
    }
]
FURTHER_INFO_ON_SELF_SIGNED_CERT += BASIC_FURTHER_INFO

FURTHER_INFO_ON_PFS = [
    {
        "URL": "https://community.qualys.com/blogs/securitylabs/2013/06/25/ssl-labs-deploying-forward-secrecy",
        "Title": "Qualys SSL Lab - Deploying Forward Secrecy"
    },
    {
        "URL": "https://blog.twitter.com/2013/forward-secrecy-at-twitter-0",
        "Title": "Twitter Blog - Forward Secrecy at Twitter",
    },
    {
        "URL": "https://blog.mozilla.org/security/2013/11/12/navigating-tls/",
        "Title": "Mozilla Security Blog - Navigating the TLS landscape"
    },
]
FURTHER_INFO_ON_PFS += BASIC_FURTHER_INFO

_issues = {
    "low_pk_strength":
        {
            "Code": "OSAFT-0",
            "Summary": "Certificate key size should be at least 2048 bits",
            "Description": "Certificate key size is too low. The current key size is {size} bits. 2048 bits is the \
minimum recommended size for a SSL/TLS certificate.",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_KEY_SIZE
        },
     "high_pk_strength":
        {
            "Code": "OSAFT-1",
            "Summary": "Certificate key size is at least 2048 bits",
            "Description": "Certificate key size has met the minimal key size recommendation, which is at least \
2048 bits. The current key size is {size} bits.",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_KEY_SIZE
        },
   "no_sec_renego":
        {
            "Code": "OSAFT-2",
            "Summary": "Server does not support secure TLS renegotation",
            "Description": "A flaw in the design of the TLS v.1/SSL v.3 (TLS/SSL) handshake process was discovered \
in 2009, and RFC 5746 (Feb. 2010) was released to update the protocol specification. The flaw enables man-in-the-middle \
attack during the handshake process. This scan reveals that the target server serving the SSL/TLS is not up-to-date.",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_RENGO
        },
   "has_sec_renego":
        {
            "Code": "OSAFT-3",
            "Summary": "Server supports secure TLS renegotation",
            "Description": "The target server serving the SSL/TLS certificate has secure_renegotation flag enabled. \
A flaw in the design of the TLS v.1/SSL v.3 (TLS/SSL) handshake process was discovered in 2009, and RFC 5746 \
(Feb. 2010) was released to update the protocol specification. The flaw enables man-in-the-middle attack during \
the handshake process. This scan reveals that the target server is safe from TLS renegotation man-in-the-middle attack.",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_RENGO
        },
    "expired":
        {
            "Code": "OSAFT-4",
            "Summary": "Certificate has expired",
            "Description": "A certificate is issued and considered valid for a period of time. The scan reveals that \
the scanned certificate has expired since {timestamp}.",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_CERT_VALID
        },
    "valid":
        {
            "Code": "OSAFT-5",
            "Summary": "Certificate is still valid",
            "Description": "A certificate is issued and considered valid for a period of time. The scan reveals that \
the scanned certificate is still valid.",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_CERT_VALID
        },
    "low_cipher_default":
        {
            "Code": "OSAFT-6",
            "Summary": "Default cipher for {version} is considered weak",
            "Description": "The default cipher for {version} return from the server is {cipher}. The security strength is {level}. \
It is recommended to choose a higher security strength cipher.",
            "Severity": "Medium",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_CIPHER_LEVEL
        },
    "high_cipher_default":
        {
            "Code": "OSAFT-7",
            "Summary": "Default cipher for {version} is considered strong",
            "Description": "The default cipher for {version} return from the server is {cipher}. The security strength is {level}.",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_CIPHER_LEVEL
        },
    "is_self_signed":
        {
            "Code": "OSAFT-8",
            "Summary": "Certificate is self-signed",
            "Description": "Self-signed certificates are not verifiable by clients such as browsers because they are not \
signed and trusted by any Certificate Authority (CA). A web user must add the self-signed certificate at his or her own \
risk. Self-signed certificate cannot prove the legitimacy of the connection.",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_SELF_SIGNED_CERT
        },
    "not_self_signed":
        {
            "Code": "OSAFT-9",
            "Summary": "Certificate is trusted and signed by a CA",
            "Description": "This certificate is signed and trusted by a Certificate Authority (CA). A web user can connect \
to the target server with high confident the connection is legitmate and trusted.",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_SELF_SIGNED_CERT
        },
    "no_pfs":
        {
            "Code": "osaft-10",
            "Summary": "Server does not support perfect forward secrecy",
            "Description": "Under traditional https, the client chooses a random session key, encrypts it using the server \
public key, and sends it over the network. When the key is compromised, all previous traffic and future traffic can be decrypted. \
Instead of requiring two parties (e.g. browser and the server) to agree on the session key by exchanging each other's key, \
PFS performs Diffie-Hellman keychange so that only the two parties have access to the session key.",
            "Severity": "Medium",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_PFS
        },
    "support_pfs":
        {
            "Code": "osaft-11",
            "Summary": "Server supports perfect forward secrecy",
            "Description": "This server supports forward secrecy. Under traditional https, the client chooses a random \
session key, encrypts it using the server public key, and sends it over the network. When the key is compromised, all \
previous traffic and future traffic can be decrypted. Instead of requiring two parties (e.g. browser and the server) \
to agree on the session key by exchanging each other's key, PFS performs Diffie-Hellman keychange so that only the two\
 parties have access to the session key.",
            "Severity": "Info",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_PFS
        },
}

def format_report(issue_key, format_list):
    issue = copy.deepcopy(_issues[issue_key])
    for component in format_list:
        for component_name, kwargs in component.items():
            issue[component_name] = issue[component_name].format(**kwargs)
    return issue

def default_cipher_check(version, result):
    def _get_cipher_level(text):
        cipher, level = text.split(" ")
        return cipher.strip(), level.strip()

    cipher, level = _get_cipher_level(result)
    if "HIGH" not in result:
        return format_report('low_cipher_default', 
                [{"Summary": {"version": version}},
                 {"Description": {"version": version, "cipher": cipher, "level": level}}])
    else:
        return format_report('high_cipher_default',
                [{"Summary": {"version": version}},
                 {"Description": {"version": version, "cipher": cipher, "level": level}}])


def check_cert_expire(result):
    # when cert is valid not expired, we only receive yes
    # so on split the tuple is empty string on both positions
    _, valid_until = re.split(r"yes|no", result)
    if valid_until:
        return False, valid_until
    else:
        return True, None

def get_check_issues(check_report):
    """
    Return a list of issues that the +check have discovered.
    """

    issues = []
    cert_summary = check_report["Certificate Check Summary"]
    sslv3_default = cert_summary["Default cipher for SSLv3"]
    tlsv1_default = cert_summary["Default cipher for TLSv1"]
    pk_strength = cert_summary["Certificate public key size"]
    is_not_expired = cert_summary["Certificate is not expired"]
    is_not_self_signed = cert_summary["Certificate is not self-signed"]
    support_pfs = cert_summary["Target supports forward secrecy (PFS)"]

    for suite in (("SSLv3", sslv3_default), ("TLSv1", tlsv1_default)):
        issues.append(default_cipher_check(suite[0], suite[1]))

    key_size = pk_strength.split(" bits")[0]
    if int(key_size) < 2048:
        issues.append(
            format_report('low_pk_strength', 
                [{"Description": {"size": key_size}}]))
    else:
        issues.append(
            format_report('high_pk_strength', 
                [{"Description": {"size": key_size}}]))

    is_not_expired, valid_until = check_cert_expire(is_not_expired)
    if not is_not_expired:
        valid_until = valid_until.split("(")[1].split(")")[0]
        issues.append(
            format_report('expired', 
                [{"Description": {"timestamp": valid_until}}]))
    else:
        issues.append(_issues["valid"])

    if "no" in is_not_self_signed:
        issues.append(_issues["is_self_signed"])
    else:
        issues.append(_issues["not_self_signed"])

    if "no" in support_pfs:
        issues.append(_issues["no_pfs"])
    else:
        issues.append(_issues["support_pfs"])
    
    return issues

def get_info_issues(info_report):
    """
    Return a list of issues that the +info have discovered.

    Parameters
    ----------
    info_report : dict
        This dictionary should come from section_processor.

    Returns
    -------
    issues: list
        A list of issues found in the standard Minion
        scan issue format.

    """

    issues = []
    cert_info = info_report["Certificate Information"]
    pk_strength = cert_info.get("Certificate Public Key Length")
    has_sec_renego = cert_info.get("Target supports renegotiation")
    valid_until = cert_info.get("Certificate valid until")

    if int(pk_strength) < 2048:
        issues.append(
            format_report('low_pk_strength', 
                [{"Description": {"size": pk_strength}}]))
    else:
        issues.append(
            format_report('high_pk_strength', 
                [{"Description": {"size": pk_strength}}]))

    expire_datetime = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
    if datetime.today() >= expire_datetime:
        issues.append(
            format_report('expired', 
                [{"Description": {"timestamp": valid_until}}]))
    else:
        issues.append(
            format_report('valid', 
                [{"Description": {"timestamp": valid_until}}]))

    if has_sec_renego != "Secure Renegotiation IS supported":
        issues.append(_issues["no_sec_renego"])
    else:
        issues.append(_issues["has_sec_renego"])

    return issues

def get_quick_issues(quick_report):
    issues = []
    cert_info = quick_report["Certificate Information"]
    cert_summary = quick_report["Certificate Check Summary"]
    sslv3_default = cert_summary["Default CipherSSLv3"]
    tlsv1_default = cert_summary["Default CipherTLSv1"]
    is_not_expired = cert_summary["Validity (date)"]
    support_pfs = cert_summary["PFS supported"]
    has_sec_renego = cert_info["Renegotiation"]

    for suite in (("SSLv3", sslv3_default), ("TLSv1", tlsv1_default)):
        issues.append(default_cipher_check(suite[0], suite[1]))

    is_not_expired, valid_until = check_cert_expire(is_not_expired)
    if not is_not_expired:
        valid_until = valid_until.split("( ..")[1].split(")")[0].strip()
        issues.append(
            format_report('expired', 
                [{"Description": {"timestamp": valid_until}}]))
    else:
        issues.append(_issues['valid'])

    if "no" in support_pfs:
        issues.append(_issues["no_pfs"])
    else:
        issues.append(_issues["support_pfs"])

    if has_sec_renego != "Secure Renegotiation IS supported":
        issues.append(_issues["no_sec_renego"])
    else:
        issues.append(_issues["has_sec_renego"])

    return issues
