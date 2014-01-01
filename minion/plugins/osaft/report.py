# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re

def convert_rows_to_dict(lines):
    """
    Convert each row in a section into
    key-value pair by splitting on ``:``
    character in each row. The first ``:``
    is the key.

    Parameters
    ----------
    lines : list
        A list of lines orginated from spliting on ":" 
        on a section.

    Returns
    -------
    section_dict : dict
    
    """

    new_list = []
    for line in lines:
        temp = line.split(":", 1)
        if len(temp) == 2:
            new_list.append([temp[0], temp[1].strip()])
    return {item[0]: item[1] for item in new_list}

def split_cipher_check(cipher_list, name):
    if len(cipher_list) < 3:
        raise Exception("%s cipher check list does not have enough rows to parse." % name)
    ciphers = cipher_list[3:]
    title = "%s Cipher Checks" % name
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
        #"+quick": split_quick_sections,
        #"+check": split_check_sections
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
        sections_dict[section] = convert_rows_to_dict(rows)

    return sections_dict
