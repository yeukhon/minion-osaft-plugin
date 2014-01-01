# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re

def convert_rows_to_dict(lines):
    """
    Returns a list of (column1, column2) key-value
    tuple for each non-summary section.

    Parameters
    ----------
    lines : list
        A list of lines orginated from spliting on ":" 
        on a section.

    Returns
    -------
    new_list : list
    
    """

    new_list = []
    for line in lines:
        temp = line.split(":", 1)
        if len(temp) == 2:
            new_list.append([temp[0], temp[1].strip()])
    return {item[0]: item[1] for item in new_list}

def process_report(text):
    def _extra(self, section):
        lines = section.split("\n")
        # each section is preceed by section name, some line and a line of dashes
        # the "some line" could be an empty line or column's names
        if len(lines) < 4:
            raise Exception("Incomplete section discovered in the report.")

        data = lines[4:]
        report_data = []
        for item in data:
            temp = item.split(":", 1)
            new_list.append( [temp[0], temp[1].strip()] )
        return report_data

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

def skip_to_target(lines):
    """
    Locate the index of the beginning of the Target section
    from a list of lines of the stdout.

    Parameters
    ----------
    lines : list
        A list of lines split on "\n" from the original stdout.

    Returns
    -------
    target_index : int
        The location of the Target section header in the list.

    """

    target_index = 0
    for i, line in enumerate(lines):
        if "==== Target:" in line:
            target_index = i
            break
    if target_index == 0:
        raise Exception("Report does not contain Target section.")
    return target_index

def split_sections(command, stdout):
    """
    Split the stdout report into a list of sections based on command.

    Different command has different output so different sections will
    be found. To further split each section down into key-value dict,
    call ``convert_section_to_dict``.

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
    Return a list of sections in the info report.

    Parameters
    ----------
    all_lines : list
        A list of lines from the original stdout which is generated
        by splitting on ``\n``.
    target_index : int
        The index where the target section header first appear.

    Returns
    -------
    sections_list : list

    """

    info_sections = [
        "=== Informations ==="
    ]
    sections_title = [
        "Certificate Information"
    ]

    sections = []

    sections_count = len(info_sections)
    next_h_index = 0
    # to split by section, we find the index of the section header in
    # and the location of the next header (if not already last) from
    # all the lines.
    for index, section_header in enumerate(info_sections):
        header_index = all_lines.index(section_header)
        # skip the entire header we don't need it in the report
        starting_index = header_index + 1
        if index == sections_count - 1:
            # we hit the last section so we don't need to the last index
            ending_index = None
        else:
            # we are not at the last section so we better find the index
            # of the next section
            next_h_index = all_lines.index(info_sections[index+1])
            # go one line up before the next header appears
            ending_index = next_h_index - 1
        # once we split, we need to remove empty lines
        sections.append(filter(None, all_lines[starting_index:ending_index]))

    # sections now contains all the lines for each individual section
    # zip each section with the title we will use in the report
    sections_dict = dict(zip(sections_title, sections))

    # we need to further process the dictionary by breaking into
    # key/value.
    for section, rows in sections_dict.items():
        sections_dict[section] = convert_rows_to_dict(rows)

    return sections_dict
