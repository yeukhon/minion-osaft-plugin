# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import re
import subprocess

from minion.plugins.base import ExternalProcessPlugin
from report import split_sections, get_info_issues, get_check_issues, get_quick_issues

class OSAFTPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "O-SAFT"
    PLUGIN_VERSION = "0.1"

    OSAFT_NAME = "o-saft.pl"
    OSAFT_MIN_VERSION = "13.12.17b"
    OSAFT_MAX_VERSION = "13.12.26"

    def load_config(self):
        for config_f in ["/etc/minion/osaft-plugin.json", \
                os.path.expanduser("~/.minion/osaft-plugin.json")]:
            if os.path.exists(config_f):
                with open (config_f, "r") as f:
                    return json.load(f)
        raise Exception("osaft-plugin.json does not exist.")

    # override the default locate_program
    def locate_program(self):
        osaft_config = self.load_config()
        osaft_path = osaft_config.get("osaft-path")
        if not osaft_path:
            raise Exception("osaft-plugin.json must specify osaft-path.")

        osaft_path = os.path.join(osaft_path, self.OSAFT_NAME)
        if not os.path.exists(osaft_path):
            raise Exception("{path} does not exists.".format(path=osaft_path))
        self.osaft_path = osaft_path

    def check_version(self, program_path):
        p = subprocess.Popen([program_path, "--version"], \
            stdout=subprocess.PIPE, \
            stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if stderr:
            return Exception("Unable to launch O-SAFT to check version. " + stderr)

        r = re.compile("o-saft.pl\s(?P<version>\d+\.\d+\.\d+\w)")
        m = r.search(stdout)
        if m:
            version = m.group('version')
            if version < self.OSAFT_MIN_VERSION or version > self.OSAFT_MAX_VERSION:
                raise Exception("This version {cv} is not supported. We only support {v1} to {v2}".format(
                                cv=version, v1=self.OSAFT_MIN_VERSION, v2=self.OSAFT_MAX_VERSION))
        else:
            raise Exception("Unable to detect O-SAFT version.")

    def do_start(self):
        self.locate_program()
        self.check_version(self.osaft_path)
        self.stdout = ""
        self.stderr = ""

        # validate and construct arguments
        configs = self.configuration
        info, quick, check = configs.get('info'), \
                             configs.get('quick'), \
                             configs.get('check')
        _cmd_count = sum(map(bool, (info, quick, check)))
        if _cmd_count > 1:
            raise Exception("Only one O-SAFT command (info, quick, check) is allowed per scan.")
        elif not _cmd_count:
            raise Exception("One O-SAFT command (info, quick, check) must be specified per scan.")

        if info:
            self.osaft_command = "+info"
        elif quick:
            self.osaft_command = "+quick"
        else:
            self.osaft_command = "+check"

        target = configs["target"]
        self.spawn(self.osaft_path, [self.osaft_command, target])

    def do_process_stdout(self, data):
        self.stdout += data

    def do_process_stderr(self, data):
        self.stderr += data

    def do_process_ended(self, process_status):
        if self.stopping and process_status == 9:
            self.report_finish("STOPPED")
        elif process_status == 0:
            sections_dict = split_sections(self.osaft_command, self.stdout)
            if self.stdout:
                if self.osaft_command == "+info":
                    issues = get_info_issues(sections_dict)
                elif self.osaft_command == "+check":
                    issues = get_check_issues(sections_dict)
                elif self.osaft_command == "+quick":
                    issues = get_quick_issues(sections_dict)    
                self.report_issues(issues)
            else:
                summary = "Unsuccessful OSAFT scan"
                description = self.stderr
                self.report_issues([
                    {"Summary": summary,
                     "Description": description,
                    "Severity": "Info",
                    "URLs": [ {"URL": None, "Extra": None} ],
                    "FurtherInfo": [ {"URL": None, "Title": None} ]
                    }
                ])
            self.report_finish()
