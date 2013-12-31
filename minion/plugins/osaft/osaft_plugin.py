# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from minion.plugins.base import ExternalProcessPlugin

class OSAFTPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "O-SAFT"
    PLUGIN_VERSION = "0.0"

    OSAFT_NAME = "o-saft.pl"
    OSAFT_MIN_VERSION = "13.12.17b"
    OSFT_MAX_VERSION = "13.12.17b"

    def do_start(self):
        osaft_path = "/home/vagrant/o-saft/o-saft.pl"
        osaft_executable = "perl" + " " + osaft_path
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
            command = "+info"
        elif quick:
            command = "+quick"
        else:
            command = "+check"

        target = configs["target"]
        self.spawn("perl", [osaft_path, command, target])

    def do_process_stdout(self, data):
        self.stdout += data

    def do_process_stderr(self, data):
        self.stderr += data

    def do_process_ended(self, process_status):
        if self.stopping and process_status == 9:
            self.report_finish("STOPPED")
        elif process_status == 0:
            if not self.stderr:
                summary = "Successful OSAFT scan"
                description = self.stdout
            else:
                summary = "Unsuccessful OSAFT scan"
                description = self.stdout
            self.report_issues([
                {"Summary": summary,
                 "Description": description,
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": [ {"URL": None, "Title": None} ]
                }
            ])
            self.report_finish()
