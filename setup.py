# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = []

setup(name="minion-osaft-plugin",
      version="0.0",
      description="OWASP O-SAFT SSL Plugin for Minion",
      url="https://github.com/yeukhon/minion-osaft-plugin/",
      author="Yeuk Hon Wong",
      author_email="yeukhon@acm.org",
      packages=['minion', 'minion.plugins', 'minion.plugins.osaft'],
      namespace_packages=['minion', 'minion.plugins'],
      include_package_data=True,
      install_requires=install_requires)
