#minion-osaft-plugin

This is a minion plugin for the OWASP O-SAFT
(https://github.com/OWASP/O-Saft) plugin.

##Getting Started

First, setup Minion (https://github.com/mozilla/minion).

Second, grab the O-Saft source code from https://github.com/OWASP/O-Saft.

```
git clone https://github.com/OWASP/O-Saft.git
mv O-Saft o-saft
chmod +x o-saft/o-saft.pl
rm o-saft/o-saft-README
```

Finally, clone this repository.

```
git clone https://github.com/yeukhon/minion-osaft-plugin
cd minion-osaft-plugin
source <MINION_BACKEND_VRITUAL_ENV>/bin/activate
[sudo] python setup.py [develop|install]
```

Note you need to replace ``MINION_BACKEND_VIRTUAL_ENV`` with
the name of the virtualenv you created for Minion. If you install
Minion to the global, system Python interpreter, you can skip that
step.

## Plugin Plan

You can get started by creating a plan like this::

```
[
  {
    "configuration": {
      "info": true
    },
    "description": "Run the O-Saft SSL/TLS Scanner",
    "plugin_name": "minion.plugins.osaft.OSAFTPlugin"
  }
]

```

You can enable either ``info``, ``quick`` or ``check``. Only
one is allowed per scan.
