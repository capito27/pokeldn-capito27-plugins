"""The tests run against a pokeldn checkout of plugin API 1.8 or newer: POKELDN_SOURCE, else a pokeldn folder
next to this repository. Its data folder is a temporary one, so no test touches Documents/pokeldn."""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.abspath(os.environ.get("POKELDN_SOURCE") or os.path.join(ROOT, "..", "..", "pokeldn"))

for path in (os.path.join(SOURCE, "vendor", "LDN"), SOURCE, os.path.join(ROOT, "tools"), ROOT):
    if path in sys.path:
        sys.path.remove(path)
    sys.path.insert(0, path)

# A live run's variables left in the shell send a run down the board path; pokeldn.app.paths reads POKELDN_DATA at
# import, so they are set before any test module loads.
for name in ("POKELDN_RADIO", "POKELDN_ESP32_TRACE", "POKELDN_ESP32_BAUD", "POKELDN_MANAGED_RUN", "POKELDN_POPUPS",
             "POKELDN_PLUGINS"):
    os.environ.pop(name, None)
os.environ["POKELDN_DATA"] = tempfile.mkdtemp(prefix="switch-updates-tests-")

import pytest  # noqa: E402

from pokeldn import plugins  # noqa: E402

if (plugins.API_VERSION, plugins.API_LEVEL) < (1, 8):
    pytest.exit(f"{SOURCE} is pokeldn with plugin API {plugins.API_VERSION}.{plugins.API_LEVEL}; the plugin needs "
                "1.8 (pokeldn 0.29.0). Set POKELDN_SOURCE to a newer checkout.", returncode=4)
