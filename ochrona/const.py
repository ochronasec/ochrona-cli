# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

PIPFILE_LOCK = "Pipfile.lock"
POETRY_LOCK = "poetry.lock"
SETUP_PY = "setup.py"
REQUIREMENTS_TXT = "requirements.txt"
CONSTRAINTS_TXT = "constraints.txt"
CONDA_ENVIRONMENT = "environment.yml"
TOX_INI = "tox.ini"

SUPPORTED_DEPENDENCY_FILE_PATTERNS = {
    REQUIREMENTS_TXT: "**/*requirements*.txt",
    CONSTRAINTS_TXT: "**/*constraints*.txt",
    PIPFILE_LOCK: "**/*Pipfile.lock",
    POETRY_LOCK: "**/*poetry.lock",
    SETUP_PY: "**/*setup.py",
    CONDA_ENVIRONMENT: "**/environment.yml",
    TOX_INI: "**/tox.ini",
}

INVALID_REQUIREMENTS_LINES = [
    "#",
    "-i",
    "-f",
    "-Z",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "--no-index",
    "--allow-external",
    "--allow-unverified",
    "--always-unzip",
    "--hash",
]

TOX_LINKED_REQUIREMENTS = "-r"
INVALID_TOX_LINES = ["{"]

INVALID_SPECIFIERS = {"<", ">", "!", "~"}
EQUALS_SPECIFIER = "=="

LICENSE_MAP = {
    "AGPL-3.0-only": ["AGPLv3", "AGPL 3.0"],
    "Apache-2.0": [
        "Apache License 2.0",
        "Apache License",
        "Apache 2.0",
        "Apache 2",
        "Apache Software License",
        "Apache License Version 2.0",
        "Apache License, Version 2.0",
        "Apache",
        "Apache Software License 2.0",
        "http://www.apache.org/licenses/LICENSE-2.0",
        "ASL 2",
        "APL 2.0",
        "BSD License (Apache)",
    ],
    "ZPL-2.1": ["ZPL 2.1", "ZPL"],
    "MIT": ["MIT", "MIT license", "MIT License", "MIT/Expat"],
    "HPND": ["HPND"],
    "Beerware": ["Custom BSD Beerware"],
    "BSD-2-Clause": ["BSD 2-Clause License"],
    "BSD-3-Clause": [
        "BSD-3-Clause",
        "3 Clause BSD",
        "New BSD",
        "BSD 3-Clause License",
        "3-Clause BSD License",
        "3 Clause BSD",
        "BSD3",
        "BSD License",
        "BSD",
    ],
    "LGPL-2.0-only": ["LGPLv2"],
    "LGPL-2.1-only": ["LGPL-2.1", "LGPLv2 and GPLv2+"],
    "LGPL-2.1-or-later": ["LGPL-2.1+", "LGPLv2+"],
    "LGPL-3.0-only": ["LGPL3"],
    "LGPL-3.0-or-later": ["LGPLv3+"],
    "GPL-1.0-only": ["GPL"],
    "GPL-2.0-only": ["GPL version 2", "GNU GPLv2", "GPLv2"],
    "GPL-2.0-or-later": [
        "GPLv2-or-later with a special exception which allows to use PyInstaller to build and distribute non-free programs (including commercial ones)",
        "GNU GPLv2 or any later version",
        "GPLv2+",
        "GNU GPL",
    ],
    "GPL-3.0-or-later": ["GPL-3+", "GPLv3+", "GNU/GPL version 3"],
    "GPL-3.0-only": [
        "GPL-3.0",
        "GNU General Public License v3.0",
        "GNUv3",
        "GNU GPL v3.0",
        "GPL-3",
        "GPLv3",
    ],
    "PSF-2.0": ["PSF", "PSF license"],
    "PostgreSQL": ["PostgreSQL"],
    "ISC": ["ISC License"],
    "MPL-2.0": ["MPL"],
    "Zlib": ["Zlib"],
    "Other": [
        "Other",
        "Public domain",
        "OSI Approved",
        "Copyright (C) 2008-2019 by Vinay Sajip. All Rights Reserved. See LICENSE.txt for license.",
        "BSD-derived",
        "BSD-derived (http://www.repoze.org/LICENSE.txt)",
    ],
    "EFL-2.0": ["Eiffel Forum License, version 2"],
    "BSD-3-Clause OR Apache-2.0": ["BSD or Apache License, Version 2.0"],
    "MPL-2.0 OR MIT": ["MPLv2.0, MIT Licences"],
    "Unknown": [""],
}

PYTHON_PACKAGE_NAME_POLICY = "package_name"
PYTHON_LICENSE_TYPE_POLICY = "license_type"
