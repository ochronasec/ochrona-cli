PIPFILE_LOCK = "Pipfile.lock"
POETRY_LOCK = "poetry.lock"
SETUP_PY = "setup.py"

SUPPORTED_DEPENDENCY_FILE_PATTERNS = {
    "requirements_txt": "**/*requirements*.txt",
    "pipfile_lock": "**/*Pipfile.lock",
    "poetry_lock": "**/*poetry.lock",
    "setup_py": "**/*setup.py",
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
]

INVALID_SPECIFIERS = {"<", ">", "!", "~"}
EQUALS_SPECIFIER = "=="
