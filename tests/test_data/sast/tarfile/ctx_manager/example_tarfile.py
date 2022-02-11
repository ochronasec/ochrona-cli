import sys
import tarfile

# with context manager
with tarfile.open(sys.argv[1], "r") as tar:
    tar.extractall()