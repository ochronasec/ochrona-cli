import sys
import tarfile as tar

# standard
t = tar.open(sys.argv[1], "r")
t.extractall()
t.close()

# with context manager
with tar.open(sys.argv[1], "r") as t:
    t.extractall()