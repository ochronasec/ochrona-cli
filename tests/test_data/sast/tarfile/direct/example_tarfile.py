import sys
import tarfile

# standard
tar = tarfile.open(sys.argv[1], "r")
tar.extractall()
tar.close()

