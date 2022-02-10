import sys
from tarfile import open as topen
from tarfile import extractall
from tarfile import close as tclose


# standard
tar = topen(sys.argv[1], "r")
tar.extractall()
tar.tclose()

