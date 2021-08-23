from collections import namedtuple

TokenInstance = namedtuple("TokenInstance", ["id", "value"])

Definition = namedtuple("Definition", ["field", "operator", "value"])
