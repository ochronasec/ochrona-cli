from yaml import load

document = """
  a: 1
  b:
    c: 3
    d: 4
"""

data = load(document)