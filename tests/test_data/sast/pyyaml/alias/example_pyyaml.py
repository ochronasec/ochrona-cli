import yaml as yml

document = """
  a: 1
  b:
    c: 3
    d: 4
"""

data = yml.load(document)