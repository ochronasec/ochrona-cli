import yaml

document = """
  a: 1
  b:
    c: 3
    d: 4
"""

data = yaml.load(document, Loader=yaml.Loader)