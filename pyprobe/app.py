import sys
import yaml
import django

print(yaml.load(sys.argv[1], Loader=yaml.Loader))
