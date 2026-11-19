import yaml
import requests


def load(text):
    return yaml.load(text, Loader=yaml.Loader)


if __name__ == "__main__":
    print(load("a: 1"), requests.__version__)
