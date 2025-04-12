from enum import Enum


class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"


class Mode(Enum):
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"
