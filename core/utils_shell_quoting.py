def shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"

def psq(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"
