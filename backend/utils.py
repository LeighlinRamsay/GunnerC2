def _psq(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"

def _shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"
