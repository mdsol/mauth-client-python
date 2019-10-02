import os

def load_key(keytype="pub"):
    """
    Load the sample keys
    :param keytype: type of key to load
    :return: key content
    :rtype: str
    """
    assert keytype in ("pub", "rsapub", "priv")
    content = ""
    with open(os.path.join(os.path.dirname(__file__),
                           "keys",
                           "fake_mauth_authenticator.%s.key" % keytype), "r") as key:
        content = key.read()
    return content
