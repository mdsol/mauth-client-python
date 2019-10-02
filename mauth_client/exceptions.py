class InauthenticError(Exception):
    """
    Used to indicate that an object was expected to be validly signed but its signature does not
    match its contents, and so is inauthentic.
    """


class UnableToAuthenticateError(Exception):
    """
    The response from the MAuth service encountered when attempting to retrieve mauth
    """


class UnableToSignError(Exception):
    """
    Required information for signing was missing
    """


class MAuthNotPresent(Exception):
    """
    No mAuth signature present
    """


class MissingV2Error(Exception):
    """
    V2 is required but not present and v1 is present
    """
