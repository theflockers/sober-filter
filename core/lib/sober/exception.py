class NonRootException(Exception): pass
class VirusFoundException(Exception): pass
class SpamFoundKillException(Exception): pass
class SpamFoundTagException(Exception): pass
class SpamFoundTag2Exception(Exception): pass
class HamFound(Exception): pass
class ErrorException(Exception): pass
class FatalException(Exception): pass
class SenderEmailFoundException(Exception): pass
class SenderDomainFoundException(Exception): pass
class BlockedExtensionFoundException(Exception): pass
class MessageContentFoundException(Exception): pass
class NoQueueException(Exception): pass
class NoRedisConnection(Exception): pass
class MessageTooLargeException(Exception): pass
class MessageTooSmallException(Exception): pass