"""Evidence correlation across sessions, hosts and time.

STATUS: NOT IMPLEMENTED (planned for M5).

Will correlate observations that are individually weak -- a STARTTLS offer
that is never taken up, a host that negotiates strong TLS on one port and
plaintext on another -- into explainable findings, each retaining the packet
references of every contributing observation.
"""
