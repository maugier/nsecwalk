# nsecwalk

Early versions of DNSSEC defined the NSEC record type, that allows for proof of non-existence
of a DNS record even when the authoritative server doesn't hold the zone signing key. An NSEC record
asserts that there exists no entries between the requested name and a given next name.

Unfortunately, this discloses the next name in the domain, allowing an attacker to dump all names from
a zone. This is what this program does.

Zones should use the newer NSEC3 record type for proof of non-existence. NSEC3 hides the names behind a hash. 
