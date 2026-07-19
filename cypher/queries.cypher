// ═══════════════════════════════════════════════════════════════════════════
//  BloodHound CE — Custom Cypher hunting pack
//  Paste into the BloodHound CE "Cypher" search box or the Neo4j browser.
//  Ships alongside BloodHound-Parser (also emitted by `-f cypher`).
// ═══════════════════════════════════════════════════════════════════════════

// ── Kerberos ────────────────────────────────────────────────────────────────
// Kerberoastable users (enabled, has SPN)
MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u.name ORDER BY u.name;

// ASREPRoastable users (no Kerberos pre-auth)
MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u.name;

// Kerberoastable users that are also privileged (high-value roast targets)
MATCH (u:User) WHERE u.hasspn = true AND u.admincount = true RETURN u.name;

// ── Delegation ──────────────────────────────────────────────────────────────
// Unconstrained delegation (excluding Domain Controllers)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS 'DC' RETURN c.name;

// Constrained delegation targets
MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate;

// RBCD — who can act on behalf of a computer
MATCH p=(n)-[:AllowedToAct]->(c:Computer) RETURN p;

// ── Privilege escalation paths ──────────────────────────────────────────────
// Shortest paths to Domain Admins from any OWNED principal
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group))
WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p;

// Shortest paths to Domain Admins from Domain Users (self-service escalation)
MATCH p=shortestPath((g1:Group)-[*1..]->(g2:Group))
WHERE g1.name STARTS WITH 'DOMAIN USERS@' AND g2.name STARTS WITH 'DOMAIN ADMINS@'
RETURN p;

// ── DCSync ──────────────────────────────────────────────────────────────────
// Principals able to DCSync (GetChanges + GetChangesAll on the domain)
MATCH (n)-[:GetChanges]->(d:Domain), (n)-[:GetChangesAll]->(d)
RETURN n.name, d.name;

// ── ACL abuse toward Tier-0 ────────────────────────────────────────────────
MATCH p=(n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AddKeyCredentialLink|ForceChangePassword]->(t)
WHERE t.system_tags CONTAINS 'admin_tier_0' RETURN p LIMIT 200;

// Shadow Credentials — AddKeyCredentialLink edges
MATCH p=(n)-[:AddKeyCredentialLink]->(t) RETURN p;

// ── LAPS / local admin ──────────────────────────────────────────────────────
// Non-privileged principals that can read a LAPS password
MATCH p=(u:User)-[:ReadLAPSPassword]->(c:Computer) RETURN p;

// ── Hygiene ─────────────────────────────────────────────────────────────────
// Accounts that may have an empty password
MATCH (u:User {passwordnotreqd:true, enabled:true}) RETURN u.name;

// End-of-life operating systems
MATCH (c:Computer)
WHERE c.operatingsystem CONTAINS '2008' OR c.operatingsystem CONTAINS '2003'
   OR c.operatingsystem CONTAINS 'Windows 7' OR c.operatingsystem CONTAINS 'XP'
RETURN c.name, c.operatingsystem;
