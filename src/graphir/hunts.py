"""Hunt pattern definitions for find_evil.

Each hunt has:
  - description: what it looks for
  - query: raw Cypher (full results, for detailed analysis)
  - summarize_query: aggregated Cypher (grouped results with counts + samples)
  - tactic: MITRE ATT&CK tactic
  - technique: MITRE ATT&CK technique ID

Add new hunts here. server.py loads them automatically.
"""

HUNT_QUERIES = {
    "suspicious_process_chain": {
        "description": "Suspicious process ancestry chains (variable-length, includes WMI)",
        "query": """
            MATCH (ancestor:Process)-[:SPAWNED*1..3]->(child:Process)
            WHERE ancestor.name IN ['explorer.exe', 'svchost.exe', 'services.exe',
                                     'winlogon.exe', 'lsass.exe', 'taskhost.exe',
                                     'wmiprvse.exe', 'wsmprovhost.exe', 'winrshost.exe']
              AND child.name IN ['cmd.exe', 'powershell.exe', 'wscript.exe',
                                  'cscript.exe', 'mshta.exe', 'regsvr32.exe',
                                  'rundll32.exe', 'certutil.exe', 'bitsadmin.exe',
                                  'msbuild.exe', 'installutil.exe']
            RETURN ancestor.name AS ancestor, child.name AS child,
                   child.cmdline AS cmdline, child.timestamp AS ts
            ORDER BY child.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (ancestor:Process)-[:SPAWNED*1..3]->(child:Process)
            WHERE ancestor.name IN ['explorer.exe', 'svchost.exe', 'services.exe',
                                     'winlogon.exe', 'lsass.exe', 'taskhost.exe',
                                     'wmiprvse.exe', 'wsmprovhost.exe', 'winrshost.exe']
              AND child.name IN ['cmd.exe', 'powershell.exe', 'wscript.exe',
                                  'cscript.exe', 'mshta.exe', 'regsvr32.exe',
                                  'rundll32.exe', 'certutil.exe', 'bitsadmin.exe',
                                  'msbuild.exe', 'installutil.exe']
            WITH ancestor.name AS ancestor, child.name AS child, count(*) AS occurrences,
                 collect(DISTINCT child.cmdline)[0..3] AS sample_cmdlines,
                 min(child.timestamp) AS first_seen, max(child.timestamp) AS last_seen
            RETURN ancestor, child, occurrences, sample_cmdlines, first_seen, last_seen
            ORDER BY occurrences DESC
        """,
        "tactic": "Execution",
        "technique": "T1059",
    },
    "lateral_movement_logons": {
        "description": "Network logons (Type 3/10) across hosts — potential lateral movement",
        "query": """
            MATCH (u:User)-[r:LOGGED_ON]->(dst:Host)
            WHERE r.logon_type IN [3, 9, 10]
            RETURN u.name AS user, dst.hostname AS destination,
                   r.logon_type AS logon_type, r.src_ip AS src_ip,
                   r.timestamp AS ts
            ORDER BY r.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (u:User)-[r:LOGGED_ON]->(dst:Host)
            WHERE r.logon_type IN [3, 9, 10]
            WITH u.name AS user, dst.hostname AS host,
                 count(*) AS sessions,
                 collect(DISTINCT r.src_ip) AS source_ips,
                 collect(DISTINCT r.logon_type) AS logon_types,
                 min(r.timestamp) AS first_seen, max(r.timestamp) AS last_seen
            RETURN user, host, sessions, source_ips, logon_types, first_seen, last_seen
            ORDER BY sessions DESC
        """,
        "tactic": "Lateral Movement",
        "technique": "T1021",
    },
    "lsass_access": {
        "description": "Non-system processes accessing LSASS — potential credential dumping",
        "query": """
            MATCH (p:Process)-[:ACCESSED]->(target:Process {name: 'lsass.exe'})
            WHERE NOT p.name IN ['svchost.exe', 'csrss.exe', 'services.exe', 'wininit.exe']
            RETURN p.name AS accessor, p.cmdline AS cmdline,
                   p.pid AS pid, p.timestamp AS ts
            ORDER BY p.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (p:Process)-[:ACCESSED]->(target:Process {name: 'lsass.exe'})
            WHERE NOT p.name IN ['svchost.exe', 'csrss.exe', 'services.exe', 'wininit.exe']
            WITH p.name AS accessor, count(*) AS access_count,
                 collect(DISTINCT p.cmdline)[0..3] AS sample_cmdlines,
                 min(p.timestamp) AS first_seen, max(p.timestamp) AS last_seen
            RETURN accessor, access_count, sample_cmdlines, first_seen, last_seen
            ORDER BY access_count DESC
        """,
        "tactic": "Credential Access",
        "technique": "T1003.001",
    },
    "service_installation": {
        "description": "Service installations — potential persistence or lateral movement",
        "query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id = 7045 OR e.event_id = 'registry_service'
            RETURN e.service_name AS service, e.service_path AS path,
                   h.hostname AS host, e.timestamp AS ts
            ORDER BY e.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE (e.event_id = 7045 OR e.event_id = 'registry_service')
              AND e.service_name IS NOT NULL AND e.service_name <> ''
            WITH e.service_name AS service, e.service_path AS path,
                 h.hostname AS host, count(*) AS install_count,
                 min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
            RETURN service, path, host, install_count, first_seen, last_seen
            ORDER BY first_seen
        """,
        "tactic": "Persistence",
        "technique": "T1543.003",
    },
    "rare_processes": {
        "description": "Rarely executed processes — anomaly detection by frequency",
        "query": """
            MATCH (p:Process)
            WITH p.name AS proc_name, count(*) AS exec_count
            WHERE exec_count <= 2
            RETURN proc_name, exec_count
            ORDER BY exec_count ASC
            LIMIT 100
        """,
        "summarize_query": """
            MATCH (p:Process)
            WITH p.name AS proc_name, count(*) AS exec_count,
                 collect(DISTINCT p.cmdline)[0..2] AS sample_cmdlines,
                 collect(DISTINCT p.user)[0..2] AS users
            WHERE exec_count <= 2
            RETURN proc_name, exec_count, sample_cmdlines, users
            ORDER BY exec_count ASC
            LIMIT 50
        """,
        "tactic": "Discovery",
        "technique": "T1057",
    },
    "encoded_commands": {
        "description": "Encoded/obfuscated command line arguments",
        "query": """
            MATCH (p:Process)
            WHERE p.cmdline CONTAINS '-enc ' OR p.cmdline CONTAINS '-EncodedCommand'
               OR p.cmdline CONTAINS 'frombase64' OR p.cmdline CONTAINS 'hidden'
               OR p.cmdline CONTAINS '-w hidden' OR p.cmdline CONTAINS '-nop'
            RETURN p.name AS process, p.cmdline AS cmdline,
                   p.user AS user, p.timestamp AS ts
            ORDER BY p.timestamp
            LIMIT 50
        """,
        "summarize_query": """
            MATCH (p:Process)
            WHERE p.cmdline CONTAINS '-enc ' OR p.cmdline CONTAINS '-EncodedCommand'
               OR p.cmdline CONTAINS 'frombase64' OR p.cmdline CONTAINS 'hidden'
               OR p.cmdline CONTAINS '-w hidden' OR p.cmdline CONTAINS '-nop'
            RETURN p.name AS process, p.cmdline AS cmdline,
                   p.user AS user, p.timestamp AS ts
            ORDER BY p.timestamp
            LIMIT 50
        """,
        "tactic": "Defense Evasion",
        "technique": "T1027",
    },
    "discovery_commands": {
        "description": "Reconnaissance / discovery commands",
        "query": """
            MATCH (p:Process)
            WHERE p.name IN ['whoami.exe', 'ipconfig.exe', 'net.exe', 'net1.exe',
                              'nltest.exe', 'systeminfo.exe', 'tasklist.exe',
                              'nslookup.exe', 'quser.exe', 'arp.exe',
                              'route.exe', 'findstr.exe', 'netstat.exe']
            RETURN p.name AS tool, p.cmdline AS cmdline, p.user AS user,
                   p.timestamp AS ts
            ORDER BY p.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (p:Process)
            WHERE p.name IN ['whoami.exe', 'ipconfig.exe', 'net.exe', 'net1.exe',
                              'nltest.exe', 'systeminfo.exe', 'tasklist.exe',
                              'nslookup.exe', 'quser.exe', 'arp.exe',
                              'route.exe', 'findstr.exe', 'netstat.exe']
            WITH p.name AS tool, count(*) AS exec_count,
                 collect(DISTINCT p.cmdline)[0..3] AS sample_cmdlines,
                 collect(DISTINCT p.user)[0..2] AS users,
                 min(p.timestamp) AS first_seen, max(p.timestamp) AS last_seen
            RETURN tool, exec_count, sample_cmdlines, users, first_seen, last_seen
            ORDER BY first_seen
        """,
        "tactic": "Discovery",
        "technique": "T1082",
    },
}
