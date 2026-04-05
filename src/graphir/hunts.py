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
            LIMIT 30
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
            LIMIT 20
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
            LIMIT 20
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
            WITH e,
                 CASE
                   WHEN toLower(toString(e.service_path)) CONTAINS 'system32\\\\drivers' THEN 'kernel_driver'
                   WHEN toLower(toString(e.service_path)) CONTAINS 'svchost' THEN 'svchost_hosted'
                   WHEN toLower(toString(e.service_path)) CONTAINS 'system32' THEN 'system_service'
                   WHEN toLower(toString(e.service_path)) CONTAINS 'program files' THEN 'program_files'
                   WHEN toLower(toString(e.service_path)) CONTAINS '\\\\temp\\\\'
                     OR toLower(toString(e.service_path)) CONTAINS '\\\\appdata\\\\' THEN 'SUSPICIOUS'
                   ELSE 'other'
                 END AS category
            RETURN category, count(*) AS service_count,
                   collect(DISTINCT e.service_name)[0..5] AS examples,
                   min(e.timestamp) AS earliest, max(e.timestamp) AS latest
            ORDER BY category
        """,
        "tactic": "Persistence",
        "technique": "T1543.003",
    },
    "rare_processes": {
        "description": "Rarely executed processes — anomaly detection by frequency (excludes PID stubs)",
        "query": """
            MATCH (p:Process)
            WHERE NOT p.name STARTS WITH '0x'
            WITH p.name AS proc_name, count(*) AS exec_count
            WHERE exec_count <= 2
            RETURN proc_name, exec_count
            ORDER BY exec_count ASC
            LIMIT 100
        """,
        "summarize_query": """
            MATCH (p:Process)
            WHERE NOT p.name STARTS WITH '0x'
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
            WHERE toLower(p.cmdline) CONTAINS '-enc ' OR toLower(p.cmdline) CONTAINS '-encodedcommand'
               OR toLower(p.cmdline) CONTAINS 'frombase64' OR toLower(p.cmdline) CONTAINS 'hidden'
               OR toLower(p.cmdline) CONTAINS '-w hidden' OR toLower(p.cmdline) CONTAINS '-nop'
            RETURN p.name AS process, p.cmdline AS cmdline,
                   p.user AS user, p.timestamp AS ts
            ORDER BY p.timestamp
            LIMIT 50
        """,
        "summarize_query": """
            MATCH (p:Process)
            WHERE toLower(p.cmdline) CONTAINS '-enc ' OR toLower(p.cmdline) CONTAINS '-encodedcommand'
               OR toLower(p.cmdline) CONTAINS 'frombase64' OR toLower(p.cmdline) CONTAINS 'hidden'
               OR toLower(p.cmdline) CONTAINS '-w hidden' OR toLower(p.cmdline) CONTAINS '-nop'
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
            LIMIT 20
        """,
        "tactic": "Discovery",
        "technique": "T1082",
    },

    # --- Additional hunts (8 more → 15 total) ---

    "scheduled_tasks": {
        "description": "Scheduled task creation or modification events",
        "query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id IN [4698, 4702, 106]
            RETURN e.event_id AS event_id, e.message AS message,
                   h.hostname AS host, e.timestamp AS ts
            ORDER BY e.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id IN [4698, 4702, 106]
            WITH e.event_id AS event_id, count(*) AS cnt,
                 h.hostname AS host,
                 min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
            RETURN event_id, cnt, host, first_seen, last_seen
            ORDER BY cnt DESC
            LIMIT 20
        """,
        "tactic": "Persistence",
        "technique": "T1053",
    },
    "registry_persistence": {
        "description": "Registry modifications to known persistence locations (Run, RunOnce, Services, Winlogon)",
        "query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id = 'registry_mod'
              AND e.is_persistence = true
            RETURN e.key_path AS key, e.values AS values,
                   h.hostname AS host, e.timestamp AS ts
            ORDER BY e.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id = 'registry_mod'
              AND e.is_persistence = true
            WITH e.key_path AS key, count(*) AS modifications,
                 h.hostname AS host,
                 min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
            RETURN key, modifications, host, first_seen, last_seen
            ORDER BY modifications DESC
            LIMIT 20
        """,
        "tactic": "Persistence",
        "technique": "T1547.001",
    },
    "log_clearing": {
        "description": "Security/System log clearing events — potential defense evasion",
        "query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id IN [1102, 104, 1100]
            RETURN e.event_id AS event_id, e.source AS source,
                   e.message AS message, h.hostname AS host, e.timestamp AS ts
            ORDER BY e.timestamp
            LIMIT 50
        """,
        "summarize_query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id IN [1102, 104, 1100]
            WITH e.event_id AS event_id, e.source AS source, count(*) AS cnt,
                 h.hostname AS host,
                 min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
            RETURN event_id, source, cnt, host, first_seen, last_seen
            ORDER BY first_seen
            LIMIT 20
        """,
        "tactic": "Defense Evasion",
        "technique": "T1070.001",
    },
    "dll_sideloading": {
        "description": "Processes loading DLLs from non-standard locations — potential sideloading",
        "query": """
            MATCH (p:Process)-[:ACCESSED]->(f:File)
            WHERE f.name ENDS WITH '.dll'
              AND NOT f.path STARTS WITH 'C:\\Windows\\'
              AND NOT f.path STARTS WITH 'C:\\Program Files'
            RETURN p.name AS process, f.path AS dll_path,
                   p.timestamp AS ts
            ORDER BY p.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (p:Process)-[:ACCESSED]->(f:File)
            WHERE toLower(f.name) ENDS WITH '.dll'
              AND NOT toLower(f.path) STARTS WITH 'c:\\windows\\'
              AND NOT toLower(f.path) STARTS WITH 'c:\\program files'
            WITH f.path AS dll_path, count(*) AS load_count,
                 collect(DISTINCT p.name)[0..3] AS loaded_by,
                 min(p.timestamp) AS first_seen, max(p.timestamp) AS last_seen
            RETURN dll_path, load_count, loaded_by, first_seen, last_seen
            ORDER BY load_count DESC
            LIMIT 20
        """,
        "tactic": "Defense Evasion",
        "technique": "T1574.002",
    },
    "suspicious_file_creation": {
        "description": "Files created in temp, AppData, or user-writable directories",
        "query": """
            MATCH (h:Host)-[:MODIFIED]->(f:File)
            WHERE toLower(f.path) CONTAINS '\\temp\\' OR toLower(f.path) CONTAINS '\\appdata\\'
               OR toLower(f.path) CONTAINS '\\downloads\\' OR toLower(f.path) CONTAINS '\\public\\'
            RETURN f.name AS file_name, f.path AS path,
                   h.hostname AS host, f.timestamp AS ts
            ORDER BY f.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (h:Host)-[:MODIFIED]->(f:File)
            WHERE toLower(f.path) CONTAINS '\\\\temp\\\\' OR toLower(f.path) CONTAINS '\\\\appdata\\\\'
               OR toLower(f.path) CONTAINS '\\\\downloads\\\\' OR toLower(f.path) CONTAINS '\\\\public\\\\'
            WITH f.extension AS ext, count(*) AS file_count,
                 collect(DISTINCT f.name)[0..5] AS sample_files,
                 h.hostname AS host,
                 min(f.timestamp) AS first_seen, max(f.timestamp) AS last_seen
            RETURN ext, file_count, sample_files, host, first_seen, last_seen
            ORDER BY file_count DESC
            LIMIT 20
        """,
        "tactic": "Execution",
        "technique": "T1204",
    },
    "failed_logons": {
        "description": "Failed logon attempts (4625) — potential brute force or credential stuffing",
        "query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id = 4625
            RETURN e.message AS message, h.hostname AS host, e.timestamp AS ts
            ORDER BY e.timestamp
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id = 4625
            WITH h.hostname AS host, count(*) AS failures,
                 min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
            RETURN host, failures, first_seen, last_seen,
                   duration.between(first_seen, last_seen) AS window
            ORDER BY failures DESC
            LIMIT 20
        """,
        "tactic": "Credential Access",
        "technique": "T1110",
    },
    "privilege_escalation": {
        "description": "Special privilege assignment (4672) — tracks who gets elevated privileges",
        "query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id = 4672
            RETURN e.message AS message, h.hostname AS host, e.timestamp AS ts
            ORDER BY e.timestamp DESC
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE e.event_id = 4672
            WITH h.hostname AS host, count(*) AS assignments,
                 min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
            RETURN host, assignments, first_seen, last_seen
            ORDER BY assignments DESC
            LIMIT 20
        """,
        "tactic": "Privilege Escalation",
        "technique": "T1078",
    },
    "unusual_executables": {
        "description": "Executables with evidence from non-standard paths — amcache/shimcache/prefetch outside Windows/ProgramFiles",
        "query": """
            MATCH (h:Host)-[:HAS_EXECUTABLE]->(x:Executable)
            WHERE x.path IS NOT NULL
              AND NOT toLower(x.path) STARTS WITH 'c:\\windows'
              AND NOT toLower(x.path) STARTS WITH 'c:\\program files'
              AND NOT toLower(x.path) STARTS WITH '\\systemroot'
              AND NOT x.path STARTS WITH '0'
            RETURN x.name AS name, x.path AS path, x.sha1 AS hash,
                   x.run_count AS runs, h.hostname AS host
            ORDER BY x.path
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (h:Host)-[:HAS_EXECUTABLE]->(x:Executable)
            WHERE x.path IS NOT NULL
              AND NOT toLower(x.path) STARTS WITH 'c:\\\\windows'
              AND NOT toLower(x.path) STARTS WITH 'c:\\\\program files'
              AND NOT toLower(x.path) STARTS WITH '\\\\systemroot'
              AND NOT x.path STARTS WITH '0'
            WITH CASE
                   WHEN toLower(x.path) CONTAINS '\\\\temp\\\\' THEN 'SUSPICIOUS_temp'
                   WHEN toLower(x.path) CONTAINS '\\\\appdata\\\\' THEN 'user_appdata'
                   WHEN toLower(x.path) CONTAINS '\\\\users\\\\' THEN 'user_profile'
                   WHEN toLower(x.path) CONTAINS '\\\\device\\\\' THEN 'external_device'
                   ELSE 'other'
                 END AS location,
                 count(*) AS exe_count,
                 collect(x.name)[0..5] AS samples,
                 h.hostname AS host
            RETURN location, exe_count, samples, host
            ORDER BY location
            LIMIT 20
        """,
        "tactic": "Execution",
        "technique": "T1059",
    },
    "timestomping_indicators": {
        "description": "Files where MACB timestamps are inconsistent — potential timestomping or anti-forensics",
        "query": """
            MATCH (f:File)
            WHERE f.born_time IS NOT NULL AND f.modified_time IS NOT NULL
              AND f.modified_time < f.born_time
            RETURN f.name AS file, f.path AS path,
                   f.born_time AS born, f.modified_time AS modified,
                   duration.between(f.modified_time, f.born_time) AS delta
            ORDER BY f.born_time
            LIMIT 100
        """,
        "summarize_query": """
            MATCH (f:File)
            WHERE f.born_time IS NOT NULL AND f.modified_time IS NOT NULL
              AND f.modified_time < f.born_time
            RETURN f.name AS file, f.path AS path,
                   f.born_time AS born, f.modified_time AS modified,
                   duration.between(f.modified_time, f.born_time) AS delta
            ORDER BY f.born_time
            LIMIT 20
        """,
        "tactic": "Defense Evasion",
        "technique": "T1070.006",
    },
    "suspicious_filesystem_artifacts": {
        "description": "Executable/DLL/script files in suspicious filesystem locations (temp, debug, admin$, NETLOGON, Common Files)",
        "query": """
            MATCH (h:Host)-[:MODIFIED]->(f:File)
            WHERE f.name IS NOT NULL
              AND (toLower(f.path) CONTAINS '\\temp\\' OR toLower(f.path) CONTAINS '\\debug\\'
                   OR toLower(f.path) CONTAINS '\\admin$\\' OR toLower(f.path) CONTAINS '\\netlogon\\'
                   OR toLower(f.path) CONTAINS '\\common files\\' OR toLower(f.path) CONTAINS '\\startup\\'
                   OR toLower(f.path) CONTAINS '\\tasks\\' OR toLower(f.path) CONTAINS '\\recycle')
              AND (toLower(f.name) ENDS WITH '.exe' OR toLower(f.name) ENDS WITH '.dll'
                   OR toLower(f.name) ENDS WITH '.bat' OR toLower(f.name) ENDS WITH '.cmd'
                   OR toLower(f.name) ENDS WITH '.ps1' OR toLower(f.name) ENDS WITH '.vbs')
            RETURN f.name AS file, f.path AS path, h.hostname AS host,
                   f.born_time AS born, f.modified_time AS modified,
                   f.accessed_time AS accessed
            ORDER BY f.born_time
            LIMIT 200
        """,
        "summarize_query": """
            MATCH (h:Host)-[:MODIFIED]->(f:File)
            WHERE f.name IS NOT NULL
              AND (toLower(f.path) CONTAINS '\\\\temp\\\\' OR toLower(f.path) CONTAINS '\\\\debug\\\\'
                   OR toLower(f.path) CONTAINS '\\\\admin$\\\\' OR toLower(f.path) CONTAINS '\\\\netlogon\\\\'
                   OR toLower(f.path) CONTAINS '\\\\common files\\\\' OR toLower(f.path) CONTAINS '\\\\startup\\\\'
                   OR toLower(f.path) CONTAINS '\\\\tasks\\\\' OR toLower(f.path) CONTAINS '\\\\recycle')
              AND (toLower(f.name) ENDS WITH '.exe' OR toLower(f.name) ENDS WITH '.dll'
                   OR toLower(f.name) ENDS WITH '.bat' OR toLower(f.name) ENDS WITH '.cmd'
                   OR toLower(f.name) ENDS WITH '.ps1' OR toLower(f.name) ENDS WITH '.vbs')
            WITH CASE
                   WHEN toLower(f.path) CONTAINS '\\\\debug\\\\' THEN 'debug_dir'
                   WHEN toLower(f.path) CONTAINS '\\\\admin$\\\\' THEN 'admin_share'
                   WHEN toLower(f.path) CONTAINS '\\\\netlogon\\\\' THEN 'netlogon_share'
                   WHEN toLower(f.path) CONTAINS '\\\\common files\\\\' THEN 'common_files'
                   WHEN toLower(f.path) CONTAINS '\\\\temp\\\\' THEN 'temp_dir'
                   WHEN toLower(f.path) CONTAINS '\\\\startup\\\\' THEN 'startup'
                   WHEN toLower(f.path) CONTAINS '\\\\tasks\\\\' THEN 'scheduled_tasks'
                   ELSE 'other'
                 END AS location,
                 count(*) AS file_count,
                 collect(DISTINCT f.name)[0..5] AS samples,
                 h.hostname AS host
            RETURN location, file_count, samples, host
            ORDER BY location
            LIMIT 20
        """,
        "tactic": "Persistence",
        "technique": "T1036",
    },
}
