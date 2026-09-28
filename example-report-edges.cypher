// BloodHound edges derived from Group Policy by group3rpy.
// Generated: 2026-09-28T11:51:44+00:00
// Domain: contoso.local
// Relationships: 28
//
// READ THIS BEFORE RUNNING.
// * Every statement MATCHes both endpoints and MERGEs only the
//   relationship, so no node is ever created: an endpoint BloodHound
//   never collected simply matches nothing.
// * MERGE, never CREATE, so re-running this file changes nothing.
// * A relationship we create is stamped r.source = 'group3rpy'.
//   A relationship that already existed is NOT stamped with that
//   (it only gets r.group3rpySeen), so the rollback below cannot
//   delete an edge BloodHound collected itself.
// * Edges with uncertain = true come from a GPO whose real scope is
//   narrower than its link scope; see r.reason.
// * A principal the GPO named only as NETBIOS\SAM is matched on name,
//   samaccountname or SAM@..., because BloodHound stores
//   SAM@DOMAIN.FQDN. In a multi-domain forest that can match more
//   than one object, so check those statements before running.
//
// ROLLBACK -- uncomment and run these two statements to undo:
// MATCH ()-[r]->() WHERE r.source = 'group3rpy' DELETE r;
// MATCH ()-[r]->() WHERE r.group3rpySeen IS NOT NULL REMOVE r.group3rpySeen, r.group3rpyGpo;

// AdminTo: FAILED SID RESOLUTION -> WS-ENG-01.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-1134'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-01,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// AdminTo: FAILED SID RESOLUTION -> WS-ENG-02.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-1134'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-02,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// AdminTo: FAILED SID RESOLUTION -> WS-ENG-03.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-1134'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-03,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// AdminTo: FAILED SID RESOLUTION -> WS-ENG-04.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-1134'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-04,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// AdminTo: DOMAIN USERS -> WS-ENG-01.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-513'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-01,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// AdminTo: DOMAIN USERS -> WS-ENG-02.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-513'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-02,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// AdminTo: DOMAIN USERS -> WS-ENG-03.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-513'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-03,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// AdminTo: DOMAIN USERS -> WS-ENG-04.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-513'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WS-ENG-04,OU=ENGINEERING,OU=WORKSTATIONS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:AdminTo]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}', r.gpoDisplayName = 'Local Administrator Provisioning', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}\\Machine\\Preferences\\Groups\\Groups.xml', r.localGroup = 'Administrators', r.localGroupSid = 'S-1-5-32-544'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{C48E1A77-31D9-4B6C-BF20-7A19D3E4C003}';

// GPOGrantsPrivilege: EVERYONE -> DC01.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-1-0'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC01,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeDebugPrivilege', r.adminEquivalent = true, r.msDescription = 'Debug programs'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: EVERYONE -> DC02.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-1-0'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC02,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeDebugPrivilege', r.adminEquivalent = true, r.msDescription = 'Debug programs'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: FAILED SID RESOLUTION -> DC01.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-1134'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC01,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeTakeOwnershipPrivilege', r.adminEquivalent = true, r.msDescription = 'Take ownership of files or other objects'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: FAILED SID RESOLUTION -> DC02.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-1134'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC02,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeTakeOwnershipPrivilege', r.adminEquivalent = true, r.msDescription = 'Take ownership of files or other objects'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: DOMAIN USERS -> DC01.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-513'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC01,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeRemoteInteractiveLogonRight', r.grantsRemoteAccess = true, r.msDescription = 'Allow log on through Remote Desktop Services'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: DOMAIN USERS -> DC02.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-21-1004336348-1177238915-682003330-513'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC02,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeRemoteInteractiveLogonRight', r.grantsRemoteAccess = true, r.msDescription = 'Allow log on through Remote Desktop Services'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: ADMINISTRATORS -> DC01.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-32-544'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC01,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeTakeOwnershipPrivilege | SeBackupPrivilege | SeRestorePrivilege | SeRemoteInteractiveLogonRight | SeLoadDriverPrivilege', r.adminEquivalent = true, r.msDescription = 'Take ownership of files or other objects | Back up files and directories | Restore files and directories | Allow log on through Remote Desktop Services | Load and unload device drivers', r.grantsRemoteAccess = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: ADMINISTRATORS -> DC02.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-32-544'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC02,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeTakeOwnershipPrivilege | SeBackupPrivilege | SeRestorePrivilege | SeRemoteInteractiveLogonRight | SeLoadDriverPrivilege', r.adminEquivalent = true, r.msDescription = 'Take ownership of files or other objects | Back up files and directories | Restore files and directories | Allow log on through Remote Desktop Services | Load and unload device drivers', r.grantsRemoteAccess = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: BACKUP OPERATORS -> DC01.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-32-551'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC01,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeBackupPrivilege | SeRestorePrivilege', r.adminEquivalent = true, r.msDescription = 'Back up files and directories | Restore files and directories'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOGrantsPrivilege: BACKUP OPERATORS -> DC02.CONTOSO.LOCAL
MATCH (s) WHERE s.objectid = 'S-1-5-32-551'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=DC02,OU=DOMAIN CONTROLLERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOGrantsPrivilege]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}', r.gpoDisplayName = 'Default Domain Controllers Policy', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', r.privilege = 'SeBackupPrivilege | SeRestorePrivilege', r.adminEquivalent = true, r.msDescription = 'Back up files and directories | Restore files and directories'
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{6AC1786C-016F-11D2-945F-00C04FB984F9}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_BACKUP -> SQL-01.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_BACKUP' OR toUpper(s.samaccountname) = 'SVC_BACKUP' OR toUpper(s.name) STARTS WITH 'SVC_BACKUP@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=SQL-01,OU=SQL,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Nightly Backup', r.logonType = 'password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_BACKUP -> SQL-02.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_BACKUP' OR toUpper(s.samaccountname) = 'SVC_BACKUP' OR toUpper(s.name) STARTS WITH 'SVC_BACKUP@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=SQL-02,OU=SQL,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Nightly Backup', r.logonType = 'password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_BACKUP -> WEB-01.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_BACKUP' OR toUpper(s.samaccountname) = 'SVC_BACKUP' OR toUpper(s.name) STARTS WITH 'SVC_BACKUP@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WEB-01,OU=WEB,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Nightly Backup', r.logonType = 'password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_BACKUP -> WEB-02.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_BACKUP' OR toUpper(s.samaccountname) = 'SVC_BACKUP' OR toUpper(s.name) STARTS WITH 'SVC_BACKUP@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WEB-02,OU=WEB,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Nightly Backup', r.logonType = 'password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_INVENTORY -> SQL-01.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_INVENTORY' OR toUpper(s.samaccountname) = 'SVC_INVENTORY' OR toUpper(s.name) STARTS WITH 'SVC_INVENTORY@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=SQL-01,OU=SQL,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Inventory Sync', r.runLevel = 'HighestAvailable', r.logonType = 'Password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_INVENTORY -> SQL-02.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_INVENTORY' OR toUpper(s.samaccountname) = 'SVC_INVENTORY' OR toUpper(s.name) STARTS WITH 'SVC_INVENTORY@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=SQL-02,OU=SQL,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Inventory Sync', r.runLevel = 'HighestAvailable', r.logonType = 'Password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_INVENTORY -> WEB-01.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_INVENTORY' OR toUpper(s.samaccountname) = 'SVC_INVENTORY' OR toUpper(s.name) STARTS WITH 'SVC_INVENTORY@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WEB-01,OU=WEB,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Inventory Sync', r.runLevel = 'HighestAvailable', r.logonType = 'Password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOScheduledTaskPrincipal: CONTOSO\SVC_INVENTORY -> WEB-02.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_INVENTORY' OR toUpper(s.samaccountname) = 'SVC_INVENTORY' OR toUpper(s.name) STARTS WITH 'SVC_INVENTORY@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=WEB-02,OU=WEB,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOScheduledTaskPrincipal]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}', r.gpoDisplayName = 'Server Maintenance Tasks', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml', r.taskName = 'Inventory Sync', r.runLevel = 'HighestAvailable', r.logonType = 'Password', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{9D2F6E80-A4C3-4E11-95B8-6C3A7F82D004}';

// GPOServiceAccount: CONTOSO\SVC_SQL -> SQL-01.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_SQL' OR toUpper(s.samaccountname) = 'SVC_SQL' OR toUpper(s.name) STARTS WITH 'SVC_SQL@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=SQL-01,OU=SQL,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOServiceAccount]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{5E71B3A9-C820-4D77-8F16-4B9E2C61A005}', r.gpoDisplayName = 'SQL Service Configuration', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{5E71B3A9-C820-4D77-8F16-4B9E2C61A005}\\Machine\\Preferences\\Services\\Services.xml', r.serviceName = 'MSSQLSERVER', r.startupType = 'AUTOMATIC', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{5E71B3A9-C820-4D77-8F16-4B9E2C61A005}';

// GPOServiceAccount: CONTOSO\SVC_SQL -> SQL-02.CONTOSO.LOCAL
MATCH (s) WHERE toUpper(s.name) = 'CONTOSO\\SVC_SQL' OR toUpper(s.samaccountname) = 'SVC_SQL' OR toUpper(s.name) STARTS WITH 'SVC_SQL@'
MATCH (t) WHERE toUpper(t.distinguishedname) = 'CN=SQL-02,OU=SQL,OU=SERVERS,DC=CONTOSO,DC=LOCAL'
MERGE (s)-[r:GPOServiceAccount]->(t)
ON CREATE SET r.source = 'group3rpy', r.gpo = '{5E71B3A9-C820-4D77-8F16-4B9E2C61A005}', r.gpoDisplayName = 'SQL Service Configuration', r.settingSource = '\\\\contoso.local\\sysvol\\contoso.local\\Policies\\{5E71B3A9-C820-4D77-8F16-4B9E2C61A005}\\Machine\\Preferences\\Services\\Services.xml', r.serviceName = 'MSSQLSERVER', r.startupType = 'AUTOMATIC', r.gppPasswordRecovered = true
ON MATCH SET r.group3rpySeen = true, r.group3rpyGpo = '{5E71B3A9-C820-4D77-8F16-4B9E2C61A005}';
