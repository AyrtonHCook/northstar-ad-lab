# Northstar AD Security Assessment

Nov 5, 2026 · @AyrtonCook

## Overview and objective

I built a small Active Directory lab to try something out: could a normal domain user read a restricted Finance share they're not supposed to have access to, by abusing a permission that was set up wrong?

The account I started from was NORTHSTAR\\alex.morgan, just an ordinary user. The goal was to read a file in the Finance share on FS01. The file has the string NORTHSTAR-FINANCE-01 in it, so if I saw that, I knew I'd actually reached the right file and not something cached.

It's my own lab, isolated, and all the data is made up. Short version: it worked. Alex got to the file through a delegated write permission on a group's membership. The rest of this is how, with the commands and outputs, and how I fixed it.

## Scope and lab architecture

Everything runs in VMware. The domain is northstar.test (NetBIOS NORTHSTAR), functional level Windows Server 2016. Two servers and a client:

| Host | Role | OS | IP |
| --- | --- | --- | --- |
| DC01 | Domain controller and DNS | Windows Server 2022 Datacenter Evaluation | 10.77.0.10 |
| FS01 | File server, domain member | Windows Server 2022 Datacenter Evaluation | 10.77.0.20 |
| Client | Ran commands as alex.morgan | Windows | (to confirm) |

There was also a Linux box on the network for assessment, though I did most of this from the Windows client.

One thing I haven't nailed down yet is the exact client spec, so I'm just calling it the Windows machine I ran the alex.morgan commands on. I'd rather say that than write down something I can't confirm. The alex.morgan outputs came from sessions on that client, and the admin outputs came from DC01.

## Starting access and initial restrictions

alex.morgan is a normal domain user. The only non-default group it's in is NORTHSTAR\\IT-Support. It is not in Finance-Readers, which is the group that's actually meant to have read access to the share.

Here's how the share permissions were set up:

| Layer | Principal | Access |
| --- | --- | --- |
| NTFS | NORTHSTAR\\Finance-Readers | Read and Execute, inherited by files and subfolders |
| NTFS | BUILTIN\\Administrators | Full Control |
| NTFS | SYSTEM | Full Control |
| SMB share | NORTHSTAR\\Finance-Readers | Read |
| SMB share | NORTHSTAR\\Domain Admins | Full |

The share is \\FS01.northstar.test\\Finance (C:\\LabData\\Finance on FS01), and the target file is C:\\LabData\\Finance\\budget-dummy.txt.

Before trying anything I checked the lab was actually healthy and the access was genuinely blocked, so that if something worked later I'd know it was the misconfig and not a broken setup. What I ran:

- Get-ADDomain, to confirm the domain.
- Get-Service NTDS,DNS,KDC,Netlogon on DC01, to confirm the core directory services were running.
- Resolve-DnsName on the LDAP SRV record, which resolved to dc01.northstar.test on port 389.
- Test-ComputerSecureChannel on FS01, to confirm its secure channel to the domain was valid.
- Test-NetConnection dc01.northstar.test -Port 389, to confirm FS01 could reach the domain controller.
- whoami /groups as alex.morgan, to confirm the starting identity and group membership.

Then alex.morgan tried to open the Finance share and got Access Denied. So that's the baseline: the control works, the user has no way in.

## Enumeration and reasoning

I started from a question, not a tool. Alex can't read the file directly, so is there an indirect way in? The read access comes through the Finance-Readers group, so if Alex could change who's in that group, the membership itself is the weak spot. Group membership is a security boundary, so anything that lets a normal user edit it is worth a look.

First I listed the group's members as alex.morgan to get a clean baseline:

```
net localgroup "Finance-Readers" /domain
```

It came back with no members, which fits Alex being denied. It also meant anything showing up in the group later could only have been added during testing, so the evidence stays clean.

A couple of tools didn't work on the client, which is why I ended up using the commands I did:

- dsacls was not present on the client, so the authoritative permission check was run later from an administrative session on DC01 using Get-Acl against the group object.
- net group "Finance-Readers" /domain returned a group not found error. This is a tooling and query distinction, not a finding. The net localgroup form with the /domain switch returned the group correctly.

These are just setup/investigation notes, not findings. I'm writing them down because they explain my commands, but none of them is a security issue by itself.

At this point my guess was that IT-Support (which Alex is in) had a delegated write permission over the Finance-Readers membership. Next step was to test that instead of assuming it.

## Confirmed finding and supporting evidence

The problem is a delegated write permission on the Finance-Readers membership. IT-Support has WriteProperty on the member attribute of Finance-Readers, and because Alex is in IT-Support, Alex inherits it and can change who's in the group.

The bit I'm most happy with is how I pinned down exactly what that permission was. When I dumped the group's permissions, dsacls labelled the entry Add/Remove self as member. That label means the narrower Self-Membership right, which would only let a user add their own account. If that were true, the whole thing would be limited to adding yourself.

I didn't just trust the label. I tested whether it was really that narrow by trying to add a different account, not just Alex. First try was a mess, the test account was already in the group so the command failed on that instead of on permissions. Once I cleaned that up, the real test worked: as Alex I added a separate account to Finance-Readers. That's only possible with a generic WriteProperty, not the narrow self-only right. So the test proved the label wrong.

To be sure, I also checked it properly with Get-Acl from an admin session on DC01, filtered to the IT-Support entry, which shows the actual rights instead of the friendly label.

Keeping observed / inferred / proved separate, since that mattered here:

- Observed: the dsacls label Add/Remove self as member, and the empty baseline membership.
- Inferred first, then corrected: that the right was Self-Membership only. This inference was wrong, and I treated the test evidence as the deciding factor over the label.
- Proved: that IT-Support members can add arbitrary accounts to Finance-Readers, demonstrated by successfully adding a second account as alex.morgan and confirmed by the Get-Acl output.

Evidence I've got to go with this (screenshots / pasted outputs):

- whoami /groups as alex.morgan, showing IT-Support membership and no Finance-Readers membership at the start.
- The baseline net localgroup "Finance-Readers" /domain output showing no members.
- The successful self-add and the successful add of a second account, each as command and result together.
- The administrative Get-Acl dump of the Finance-Readers object showing the WriteProperty entry for IT-Support, captured before remediation.
- Timestamps for each step, to show the order was not rearranged afterwards.

## Demonstrated impact

The point is that a normal user read the restricted file by escalating through the group. The chain:

alex.morgan (normal user) → in IT-Support → WriteProperty on Finance-Readers member → adds self to Finance-Readers → gets Finance-Readers' Read on the FS01 share → reads budget-dummy.txt.

The steps, all as alex.morgan unless I say otherwise:

1. Self-enrol into the target group:

   ```
   net localgroup "Finance-Readers" alex.morgan /add /domain
   ```

   This completed successfully, which confirms the delegated write is live.
2. Confirm the membership took effect:

   ```
   net localgroup "Finance-Readers" /domain
   ```

   alex.morgan now appears as a member.
3. Refresh the logon token. Group membership changes do not apply to an existing session, so I logged off and back on as alex.morgan to pick up the new membership.
4. Read the objective file:

   ```
   type \\FS01.northstar.test\Finance\budget-dummy.txt
   ```

   The file content was returned, including the marker NORTHSTAR-FINANCE-01. The marker confirms this is genuine access to the correct target, not a path or caching artefact.

It's a lab so I'm not going to oversell it, but the point stands: one normal user account gave itself read access to data it shouldn't see. In a real setup the same thing would let any member of the over-privileged group reach the data, and since the write is generic it could be used to add other accounts too, not just yourself.

## Remediation and retesting

The fix goes after the cause, not the symptom. Pulling Alex out of Finance-Readers would undo this one go, but the delegated write would still be there and any IT-Support member could just do it again. So the actual fix is removing the delegated permission.

What I did:

1. Remove the test account that had been added during the scope test, as administrator on DC01:

   ```
   Remove-ADGroupMember -Identity "Finance-Readers" -Members "james.muir" -Confirm:$false
   ```

   Then confirmed Finance-Readers membership was clear.
2. Remove the root-cause permission, the IT-Support entry on the Finance-Readers object, as administrator on DC01:

   ```
   dsacls "CN=Finance-Readers,OU=Lab Users,DC=northstar,DC=test" /R NORTHSTAR\IT-Support
   ```

   The /R switch removes all permission entries for that principal on the object, which is appropriate because IT-Support should hold no explicit rights on this group.
3. Verify the removal with the same authoritative method used to confirm the finding:

   ```
   $group = Get-ADGroup "Finance-Readers" -Properties *
   (Get-Acl "AD:$($group.DistinguishedName)").Access | Where-Object { $_.IdentityReference -like "*IT-Support*" }
   ```

   This returned nothing, confirming no IT-Support entry remained on the group.

The one thing I haven't done yet is the retest. The permission removal is confirmed by the Get-Acl check above, but I haven't recorded the two negative tests that would actually close it off: that Alex can't self-add to Finance-Readers any more, and that the file read goes back to Access Denied. That's the proof the fix holds from the attacker side, and I'll paste those outputs here once I've run them. For now, remediation is done and checked at the permission level, retest still to do.

## Limitations and lessons learned

Limitations: this is one finding in a lab I built myself, with one misconfig I put there on purpose, so I'm not pretending I discovered something unknown. The value is in the method and the evidence, not the find itself. The client spec still needs confirming and the retest still needs doing.

What I took from it:

- Don't trust a tool's label over an actual test. dsacls said the right was narrower than it really was. Adding a second account is what settled it. When the label and the behaviour disagree, go with the behaviour.
- Keep observed, inferred and proved separate. My first read was an inference and it was wrong. Because I'd written it down as a guess and not a fact, it was easy to correct once I had the evidence.
- Fix the cause, not the instance. Taking Alex out of the group would've hidden it; removing the delegated write actually fixed it, and I checked the removal the same way I found it.
- A finding isn't closed until you retest from the attacker side. The permission is gone, but it's only really done once the self-add fails and the read goes back to Access Denied.
- Check the environment before drawing conclusions. The service, DNS, secure-channel and connectivity checks at the start meant I could be sure the later success was the misconfig and not a broken lab.
