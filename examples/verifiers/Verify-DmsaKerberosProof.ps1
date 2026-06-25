#Requires -Version 5.1
<#
.SYNOPSIS
    External dMSA Kerberos proof verifier skeleton for dmsa-reaper.

.DESCRIPTION
    This script is a skeleton adapter for the dmsa-reaper proof run-dmsa-verifier
    command. It must:
      1. Attempt to obtain a Kerberos ticket for the created dMSA account.
      2. Write a structured kerberos-dmsa-proof JSON to -OutFile.
      3. Exit 0 on success, non-zero on failure.

    This script MUST NOT:
      - Output raw Kerberos ticket bytes.
      - Export kirbi or ccache contents.
      - Log NT hashes, AES keys, session keys, or passwords.
      - Store base64-encoded ticket blobs anywhere.

    The proof JSON records only: principal, service principal, timestamp.

    The dmsa-reaper validator rejects any proof containing secret-looking
    base64 (>= 80 chars), hex strings (>= 32 chars), or secret-bearing
    key names (ntlm, aes_key, raw_ticket, kirbi, etc.).

.PARAMETER OperationId
    The dmsa-reaper operation ID (OP-...).

.PARAMETER Domain
    Domain FQDN (e.g. dmsalab.local).

.PARAMETER Realm
    Kerberos realm (e.g. DMSALAB.LOCAL).

.PARAMETER TargetSam
    SAM account name of the target (without $).

.PARAMETER CreatedDmsaSam
    SAM account name of the created dMSA (with $, e.g. dmsarpr-abc12345$).

.PARAMETER OutFile
    Path where the proof JSON will be written.

.PARAMETER ServicePrincipal
    Optional SPN for service ticket verification (e.g. cifs/dc01.dmsalab.local).

.EXAMPLE
    .\Verify-DmsaKerberosProof.ps1 `
        -OperationId "OP-20260604-deadbeef" `
        -Domain "dmsalab.local" `
        -Realm "DMSALAB.LOCAL" `
        -TargetSam "target.migrate" `
        -CreatedDmsaSam "dmsarpr-abc12345$" `
        -OutFile "C:\dmsa-proof.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OperationId,

    [Parameter(Mandatory = $true)]
    [string] $Domain,

    [Parameter(Mandatory = $true)]
    [string] $Realm,

    [Parameter(Mandatory = $true)]
    [string] $TargetSam,

    [Parameter(Mandatory = $true)]
    [string] $CreatedDmsaSam,

    [Parameter(Mandatory = $true)]
    [string] $OutFile,

    [Parameter(Mandatory = $false)]
    [string] $ServicePrincipal = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-UtcTimestamp {
    return (Get-Date -AsUTC).ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Write-ProofJson {
    param([hashtable] $Proof)
    $json = $Proof | ConvertTo-Json -Depth 6 -Compress:$false
    [System.IO.File]::WriteAllText($OutFile, $json, [System.Text.Encoding]::UTF8)
}

function Write-FailureProof {
    param([string] $FailureClass, [string] $Reason)
    Write-Warning "dMSA Kerberos proof failed: $Reason"
    Write-ProofJson @{
        "type"          = "kerberos-dmsa-proof"
        "operation_id"  = $OperationId
        "domain"        = $Domain.ToLower()
        "realm"         = $Realm.ToUpper()
        "target_sam"    = $TargetSam
        "created_dmsa_sam" = $CreatedDmsaSam
        "result"        = "failure"
        "failure_class" = $FailureClass
        "tool"          = @{
            "name"    = "windows-dmsa-verifier"
            "version" = "0.1"
        }
        "evidence"      = @{
            "principal"  = $null
            "service"    = $null
            "timestamp"  = (Get-UtcTimestamp)
        }
    }
    exit 1
}

# ── Step 1: Verify the dMSA account exists in the domain ─────────────────────
#
# TODO: Replace with your environment's preferred dMSA lookup mechanism.
# This placeholder checks AD for the account; adjust as needed.
#
try {
    $dmsaSam = $CreatedDmsaSam.TrimEnd('$')
    # Example: use Get-ADUser or a direct LDAP query to verify the object exists.
    # Uncomment and adapt for your environment:
    #
    # Import-Module ActiveDirectory
    # $dmsaAccount = Get-ADComputer -Identity $CreatedDmsaSam -ErrorAction Stop
    #
    # If you cannot use ActiveDirectory module, use DirectoryServices:
    # $searcher = New-Object System.DirectoryServices.DirectorySearcher
    # $searcher.Filter = "(&(objectClass=msDS-DelegatedManagedServiceAccount)(sAMAccountName=$CreatedDmsaSam))"
    # $result = $searcher.FindOne()
    # if (-not $result) { throw "dMSA not found" }
    Write-Host "Step 1: dMSA account $CreatedDmsaSam — TODO: verify account exists"
}
catch {
    Write-FailureProof "kerberos-dmsa-proof-missing" "Failed to locate dMSA account: $_"
}

# ── Step 2: Attempt to obtain a Kerberos ticket for the dMSA account ─────────
#
# TODO: Replace with your environment's Kerberos acquisition tooling.
# This must NOT log or store the raw ticket. Capture only metadata.
#
# Options (implement one):
#
# A) Use Rubeus (Windows — requires Rubeus.exe in PATH or specified path):
#    $rubeusOut = & "Rubeus.exe" asktgt /user:$CreatedDmsaSam /domain:$Domain /nowrap 2>&1
#    Parse $rubeusOut for "UserName", "ServiceName", "StartTime" fields ONLY.
#    Do NOT store the base64 ticket blob.
#
# B) Use native Windows credential APIs / SSPI:
#    Call AcquireCredentialsHandle + InitializeSecurityContext for the dMSA identity.
#    Capture ContextAttributes and expiry metadata only.
#
# C) Use Impacket (Linux — if running from WSL or a Linux proxy):
#    Run getTGT.py or getST.py; parse the ccache for principal metadata with klist.
#    Do NOT export ccache contents.
#
# Placeholder — always returns failure until implemented:
$ticketPrincipal = $null
$ticketService   = $null
$ticketObtained  = $false

# TODO: Remove this block and replace with real Kerberos acquisition above.
Write-Warning "Kerberos ticket acquisition is not implemented in this skeleton."
Write-Warning "Replace Step 2 with your environment-specific tooling."
# End placeholder

# ── Step 3: Verify service ticket (optional) ──────────────────────────────────
#
# If a service principal was supplied, verify a service ticket is obtainable.
# Capture only the service SPN; do NOT store the ticket.
#
# TODO: Implement service ticket verification if required.
$spnVerified = $false
if ($ServicePrincipal -ne "") {
    # TODO: Attempt service ticket for $ServicePrincipal.
    # $ticketService = $ServicePrincipal  # Set after successful acquisition
    Write-Warning "Service ticket verification not implemented; pass an empty -ServicePrincipal to skip."
}

# ── Step 4: Write proof JSON ──────────────────────────────────────────────────
if (-not $ticketObtained) {
    Write-FailureProof "kerberos-dmsa-proof-missing" `
        "Kerberos ticket acquisition for $CreatedDmsaSam was not completed (skeleton — implement Step 2)"
}

# SUCCESS path — only reaches here if Step 2 sets $ticketObtained = $true.
# Write only metadata, never raw ticket bytes.
Write-ProofJson @{
    "type"             = "kerberos-dmsa-proof"
    "operation_id"     = $OperationId
    "domain"           = $Domain.ToLower()
    "realm"            = $Realm.ToUpper()
    "target_sam"       = $TargetSam
    "created_dmsa_sam" = $CreatedDmsaSam
    "result"           = "success"
    "tool"             = @{
        "name"    = "windows-dmsa-verifier"
        "version" = "0.1"
    }
    "evidence"         = @{
        "principal"    = $ticketPrincipal
        "service"      = if ($ticketService) { $ticketService } else { "krbtgt/$Realm" }
        "timestamp"    = (Get-UtcTimestamp)
        "proof_method" = "kerberos-ticket-metadata-only"
    }
}

Write-Host "dMSA Kerberos proof written to $OutFile"
exit 0
