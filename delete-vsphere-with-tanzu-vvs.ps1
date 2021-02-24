### Import JSON input
$jsonFilePath = "c:\users\administrator\desktop\vsphere-with-tanzu-vvs-input.json"
$jsonInput = Get-Content -Path $jsonFilePath | ConvertFrom-Json

### Configure console output
Function LogMessage 
{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$message,
        [Parameter(Mandatory=$false)]
        [String]$colour,
        [Parameter(Mandatory=$false)]
        [string]$skipnewline
    )

    If (!$colour){
        $colour = "green"
    }

    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"

    Write-Host -NoNewline -ForegroundColor White " [$timestamp]"
    If ($skipnewline)
    {
        Write-Host -NoNewline -ForegroundColor $colour " $message"        
    }
    else 
    {
        Write-Host -ForegroundColor $colour " $message" 
    }
}

### Define variables based on JSON input
$nsxtManagerFqdn = $jsonInput.nsxt.nsxtManagerFqdn
$nsxtAdminUsername = $jsonInput.nsxt.nsxtAdminUsername
$nsxtAdminPassword = $jsonInput.nsxt.nsxtAdminPassword
$overlayTransportZoneName = $jsonInput.nsxt.overlay.overlayTransportZoneName
$tier0GatewayName = $jsonInput.nsxt.overlay.tier0GatewayName
$tier1GatewayName = $jsonInput.nsxt.overlay.tier1GatewayName
$kubSegmentName = $jsonInput.nsxt.overlay.kubSegmentName
$kubSegmentGatewayCIDR = $jsonInput.nsxt.overlay.kubSegmentGatewayCIDR
$kubSegmentSubnetCIDR = $jsonInput.nsxt.overlay.kubSegmentSubnetCIDR
$ingressSubnetCIDR = $jsonInput.nsxt.overlay.ingressSubnetCIDR
$egressSubnetCIDR = $jsonInput.nsxt.overlay.egressSubnetCIDR
$podsSubnetCIDR = $jsonInput.nsxt.overlay.podsSubnetCIDR
$servicesSubnetCIDR = $jsonInput.nsxt.overlay.servicesSubnetCIDR
$ipPrefixListName = $jsonInput.nsxt.routes.ipPrefixListName
$routeMapName = $jsonInput.nsxt.routes.routeMapName
$localeServicesName = $jsonInput.nsxt.routes.localeServicesName
$edgeClusterName = $jsonInput.nsxt.routes.edgeClusterName
$computeManagerFqdn = $jsonInput.vsphere.computeManagerFqdn
$computeManagerUsername = $jsonInput.vsphere.computeManagerAdminUsername
$computeManagerPassword = $jsonInput.vsphere.computeManagerAdminPassword
$contentLibraryName = $jsonInput.vsphere.contentLibrary.contentLibraryName
$contentLibraryUrl = $jsonInput.vsphere.contentLibrary.contentLibraryUrl
$wldDatastoreName = $jsonInput.vsphere.contentLibrary.wldDatastoreName
$spbmPolicyName = $jsonInput.vsphere.storagePolicy.spbmPolicyName
$spbmRuleSetName = $jsonInput.vsphere.storagePolicy.spbmRuleSetName
$tagName = $jsonInput.vsphere.storagePolicy.tagName
$tagCategoryName = $jsonInput.vsphere.storagePolicy.tagCategoryName
$wmClusterName = $jsonInput.vsphere.vsphereWithTanzu.wmClusterName
$wmClusterSize = $jsonInput.vsphere.vsphereWithTanzu.wmClusterSize
$wmClusterMgmtNetworkMode = $jsonInput.vsphere.vsphereWithTanzu.wmClusterMgmtNetworkMode
$wmClusterMgmtStartIpAddress = $jsonInput.vsphere.vsphereWithTanzu.wmClusterMgmtStartIpAddress
$wmClusterMgmtNetworkAddressRangeSize = $jsonInput.vsphere.vsphereWithTanzu.wmClusterMgmtNetworkAddressRangeSize
$wmClusterMgmtNetworkGateway = $jsonInput.vsphere.vsphereWithTanzu.wmClusterMgmtNetworkGateway
$wmClusterMgmtNetmask = $jsonInput.vsphere.vsphereWithTanzu.wmClusterMgmtNetmask
$ntpServerIpAddress1 = $jsonInput.vsphere.vsphereWithTanzu.ntpServerIpAddress1
$ntpServerIpAddress2 = $jsonInput.vsphere.vsphereWithTanzu.ntpServerIpAddress2
$supClusterVdsName = $jsonInput.vsphere.vsphereWithTanzu.supClusterVdsName
$dnsServerIpAddress1 = $jsonInput.vsphere.vsphereWithTanzu.dnsServerIpAddress1
$dnsServerIpAddress2 = $jsonInput.vsphere.vsphereWithTanzu.dnsServerIpAddress2
$dnsSearchDomain = $jsonInput.vsphere.vsphereWithTanzu.dnsSearchDomain
$wmNamespaceName = $jsonInput.vsphere.vsphereWithTanzu.wmNamespaceName
$wmTkcNamespaceName = $jsonInput.vsphere.vsphereWithTanzu.wmTkcNamespaceName

### Modules required
LogMessage -message "Checking if module Await 0.8 is installed..."
$awaitModule = Get-InstalledModule -Name Await -ErrorAction SilentlyContinue

if ($awaitModule -and $awaitModule.Version -eq 0.8) {
    LogMessage -message "Module Await 0.8 is installed. Skipping..."
} elseif ($awaitModule -and $awaitModule.Version -ne 0.8) {
    LogMessage -message "Module Await is installed, but it is the wrong version. Uninstalling..."
    $awaitModule | Uninstall-Module -ErrorAction SilentlyContinue
    LogMessage -message "Installing module Await 0.8..."
    Install-Module -Name Await -MinimumVersion 0.8 -ErrorAction SilentlyContinue
} elseif (!$awaitModule) {
    LogMessage -message "Module Await is not installed. Installing..."
    Install-Module -Name Await -MinimumVersion 0.8 -ErrorAction SilentlyContinue
}

### External Functions
## Get-SSLThumbprint allows you to retrieve the thumbprint of a web server's SSL certificate
# Via William Lam - https://gist.github.com/lamw/988e4599c0f88d9fc25c9f2af8b72c92
Function Get-SSLThumbprint {
    param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)
    ]
    [Alias('FullName')]
    [String]$URL
    )

add-type -TypeDefinition @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

    # Need to connect using simple GET operation for this to work
    Invoke-RestMethod -Uri $URL -Method Get | Out-Null

    $ENDPOINT_REQUEST = [System.Net.Webrequest]::Create("$URL")
    $SSL_THUMBPRINT = $ENDPOINT_REQUEST.ServicePoint.Certificate.GetCertHashString()

    return $SSL_THUMBPRINT -replace '(..(?!$))','$1:'
}

## Enable TLS 1.1 and 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

## Define header for Authentication, JSON, and X-Allow-Overwrite
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $nsxtAdminUsername,$nsxtAdminPassword)))
$headers = @{"Accept" = "application/json"}
$headers.Add("Authorization", "Basic $base64AuthInfo")
$headers.Add("X-Allow-Overwrite", $true)

## Use Connect-VIServer to connect to the Workload Domain vCenter Server
$viserver = Connect-VIServer -Server $computeManagerFqdn -User $computeManagerUsername -Password $computeManagerPassword -Force

# Build the header to perform username/password based authentication
$vcBase64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $computeManagerUsername,$computeManagerPassword)))
$getSessionHeaders = @{"vmware-use-header-authn" = "true"}
$getSessionHeaders.Add("Authorization", "Basic $vcBase64AuthInfo")

# Perform the vCenter REST API call to authenticate and retrieve the session token
$vcSession = (Invoke-WebRequest -Method POST -URI  https://$computeManagerFqdn/rest/com/vmware/cis/session -Headers $getSessionHeaders | ConvertFrom-Json).Value

# Use the session token to build the header used from here on
$vcSessionHeaders = @{"vmware-api-session-id" = $vcSession}
$vcSessionHeaders.Add("Content-Type","application/json")

# Check if the Supervisor Cluster is up
LogMessage -message "Checking the status of Supervisor Cluster $wmClusterName..."
try {
    $getInitialWmClusterStatus = Get-WmCluster -Cluster $wmClusterName -ErrorAction SilentlyContinue
} catch {
    LogMessage -message "Something went wrong."
}

if (!$getInitialWmClusterStatus) {
    LogMessage -message "vSphere Namespace $wmClusterName has already been deleted. Skipping..."
} else {

    ## Get kubectl from the Supervisor Cluster and install it
    # Get the IP address for the Supervisor Cluster Kubernetes API & Web interfaces
    $wmClusterIpAddress = (Get-WMCluster -Cluster $wmClusterName).KubernetesHostname

    # Download kubectl with the vSphere plugin from the Supervisor Cluster (Windows only)
    try {
        LogMessage -message "Downloading vsphere-plugin.zip from Supervisor Cluster $wmClusterIpAddress..."
        $getDownload = Invoke-WebRequest -URI "https://$wmClusterIpAddress/wcp/plugin/windows-amd64/vsphere-plugin.zip" -OutFile $env:USERPROFILE\Downloads\vsphere-plugin.zip -ErrorAction SilentlyContinue
    } catch {
        LogMessage -message "Something went wrong."
    }

    # Unzip the downloaded package (Windows only)
    try {
        LogMessage -message "Unzipping contents of vsphere-plugin.zip to Downloads\vsphere-plugin\..."
        Expand-Archive -Path $env:USERPROFILE\Downloads\vsphere-plugin.zip -DestinationPath $env:USERPROFILE\Downloads\vsphere-plugin\ -Force
    } catch {
        LogMessage -message "Something went wrong."
    }

    # Move kubectl and kubectl-vsphere to a new folder (Windows only)
    try {
        LogMessage -message "Creating c:\kube and moving the contents of Downloads\vsphere-plugin\ to it..."
        New-Item -Path "c:\" -Name "kube" -ItemType "Directory" -Force
        Move-Item -Path $env:USERPROFILE\Downloads\vsphere-plugin\bin\* -Destination C:\kube -Force
    } catch {
        LogMessage -message "Something went wrong."
    }

    # Add the new folder to the PATH environment variable (Windows only)
    try {
        LogMessage -message "Configuring the PATH environment variable to include c:\kube..."
        $env:PATH = "c:\kube;$env:PATH"
    } catch {
        LogMessage -message "Something went wrong."
    }

    # Use the cmdlets from the Await module to login to the Supervisor Cluster (Windows only)
    try {
        LogMessage -message "Logging in to Supervisor Cluster $wmClusterName as $computeManagerUsername with kubectl..."
    Start-AwaitSession | Out-Null
    Send-AwaitCommand "kubectl vsphere login --server $wmClusterIpAddress --vsphere-username $computeManagerUsername --insecure-skip-tls-verify" | Out-Null
    Wait-AwaitResponse "Password:" | Out-Null
    Send-AwaitCommand "$computeManagerPassword" | Out-Null
    Stop-AwaitSession | Out-Null

    Start-Sleep -seconds 5 | Out-Null

    } catch {
        LogMessage -Message "Something went wrong."
    }

    # Switch context to use Supervisor Namespace $wmTkcNamespaceName
    try {
        LogMessage -message "Switching context to use Supervisor Namespace $wmTkcNamespaceName..."
        kubectl config use-context $wmTkcNamespaceName | Out-Null
    } catch {
        LogMessage -message "Something went wrong."
    }

    # Delete TK Cluster
    LogMessage -message "Checking the status of Tanzu Kubernetes Cluster $wmTkcNamespaceName..."
    try {
        $getTkcDeleteStatus = (kubectl get TanzuKubernetesCluster $wmTkcNamespaceName -o json | ConvertFrom-Json).status
    } catch {
        LogMessage -message "Something went wrong."
    }

    if (!$getTkcDeleteStatus) {
        LogMessage -message "Tanzu Kubernetes Cluster $wmTkcNamespaceName has already been deleted. Skipping..."
    } else {
        LogMessage -message "Deleting Tanzu Kubernetes Cluster $wmTkcNamespaceName..."
        $deleteTkc = kubectl delete TanzuKubernetesCluster $wmTkcNamespaceName

        Do {
            LogMessage -message "Checking Tanzu Kubernetes Cluster $wmTkcNamespaceName status to ensure it is deleted..."
            $checkTkcDeleteStatus = (kubectl get TanzuKubernetesCluster $wmTkcNamespaceName -o json | ConvertFrom-Json).status

            if (!$checkTkcDeleteStatus) {
                LogMessage -message "Tanzu Kubernetes Cluster $wmTkcNamespaceName has been successfully deleted."
            } else {
                LogMessage -message "Tanzu Kubernetes Cluster $wmTkcNamespaceName is still being removed. Waiting 1 minunte and trying again..."
                Start-Sleep -seconds 60
            }
        } Until (!$checkTkcDeleteStatus)
    }

    # Delete Namespaces
    LogMessage -message "Checking the status of vSphere Namespace $wmNamespaceName..."
    try {
        $getWmNamespaceStatus = Get-WmNamespace -Name $wmNamespaceName -ErrorAction SilentlyContinue
    } catch {
        LogMessage -message "Something went wrong."
    }

    if (!$getWmNamespaceStatus) {
        LogMessage -message "vSphere Namespace $wmNamespaceName has already been deleted. Skipping..."
    } else {
        LogMessage -message "Deleting vSphere Namespace $wmNamespaceName..."
        $deleteWmNamespace = Get-WmNamespace -Name $wmNamespaceName | Remove-WMNamespace -Confirm:$false

        try {
            $checkWmNamespaceStatus = Get-WmNamespace -Name $wmNamespaceName -ErrorAction SilentlyContinue
        } catch {
            LogMessage -message "Something went wrong."
        }

        if (!$checkWmNamespaceStatus) {
            LogMessage -Message "vSphere Namespace $wmNamespaceName has been successfully deleted."
        } else {
            LogMessage -message "Something went wrong."
        }
    }

    LogMessage -message "Checking the status of vSphere Namespace $wmTkcNamespaceName..."
    try {
        $getWmTkcNamespaceStatus = Get-WmNamespace -Name $wmTkcNamespaceName -ErrorAction SilentlyContinue
    } catch {
        LogMessage -message "Something went wrong."
    }

    if (!$getWmTkcNamespaceStatus) {
        LogMessage -message "vSphere Namespace $wmTkcNamespaceName has already been deleted. Skipping..."
    } else {
        LogMessage -message "Deleting vSphere Namespace $wmTkcNamespaceName..."
        $deleteWmTkcNamespace = Get-WmNamespace -Name $wmTkcNamespaceName | Remove-WMNamespace -Confirm:$false

        try {
            $checkWmTkcNamespaceStatus = Get-WmNamespace -Name $wmTkcNamespaceName -ErrorAction SilentlyContinue
        } catch {
            LogMessage -message "Something went wrong."
        }

        if (!$checkWmTkcNamespaceStatus) {
            LogMessage -Message "vSphere Namespace $wmTkcNamespaceName has been successfully deleted."
        } else {
            LogMessage -message "Something went wrong."
        }
        
    }

    # Delete Harbor
    # Check to see if the embedded Harbor Registry already exists
    LogMessage -Message "Checking embedded Harbor Registry for Supervisor Cluster $wmClusterName to see if it exists..."
    try {    
        $getHarborInstalled = (Invoke-WebRequest -Method GET -URI  https://$computeManagerFqdn/rest/vcenter/content/registries/harbor -Headers $vcSessionHeaders -ErrorAction SilentlyContinue | ConvertFrom-Json).value
    } catch {
        $harborStatusErrorOutput = $_.Exception
    }

    if (!$getHarborInstalled) {
        LogMessage -message "Embedded Harbor Registry for Supervisor Cluster $wmClusterName has already been deleted. Skipping..."
    } else {
        # Retrieve the Supervisor Cluster id
        $wmClusterId = (Invoke-WebRequest -Method GET -URI  https://$computeManagerFqdn/api/vcenter/namespace-management/clusters -Headers $vcSessionHeaders | ConvertFrom-Json).cluster
        $harborRegistryId = ((Invoke-WebRequest -Method GET -URI  https://$computeManagerFqdn/rest/vcenter/content/registries/harbor -Headers $vcSessionHeaders | convertfrom-json).value | Where-Object {$_.cluster -eq $wmClusterId}).registry


        try {
            LogMessage -Message "Removing embedded Harbor Registry for Supervisor Cluster $wmClusterName..."
            $harborRegistryId = ((Invoke-WebRequest -Method GET -URI  https://$computeManagerFqdn/rest/vcenter/content/registries/harbor -Headers $vcSessionHeaders -ErrorAction SilentlyContinue | convertfrom-json).value | Where-Object {$_.cluster -eq $wmClusterId}).registry
            $deleteHarbor = Invoke-WebRequest -Method DELETE -URI  https://$computeManagerFqdn/rest/vcenter/content/registries/harbor/$harborRegistryId -Headers $vcSessionHeaders -ErrorAction SilentlyContinue
        } catch {
            LogMessage -message "Something went wrong."
        }

        do {
            $getHarborStatus = $null    
            LogMessage -message "Checking the embedded Habror Registry for Supervisor Cluster $wmClusterName configuration status..."
            try {    
                $getHarborStatus = (Invoke-WebRequest -Method GET -URI  https://$computeManagerFqdn/rest/vcenter/content/registries/harbor/$harborRegistryId -Headers $vcSessionHeaders -ErrorAction SilentlyContinue | convertfrom-json).value.health.status
            } catch {
                $harborStatusErrorOutput = $_.Exception
            }

            if ($getHarborStatus -eq "DELETING") {
                LogMessage -message "Embedded Harbor Registry for Supervisor Cluster $wmClusterName removal is incomplete. Waiting 1 minute and try again..."
                Start-Sleep -Seconds 60
            } elseif (!$getHarborStatus) {
                LogMessage -message "Embedded Harbor Registry for Supervisor Cluster $wmClusterName has been removed successfully."
            } else {
                LogMessage -message "Something went wrong."
                break
            }
        } until (!$getHarborStatus)
    }

    # Delete Supervisor Cluster
    LogMessage -message "Checking the status of Supervisor Cluster $wmClusterName..."
    try {
        $getWmClusterStatus = Get-WmCluster -Cluster $wmClusterName -ErrorAction SilentlyContinue
    } catch {
        LogMessage -message "Something went wrong."
    }

    if (!$getWmClusterStatus) {
        LogMessage -message "vSphere Namespace $wmClusterName has already been deleted. Skipping..."
    } else {
        LogMessage -message "Removing the Supervisor Cluster $wmClusterName..."
        $deleteWmCluster = Get-WmCluster -Cluster $wmClusterName | Disable-WMCluster -Confirm:$false -RunAsync

        do {
            LogMessage -message "Checking the Supervisor Cluster $wmClusterName configuration status..."
            $wmClusterStatus = $null
            try {
                $wmClusterStatus = Get-WMCluster -Cluster $wmClusterName -ErrorAction SilentlyContinue
            } catch {
                LogMessage -message "Something went wrong."
            }
            if (!$wmClusterStatus) {
                LogMessage -message "Supervisor Cluster $wmClusterName has been removed."
            } else {
                LogMessage -message "Supervisor Cluster $wmClusterName is still being removed. Waiting for 1 minute and trying again..."
                Start-Sleep -seconds 60
            }
        } until (!$wmClusterStatus)
    }
}
# Delete Content Library
LogMessage -message "Checking the status of subscribed Content Library $contentLibraryName..."
try {
    $getContentLibraryStatus = Get-ContentLibrary -Name $contentLibraryName -ErrorAction SilentlyContinue
} catch {
    LogMessage -message "Something went wrong."
}

if (!$getContentLibraryStatus) {
    LogMessage -message "vSphere Namespace $wmClusterName has already been deleted. Skipping..."
} else {
    LogMessage -message "Removing the subscribed Content Library $contentLibraryName..."
    $deleteContentLibrary = Get-ContentLibrary -Name $contentLibraryName | Remove-ContentLibrary -Confirm:$false
}

# Delete Tag applied to vSAN
LogMessage -message "Checking if $wldDatastoreName has vSphere Tag $tagName applied..."
try {
    $getTagAssignmentStatus = Get-Datastore -Name $wldDatastoreName | Get-TagAssignment -Category $tagCategoryName -ErrorAction SilentlyContinue
} catch {
    LogMessage -message "Something went wrong."
}

if (!$getTagAssignmentStatus) {
    LogMessage -message "vSphere Tag assignment has already been removed. Skipping..."
} else {
LogMessage -message "Removing the vSphere Tag $tagName from datastore $wldDatastoreName..."
$removeTagAssignment = Get-Datastore -Name $wldDatastoreName | Get-TagAssignment -Category $tagCategoryName | Remove-TagAssignment -Confirm:$false -ErrorAction SilentlyContinue
}

# Delete SPBM Policy
LogMessage -message "Checking if the SPBM Storage Policy $spbmPolicyName exists..."
$getStoragePolicy = Get-SpbmStoragePolicy -Name $spbmPolicyName -ErrorAction SilentlyContinue

if (!$getStoragePolicy) {
    LogMessage -message "SPBM Storage Policy $spbmPolicyName does not exist. Skipping..."
} else {
    LogMessage -message "SPBM Storage Policy $spbmPolicyName exists. Deleting..."
    $deleteStoragePolicy = Get-SpbmStoragePolicy -Name $spbmPolicyName | Remove-SpbmStoragePolicy -Confirm:$false
}

# Delete vSphere Tag
LogMessage -message "Checking if the vSphere Tag $tagName exists..."
$getTag = Get-Tag -Name $tagName -ErrorAction SilentlyContinue

if (!$getTag) {
    LogMessage -message "vSphere Tag $tagName does not exist. Skipping..."
} else {
    LogMessage -message "vSphereTag $tagName exists. Deleting..."
    $deleteTag = $getTag | Remove-Tag -Confirm:$false
}

# Delete vSphere Category
LogMessage -message "Checking if the vSphere Tag Category $tagCategoryName exists..."
$getTagCategory = Get-TagCategory -Name $tagCategoryName -ErrorAction SilentlyContinue

if (!$getTagCategory) {
    LogMessage -message "vSphere Tag Category $tagCategoryName does not exist. Skipping..."
} else {
    LogMessage -message "vSphere Tag Category $tagCategoryName exists. Deleting..."
    $deleteTagCategory = $getTagCategory | Remove-TagCategory -Confirm:$false
}

# Delete Compute Manager Trust
# Get the existing compute manager
$computeManager = $null
start-sleep -s 5
$computeManager = (Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/api/v1/fabric/compute-managers -ContentType application/json -Headers $headers).results | Where-Object {$_.server -eq $computeManagerFqdn}

# Checking to see if the compute manager trust is already set
LogMessage -message "Checking if the compute manager trust is already disabled..."
if ($computeManager.set_as_oidc_provider -eq $false) {
    LogMessage -message "The compute manager trust is already disabled. Skipping..."
} else {
# Set variables for use in the JSON body - we can't reference $variable.property within the JSON definition below, so we define a separate variable
$computeManagerId = $computeManager.id
$computeManagerRevision = $computeManager._revision
$computeManagerOriginType = $computeManager.origin_type
$computeManagerCredentialType = $computeManager.credential.credential_type
$computeManagerCredentialThumbprint = $computeManager.credential.thumbprint

# Define JSON body for compute manager configuration
$computeManagerJson = @"
{  
    "_revision" : $computeManagerRevision,
    "server" : "$computeManagerFqdn",
    "origin_type" : "$computeManagerOriginType",
    "set_as_oidc_provider" : "$false",
    "credential" : 
    {
        "credential_type" : "$computeManagerCredentialType",
        "username" : "$computeManagerUsername",
        "password" : "$computeManagerPassword",
        "thumbprint" : "$computeManagerCredentialThumbprint"
    }
}
"@

# Send a REST API call to NSX-T Manager to configure the existing compute manager to allow for trust between itself and NSX-T Manager
try {    
    LogMessage -message "The compute manager trust is not disabled. Disabling..."
    $tryComputeManager = Invoke-RestMethod -Method PUT -URI https://$nsxtManagerFqdn/api/v1/fabric/compute-managers/$computeManagerId -ContentType application/json -Body $computeManagerJson -Headers $headers
} catch {
    Write-Error $_.Exception
}
}

# Delete RR Config
# Get the existing locale services configuration for the Tier-0 Gateway
$localeServices = Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/locale-services/$localeServicesName -ContentType application/json -Headers $headers

# Checking to see if the route redistribution policy is already set
LogMessage -message "Checking if the route redistribution policy is already deleted..."
if ($localeServices.route_redistribution_config.redistribution_rules.route_map_path -ne "/infra/tier-0s/$tier0GatewayName/route-maps/$routeMapName") {
    LogMessage -message "The route distribution policy is already deleted. Skipping..."
} else {

# Set variables for use in the JSON body - we can't reference $variable.property within the JSON definition below, so we define a separate variable
$localeServicesRevision = $localeServices._revision
$routeRedistributionRuleName = $localeServices.route_redistribution_config.redistribution_rules.name
$edgeClusterPath = $localeServices.edge_cluster_path

# Define JSON body for route redistribution configuration
$localeServicesJson = @"
{       
    "_revision" : $localeServicesRevision,
    "edge_cluster_path" : "$edgeClusterPath",
    "route_redistribution_config" : 
    {
        "bgp_enabled" : "$true",
        "redistribution_rules" : 
        [
            {
            "name" : "$routeRedistributionRuleName",
            "route_redistribution_types" : [ "TIER0_CONNECTED", "TIER1_LB_SNAT", "TIER1_DNS_FORWARDER_IP", "TIER1_LB_VIP", "TIER1_NAT", "TIER0_NAT", "TIER1_CONNECTED", "TIER0_DNS_FORWARDER_IP", "TIER1_STATIC", "TIER0_STATIC", "TIER0_IPSEC_LOCAL_IP" ]
            }
        ]
    }
}
"@

# Send a REST API call to NSX-T Manager to enable the new route redistribution policy
try {
    $tryRouteRedistribution = Invoke-RestMethod -Method PUT -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/locale-services/$localeServicesName -ContentType application/json -body $localeServicesJson -Headers $headers
} catch {
    Write-Error $_.Exception
}
}


# Delete Route Map
try {
    Write-Output "Checking if NSX-T Route Map $routeMapName exists..."
    $tryRouteMap = Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/route-maps/$routeMapName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
} catch {
    $routeMapDeleteErrorOutput = $_.Exception
}

if (!$routeMapDeleteErrorOutput) {
    Write-Output "NSX-T Route Map $routeMapName exists. Deleting..."
    try {
        $tryDeleteRouteMap = Invoke-RestMethod -Method DELETE -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/route-maps/$routeMapName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
    
        try {
            $tryGetDeletedRouteMap = Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/route-maps/$routeMapName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
        } catch {
            $deletedRouteMapError = $_.Exception
        }
        
        if ($deletedRouteMapError.response.statuscode -eq "NotFound") {
            write-output "NSX-T Route Map $routeMapName has been successfully deleted."
        } else {
            write-output "Something went wrong."
        }
    
    } catch {
        Write-Output $_
    }
} else {
    Write-Output "NSX-T Route Map $routeMapName does not exist, so it will not be deleted."
}

# Delete IP Prefix List
try {
    Write-Output "Checking if  NSX-T IP Prefix List $ipPrefixListName exists..."
    $tryIpPrefixList = Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/prefix-lists/$ipPrefixListName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
} catch {
    $ipPrefixDeleteErrorOutput = $_.Exception
}

if (!$ipPrefixDeleteErrorOutput) {
    Write-Output " NSX-T IP Prefix List $ipPrefixListName exists. Deleting..."
    try {
        $tryDeleteIpPrefixList = Invoke-RestMethod -Method DELETE -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/prefix-lists/$ipPrefixListName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
            try {
            $tryGetDeletedIpPrefixList = Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/policy/api/v1/infra/tier-0s/$tier0GatewayName/prefix-lists/$ipPrefixListName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
            } catch {
                $deletedIpPrefixListError = $_.Exception
            }
        
        if ($deletedIpPrefixListError.response.statuscode -eq "NotFound") {
            write-output " NSX-T IP Prefix List $ipPrefixListName has been successfully deleted."
        } else {
            write-output "Something went wrong."
        }
    
    } catch {
        Write-Output $_
    }
} else {
    Write-Output " NSX-T IP Prefix List $ipPrefixListName does not exist, so it will not be deleted."
}

# Delete Overlay Segment
try {
    Write-Output "Checking if NSX-T Overlay Segment $kubSegmentName exists..."
    $tryKubSegment = Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/policy/api/v1/infra/segments/$kubSegmentName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
} catch {
    $kubSegmentDeleteErrorOutput = $_.Exception
}

if (!$kubSegmentDeleteErrorOutput) {
    Write-Output "NSX-T Overlay Segment $kubSegmentName exists. Deleting..."
    try {
        $tryDeleteKubSegment = Invoke-RestMethod -Method DELETE -URI https://$nsxtManagerFqdn/policy/api/v1/infra/segments/$kubSegmentName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
            try {
                $tryGetDeletedKubSegment = Invoke-RestMethod -Method GET -URI https://$nsxtManagerFqdn/policy/api/v1/infra/segments/$kubSegmentName -ContentType application/json -Headers $headers -ErrorAction SilentlyContinue
            } catch {
                $deletedKubSegmentError = $_.Exception
            }
        
        if ($deletedKubSegmentError.response.statuscode -eq "NotFound") {
            write-output "NSX-T Overlay Segment $kubSegmentName has been successfully deleted."
        } else {
            write-output "Something went wrong."
        }
    
    } catch {
        Write-Output $_
    }
} else {
    Write-Output "NSX-T Overlay Segment $kubSegmentName does not exist, so it will not be deleted."
}