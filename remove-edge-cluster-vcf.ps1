$guestUser = "root"
$guestPassword = '<password>'
$guestVm = "sfo-vcf01"
$vcenterFqdn = "sfo-m01-vc01.sfo.rainpole.io"
$vcenterUser = "administrator@vsphere.local"
$vcenterPassword = '<password>'
$edgeClusterCleanerUrl = "https://kb.vmware.com/sfc/servlet.shepherd/version/download/0685G00000NHZoBQAX"
$edgeClusterDestination = "/root/edge_cluster_cleaner_0.18.tar.gz"
$edgeClusterName = "sfo-w01-ec01"

$removeEdgeCluster = @"
tar -zxvf $edgeClusterDestination
touch /root/.sddc_edge_removal_warning_accepted
/root/cleanup/remove_edge_cluster.sh --cluster $edgeClusterName --user $vcenterUser --password $vcenterPassword --skip-warning
"@

$viserver = Connect-VIServer -Server $vcenterFqdn -User $vcenterUser -Password $vcenterPassword -Force

try {
    $tryDownloadSddcManager = Invoke-VMScript -VM $guestVm -ScriptType Bash -ScriptText "wget -O $edgeClusterDestination $edgeClusterCleanerUrl" -GuestUser $guestUser -GuestPassword $guestPassword
} catch {
    Write-Error $_.Exception.InnerException
}

$finished = ($tryDownloadSddcManager.ToString() -Split '\n' | Select-Object -Last 3) | Where-Object {$_ -match "[6678986/6678986]"}

if ($finished){
    try {
        $tryRemoveEdgeCluster = Invoke-VMScript -VM $guestVm -ScriptType Bash -ScriptText $removeEdgeCluster -GuestUser $guestUser -GuestPassword $guestPassword
        $tryRemoveEdgeCluster
    } catch {
        Write-Error $_.Exception.InnerException
    }
}

Disconnect-VIServer * -Confirm:$false
