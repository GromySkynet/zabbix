
#requires -version 3

<#
.SYNOPSIS
	This script part of the Zabbix 
    Tempalte Windows OS Active
    Requrired PowerShell 3.0 or higher
.DESCRIPTION
  This sricpt using for LLD and trapper
.PARAMETER <ActionType>
	Type of action: discover, get or other
.PARAMETER <Key>
	Key - attirbute for 	
.PARAMETER <Value>
	Value - var for key, may be single or multiply
.INPUTS
  Input 3 variables

.OUTPUTS
  Output in JSON format for Zabbix 
.NOTES
  Version:        1.0
  Author:         gromy.skynet@gmail.com
  Creation Date:  15/03/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
  inventory.ps1 -ActionType "$1" -Key "$2" -Value "$3"
#>


Param(
    [Parameter(Mandatory = $true)][String]$ActionType,
    [Parameter(Mandatory = $true)][String]$Key,
    [Parameter(Mandatory = $false)][String]$Value
)

$ActionType = $ActionType.ToLower()
$Key = $Key.ToLower()
$Value = $Value.ToLower()


# it is need for correct cyrilic symbols in old OS
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-VM {

    $ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem 
    $IsVM = $false      
    switch ($ComputerSystemInfo.Model) { 
                     
        # Check for Hyper-V Machine Type 
        "Virtual Machine" { 
            $MachineType = "VM" 
            $IsVM = $true
        } 
 
        # Check for VMware Machine Type 
        "VMware Virtual Platform" { 
            $MachineType = "VM" 
            $IsVM = $true
        } 
 
        # Check for Oracle VM Machine Type 
        "VirtualBox" { 
            $MachineType = "VM" 
            $IsVM = $true
        } 
 
        # Check for Xen 
        # I need the values for the Model for which to check. 
 
        # Check for KVM 
        # I need the values for the Model for which to check. 
 
        # Otherwise it is a physical Box 
        default { 
            $MachineType = "Physical" 
        } 
    } 
    return $IsVM
}

if ($ActionType -eq "discover") {
    # Discover physical disk
    if ($Key -eq "pdisk") {
        [pscustomobject]@{
            'data' = @(
                Get-WmiObject win32_PerfFormattedData_PerfDisk_PhysicalDisk | Where-Object {$_.name -ne "_Total"} | ForEach-Object {
                    [pscustomobject]@{ '{#PHYSICAL_DISK}' = $_.Name }
                }
            )
        } | ConvertTo-Json
    }


    # Discover logical disk
    if ($Key -eq "ldisk") {
        [pscustomobject]@{
            'data' = @(
                Get-WmiObject win32_logicaldisk| Where-Object {$_.drivetype -eq 3}| ForEach-Object {
                    [pscustomobject]@{
                        '{#LOGICAL_DISK}'             = $_.DeviceID
                        '{#LOGICAL_DISK_VOLUME_NAME}' = $_.VolumeName					
                    }
                }
            )
        } | ConvertTo-Json
		
    }


    # Discover network physical interface
    if ($Key -eq "pnetwork") {	
	
        <#
			Query for the instances of Win32_NetworkAdapter that you are interested in.
		Take the value of 'PNPDeviceID' from each Win32_NetworkAdapter and append it to "\HKLM\SYSTEM\CurrentControlSet\Enum\" to produce a registry path to information on the adapter. Here is an example: "\HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_100E&SUBSYS_001E8086&REV_02\3&267A616A&0&18".
		Query the registry for the "FriendlyName" key at the path you derived above.
		If the "FriendlyName" key is present then take its string value. If the "FriendlyName" key is not defined then instead use the value of the "Description" key from Win32_NetworkAdapter.
		Take the string you got in step #4 and replace all instances of "/" and "#" with an underscore "_".
		The resulting string from step #5 should match the "Name" property within Win32_PerfFormattedData_Tcpip_NetworkInterface.
        #>
        
        # check is vm or physical, because on physical need search pnp like PCI card
        if (Test-VM) {
            $filter = "NetEnabled='True' and  PhysicalAdapter='True' and not NetConnectionID like ''"

        }
        else {
            $filter = "NetEnabled='True' and  PhysicalAdapter='True' 
						and NOT Manufacturer ='Microsoft' 
                		AND NOT PNPDeviceID LIKE 'ROOT\\%'"
        }

        $result_json = [pscustomobject]@{
            'data' = @(
                get-wmiobject win32_networkadapter -Filter $filter | ForEach-Object {
                    $PHYSICAL_NETWORK_NAME = $_.NetConnectionID;
                    $PHYSICAL_NETWORK_INTERFACEINDEX = $_.InterfaceIndex;
                    Get-WmiObject Win32_PnPEntity -Filter ("PNPDeviceID='$($_.PNPDeviceID)'" -Replace '\\', '\\') | ForEach-Object { 
                        [pscustomobject]@{
                            '{#PHYSICAL_NETWORK_NAME}'           = $PHYSICAL_NETWORK_NAME;
                            '{#PHYSICAL_NETWORK_NAME_PERF}'      = $_.Name.Replace("/", "_").Replace("#", "_").Replace("(", "[").Replace(")", "]")
                            '{#PHYSICAL_NETWORK_INTERFACEINDEX}' = $PHYSICAL_NETWORK_INTERFACEINDEX
                        }
                    }
                }					
            )
        }| ConvertTo-Json
	
        # output though console with encoding UTF8, because name can be with non english  characters
        [Console]::WriteLine($result_json)
    }


    # Discover windows network nic teaming - logical network
    if ($Key -eq "lnetwork") {
        $result_json = [pscustomobject]@{
            'data' = @(
                Get-NetLbfoTeam | ForEach-Object {
                    [pscustomobject]@{
                        '{#LNETWORK}' = $_.Name
                    }
                }
            )
        } | ConvertTo-Json
        [Console]::WriteLine($result_json)
    }
}

if ($ActionType -eq "get") {
    # Get data for physical network adapter by name
    if ($Key -eq "pnetwork") {
        if ($value -ne "") {
            $adapter = get-wmiobject win32_networkadapter  -Filter "NetEnabled='True' and  PhysicalAdapter='True'" |  Where-Object {$_.Name -eq "$Value"} | Select-Object *
            $connection_status = Get-NetworkStatusFromValue -SV ([convert]::ToInt32($adapter.NetConnectionStatus))
				
            $result = New-Object PSCustomObject
            $result | Add-Member -type NoteProperty -name MacAddress  -Value $adapter.MACAddress
            $result | Add-Member -type NoteProperty -name LinkSpeed -Value ([convert]::ToInt32($adapter.Speed))
            $result | Add-Member -type NoteProperty -name Name -Value $adapter.NetConnectionID
            $result | Add-Member -type NoteProperty -name InterfaceIndex -Value $adapter.Index
            $result | Add-Member -type NoteProperty -name Status -Value $connection_status
            $result | Add-Member -type NoteProperty -name AdminStatus -Value $adapter.NetEnabled
            $result | ConvertTo-Json
	
        }
    }

    if ($Key -eq "lnetwork") {
        if ($value -ne "") {
		
            $adapter = get-wmiobject win32_networkadapter  -Filter "NetEnabled='True' and  PhysicalAdapter='True'" |  Where-Object {$_.Name -eq "$Value"} | Select-Object *
            $connection_status = Get-NetworkStatusFromValue -SV ([convert]::ToInt32($adapter.NetConnectionStatus))
				
            $result = New-Object PSCustomObject
            $result | Add-Member -type NoteProperty -name MacAddress  -Value $adapter.MACAddress
            $result | Add-Member -type NoteProperty -name LinkSpeed -Value ([convert]::ToInt32($adapter.Speed))
            $result | Add-Member -type NoteProperty -name Name -Value $adapter.NetConnectionID
            $result | Add-Member -type NoteProperty -name InterfaceIndex -Value $adapter.Index
            $result | Add-Member -type NoteProperty -name Status -Value $connection_status
            $result | Add-Member -type NoteProperty -name AdminStatus -Value $adapter.NetEnabled
            $result | ConvertTo-Json
	
        }
    }
	
    if ($Key -eq "system_status") {
		
        $LastBootUpTime = (Get-WmiObject win32_operatingsystem | Select-Object csname, @{LABEL = 'LastBootUpTime'; EXPRESSION = {$_.ConverttoDateTime($_.lastbootuptime)}}).LastBootUpTime
        $LocalTime = Get-Date
        $PSComputername = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty PSComputername
        $Caption = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption
        $OSArchitecture = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture
        $Manufacturer = Get-WmiObject Win32_BIOS | Select-Object -ExpandProperty Manufacturer
        $SerialNumber = Get-WmiObject Win32_BIOS | Select-Object -ExpandProperty SerialNumber

        $result = New-Object PSCustomObject
        $result | Add-Member -type NoteProperty -name Name -Value $PSComputername
        $result | Add-Member -type NoteProperty -name Caption -Value $Caption
        $result | Add-Member -type NoteProperty -name OSArchitecture  -Value $OSArchitecture
        $result | Add-Member -type NoteProperty -name Manufacturer -Value $Manufacturer
        $result | Add-Member -type NoteProperty -name SerialNumber -Value $SerialNumber
        $result | Add-Member -type NoteProperty -name LastBootUpTime -Value $LastBootUpTime
        $result | Add-Member -type NoteProperty -name LocalTime -Value $LocalTime  
        $result | ConvertTo-Json
	
    }

}
	
