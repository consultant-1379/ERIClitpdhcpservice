#For LITPCDS-6548

define dhcpservice::config_server6 ($interfaces           = undef,
                                    $nameservers          = undef,
                                    $domainsearch         = undef,
                                    $ntpservers           = undef,
                                    $default_lease_time   = undef,
                                    $max_lease_time       = undef,
                                    $role                 = 'primary',
                                    $ensure               = 'present'){
    if $ensure == 'absent' {
      $servicename = 'dhcpd6'
      service { $servicename:
        enable => false,
        ensure => stopped,
      }
    }
    else {
      if $role == 'primary'
         {
         $preference = 255
         }
      else
         {
         $preference = 0
         }
      class { 'dhcp6':
        default_lease_time => $default_lease_time,
        max_lease_time     => $max_lease_time,
        interfaces         => $interfaces,
        nameservers        => $nameservers,
        ntpservers         => $ntpservers,
        domainsearch       => $domainsearch,
        preference         => $preference,
      }

    }
}

