#For LITPCDS-6548

define dhcpservice::config_pool6($network      = undef,
                                 $ranges       = undef,
                                 $ensure       = 'present'){

   dhcp6::pool{$name:
      network       => $network,
      range         => $ranges,
      ensure        => $ensure,
   }
}

