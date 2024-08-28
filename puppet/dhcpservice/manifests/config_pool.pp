#For LITPCDS-6548

define dhcpservice::config_pool($network      = undef,
                                $mask         = undef,
                                $ranges       = undef,
                                $nameservers  = undef,
                                $domainsearch = undef,
                                $ntpservers   = undef,
                                $failover     = 'false',
                                $ensure       = 'present'){

   if $failover == 'true' {
      $failover_name = 'dhcp-failover'
   }
   else {
      $failover_name = ''
   }

   dhcp::pool{$name:
      network       => $network,
      mask          => $mask,
      range         => $ranges,
      nameservers   => $nameservers,
      domainsearch  => $domainsearch,
      ntpservers    => $ntpservers,
      failover      => $failover_name,
      ensure        => $ensure,
   }
}

