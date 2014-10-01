#
# (c) Jan Gehring <jan.gehring@gmail.com>
# 
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:
#
=encoding UTF-8

=head1 NAME

Rex::KVM::Agent - Small KVM Agent for Rex

=head1 DESCRIPTION

This is a small KVM agent for Rex to communicate with the VM over serial line. This is currently used to get the ip of the network devices, because sometimes the arp table doesn't list the ip.

=cut


package Rex::KVM::Agent;

use strict;
use warnings;

use JSON::XS;

require Rex;
require Rex::Commands::Gather;

sub new {
  my $that = shift;
  my $proto = ref($that) || $that;
  my $self = { @_ };

  bless($self, $proto);

  $self->{command_map} = {
    GET => {
      "/network/devices" => sub { $self->_get_network_devices() },
    },
  };

  return $self;
}

sub fh { (shift)->{fh}; }

sub run {
  my ($self) = @_;

  my $serial_line_fh = $self->{fh};

  while(my $line = <$serial_line_fh>) {
    chomp $line;
    my ($command, $parameter) = split(/ /, $line, 2);
    if(exists $self->{command_map}->{$command} && exists $self->{command_map}->{$command}->{$parameter}) {
        $self->{command_map}->{$command}->{$parameter}->();
    }
  }
}

sub _get_network_devices {
  my ($self) = @_;
  my %info = Rex::Commands::Gather::get_system_information();
  $self->fh->print(encode_json($info{Network}) . "\n");
}

1;
