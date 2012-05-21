
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "File::Spec" => 0,
    "Module::Build" => "0.3601",
    "Test::More" => 0,
    "Test::Warn" => 0
  },
  "configure_requires" => {
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "Object methods to create a DHCP packet.",
  "dist_author" => [
    "Dean Hamstead <dean\@fragfest.com.au>"
  ],
  "dist_name" => "Net-DHCP",
  "dist_version" => "0.684",
  "license" => "perl",
  "module_name" => "Net::DHCP",
  "recommends" => {},
  "recursive_test_files" => 1,
  "requires" => {
    "Carp" => 0,
    "Exporter" => 0,
    "List::Util" => 0,
    "Scalar::Util" => 0,
    "Socket" => 0
  },
  "script_files" => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
