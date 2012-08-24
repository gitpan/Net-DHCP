requires "Carp" => "0";
requires "Exporter" => "0";
requires "List::Util" => "0";
requires "Scalar::Util" => "0";
requires "Socket" => "0";
requires "constant" => "0";
requires "perl" => "v5.8.0";
requires "strict" => "0";
requires "warnings" => "0";

on 'build' => sub {
  requires "Module::Build" => "0.3601";
};

on 'test' => sub {
  requires "File::Spec" => "0";
  requires "Test::More" => "0";
  requires "Test::Warn" => "0";
};

on 'configure' => sub {
  requires "Module::Build" => "0.3601";
};
