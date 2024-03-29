use 5.014002;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'PlugAuth::Plugin::AD',
    VERSION_FROM      => 'lib/PlugAuth/Plugin/AD.pm', # finds $VERSION
    PREREQ_PM         => {'Net::LDAP' => 0,}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/PlugAuth/Plugin/AD.pm', # retrieve abstract from module
       AUTHOR         => 'root <root@>') : ()),
);
