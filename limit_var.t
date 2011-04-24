#!/usr/bin/perl

# (C) Kirill A. Korinskiy

# Tests for limit_var module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../../tests/lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(4)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

master_process off;
daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    limit_var  $remote_addr  zone=one:5000  rate=1r/s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        if ($limit_var_one) {
            return 402;
        }
        return 404;
    }
}

EOF

my $d = $t->testdir();
$t->write_file('is_bot_data', 'BOT');

$t->run();

###############################################################################

like(http_get('/'), qr!^HTTP/1.1 404 Not Found!m, 'limit skip');
like(http_get('/'), qr!^HTTP/1.1 404 Not Found!m, 'limit skip');
http_get('/');
http_get('/');
like(http_get('/'), qr!^HTTP/1.1 402 Payment Required!m, 'limit');
like(http_get('/'), qr!^HTTP/1.1 402 Payment Required!m, 'limit');

###############################################################################
