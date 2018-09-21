# vi:filetype=perl

use lib '/home/booking/nginx_build/test-nginx/inc';
use lib '/home/booking/nginx_build/test-nginx/lib';
use Test::Nginx::Socket 'no_plan';


our $http_config = <<'_EOC_';
    ngx_lfstack_memory_allocate 10m;
    ngx_lfstack_name s1;
    ngx_lfstack_name s2;
    ngx_lfstack_name s3;
    ngx_lfstack_backup "|@|" /tmp/ngx_lfstack_data.txt;
_EOC_

no_shuffle();
run_tests();


__DATA__



=== TEST 1: push s1
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
POST /processStack?target=s1
{"data":"MESSAGE1"}
--- error_code: 202
--- timeout: 3
--- response_headers
Content-Type: text/plain




=== TEST 2: push s1 second time
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
POST /processStack?target=s1
{"data":"MESSAGE2"}
--- error_code: 202
--- timeout: 3
--- response_headers
Content-Type: text/plain


=== TEST 1: push s2
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
POST /processStack?target=s2
{"data":"MESSAGE1"}
--- error_code: 202
--- timeout: 3
--- response_headers
Content-Type: text/plain



=== TEST 1: push s3
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
POST /processStack?target=s3
{"data":"MESSAGE1"}
--- error_code: 202
--- timeout: 3
--- response_headers
Content-Type: text/plain




=== TEST 2: push s3 second time
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
POST /processStack?target=s3
{"data":"MESSAGE2"}
--- error_code: 202
--- timeout: 3
--- response_headers
Content-Type: text/plain



=== TEST 5: pop s1
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
GET /processStack?target=s1
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: text/plain
--- response_body_like eval chomp
qr/.*?\"MESSAGE2\".*/



=== TEST 6: pop s1 second time
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
GET /processStack?target=s1
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: text/plain
--- response_body_like eval chomp
qr/.*?\"MESSAGE1\".*/



=== TEST 5: pop s2
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
GET /processStack?target=s2
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: text/plain
--- response_body_like eval chomp
qr/.*?\"MESSAGE1\".*/



=== TEST 5: pop s3
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
GET /processStack?target=s3
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: text/plain
--- response_body_like eval chomp
qr/.*?\"MESSAGE2\".*/



=== TEST 6: pop s3 second time
--- http_config eval: $::http_config
--- config
    location /processStack {
       ngx_lfstack_target $arg_target;
    }
--- request
GET /processStack?target=s3
--- error_code: 200
--- timeout: 10
--- response_headers
Content-Type: text/plain
--- response_body_like eval chomp
qr/.*?\"MESSAGE1\".*/