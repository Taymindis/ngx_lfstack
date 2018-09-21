# ngx_lfstack


Table of Contents
=================

* [Introduction](#introduction)
* [Usage](#usage)
* [Installation](#installation)
* [Test](#test)
* [Support](#support)
* [Copyright & License](#copyright--license)

Introduction
============

ngx_lfstack is the lock free stack(push/pop) container running on nginx share memory and it read/write across multiple threads and multiple workers without any lock!

ngx_lfstack is zero downtime nginx reloadable, data is on share memory, data is backupable in case nginx stop and start.


Usage
=======
### 1. Setup your lfstack
```nginx
# nginx.conf
http {
    ngx_lfstack_memory_allocate 10m;
    ngx_lfstack_name s1;
    ngx_lfstack_name s2;
    ngx_lfstack_name s3;
    ngx_lfstack_backup "|@|" /tmp/ngx_lfstack_data.txt;	
    ...
}
```

### 2. Push the message to specific stack name `ngx_lfstack_target` by using POST/PUT method only, the request_body will be taken as stack message, response code 202
```nginx
# nginx.conf

server {
    ....
  location /processStack {
       ngx_lfstack_target s1;
   }


   location /processStackWithArgVariable {
       ngx_lfstack_target $arg_target;
   }
}
```

### 3. Destack the message by using GET method only, response code 200
```nginx
# nginx.conf

server {
    ....
   location /processStack {
       ngx_lfstack_target s1;
   }
}
```


### 4. Get the stack info by using HEAD method only, response code 204, the headers response stack_size, total_push, total_pop
```nginx
# nginx.conf

server {
    ....
   location /processStack {
       ngx_lfstack_target s1;
   }
}
```



Installation
============

ngx_lfstack is depends on [lfstack](https://github.com/Taymindis/lfstack) , install lfstack as .so library before install ngx_lfstack.


```bash
wget 'http://nginx.org/download/nginx-1.13.7.tar.gz'
tar -xzvf nginx-1.13.7.tar.gz
cd nginx-1.13.7/

./configure --add-module=/path/to/ngx_lfstack

make -j2
sudo make install
```

[Back to TOC](#table-of-contents)


Test
=====

It depends on nginx test suite libs, please refer [test-nginx](https://github.com/openresty/test-nginx) for installation.


```bash
cd /path/to/ngx_lfstack
export PATH=/path/to/nginx-dirname:$PATH 
sudo prove t
```

[Back to TOC](#table-of-contents)

Support
=======

Please do not hesitate to contact minikawoon2017@gmail.com for any queries or development improvement.


[Back to TOC](#table-of-contents)

Copyright & License
===================

Copyright (c) 2018, Taymindis <cloudleware2015@gmail.com>

This module is licensed under the terms of the BSD license.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)



## You may also like nginx lock free stack 

[ngx_lfstack](https://github.com/Taymindis/ngx_lfstack)
